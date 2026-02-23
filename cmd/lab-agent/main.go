package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/htb-clone-lab-agent/internal/api"
	"github.com/htb-clone-lab-agent/internal/auth"
	"github.com/htb-clone-lab-agent/internal/config"
	"github.com/htb-clone-lab-agent/internal/metrics"
	"github.com/htb-clone-lab-agent/internal/observability"
	"github.com/htb-clone-lab-agent/internal/orchestrator"
	"github.com/htb-clone-lab-agent/internal/state"
	"github.com/htb-clone-lab-agent/internal/wireguard"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(fmt.Sprintf("config error: %v", err))
	}
	logger := observability.NewLogger(cfg.Observability.LogLevel)

	st, err := state.New(cfg.Storage.StateFile)
	if err != nil {
		logger.Error("state_init_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	wg := wireguard.New(cfg.WireGuard)
	ctx := context.Background()
	engine, err := orchestrator.New(ctx, cfg, st, wg, logger)
	if err != nil {
		logger.Error("engine_init_failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	if len(os.Args) > 1 && os.Args[1] == "reconcile" {
		summary, err := engine.Reconcile(ctx)
		if err != nil {
			logger.Error("reconcile_failed", slog.String("error", err.Error()))
			os.Exit(1)
		}
		report := map[string]any{
			"status":            "ok",
			"checked":           summary.Checked,
			"imported":          summary.Imported,
			"marked_stopped":    summary.MarkedStopped,
			"reconciled_at_utc": time.Now().UTC().Format(time.RFC3339),
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
		return
	}

	reg := metrics.New()
	apiServer := api.New(cfg, engine, reg, logger)

	routes := apiServer.Routes()
	authState := auth.NewMiddlewareState(cfg.Auth.NonceTTLSeconds)
	protected := authState.Middleware(cfg.Auth, routes)
	rateLimited := auth.NewRateLimiter(cfg.RateLimit, reg).Middleware(protected)
	var root http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.Server.HealthPublic && (r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/api/v1/health") {
			routes.ServeHTTP(w, r)
			return
		}
		rateLimited.ServeHTTP(w, r)
	})
	root = observability.Middleware(logger, reg, root)

	httpSrv := &http.Server{
		Addr:         cfg.Server.ListenAddr,
		Handler:      root,
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeoutSeconds) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeoutSeconds) * time.Second,
		IdleTimeout:  time.Duration(cfg.Server.IdleTimeoutSeconds) * time.Second,
		TLSConfig:    buildTLSConfig(cfg, logger),
	}

	loopCtx, cancelLoops := context.WithCancel(context.Background())
	defer cancelLoops()
	go runLoops(loopCtx, cfg, engine, logger)

	go func() {
		logger.Info("lab_agent_start", slog.String("listen_addr", cfg.Server.ListenAddr), slog.String("auth_mode", cfg.Auth.Mode))
		var err error
		if cfg.Server.TLSCertFile != "" && cfg.Server.TLSKeyFile != "" {
			err = httpSrv.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server_failed", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cancelLoops()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown_failed", slog.String("error", err.Error()))
	}
	logger.Info("lab_agent_stopped")
}

func runLoops(ctx context.Context, cfg config.Config, eng *orchestrator.Engine, logger *slog.Logger) {
	reconcileTicker := time.NewTicker(time.Duration(cfg.Reconciliation.IntervalSeconds) * time.Second)
	expireTicker := time.NewTicker(30 * time.Second)
	defer reconcileTicker.Stop()
	defer expireTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-reconcileTicker.C:
			summary, err := eng.Reconcile(context.Background())
			if err != nil {
				logger.Warn("reconcile_failed", slog.String("error", err.Error()))
				continue
			}
			logger.Info("reconcile_completed", slog.Int("checked", summary.Checked), slog.Int("imported", summary.Imported), slog.Int("marked_stopped", summary.MarkedStopped))
		case <-expireTicker.C:
			if err := eng.ExpireDue(context.Background()); err != nil {
				logger.Warn("expire_loop_failed", slog.String("error", err.Error()))
			}
		}
	}
}

func buildTLSConfig(cfg config.Config, logger *slog.Logger) *tls.Config {
	if cfg.Server.TLSClientCAFile == "" {
		return nil
	}
	caPem, err := os.ReadFile(cfg.Server.TLSClientCAFile)
	if err != nil {
		logger.Warn("tls_client_ca_read_failed", slog.String("error", err.Error()))
		return nil
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(caPem); !ok {
		logger.Warn("tls_client_ca_parse_failed")
		return nil
	}
	tlsCfg := &tls.Config{ClientCAs: pool, MinVersion: tls.VersionTLS12}
	if cfg.Server.TLSRequireClientCert {
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tlsCfg
}
