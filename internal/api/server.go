package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/htb-clone-lab-agent/internal/config"
	"github.com/htb-clone-lab-agent/internal/metrics"
	"github.com/htb-clone-lab-agent/internal/orchestrator"
	"github.com/htb-clone-lab-agent/internal/state"
)

type Orchestrator interface {
	CreateInstance(ctx context.Context, in orchestrator.CreateInput) (state.InstanceRecord, bool, error)
	GetInstance(ctx context.Context, instanceID string) (state.InstanceRecord, error)
	ListInstances(ctx context.Context) ([]state.InstanceRecord, error)
	StartInstance(ctx context.Context, instanceID string) (state.InstanceRecord, error)
	StopInstance(ctx context.Context, instanceID string) (state.InstanceRecord, error)
	DeleteInstance(ctx context.Context, instanceID string) (state.InstanceRecord, error)
	ExtendInstance(ctx context.Context, instanceID string, extendMinutes int) (state.InstanceRecord, error)
	Health(ctx context.Context) (int, error)
	Ready(ctx context.Context) error
	Reconcile(ctx context.Context) (orchestrator.ReconcileSummary, error)
}

type Server struct {
	cfg       config.Config
	engine    Orchestrator
	metrics   *metrics.Registry
	logger    *slog.Logger
	startedAt time.Time
}

func New(cfg config.Config, eng *orchestrator.Engine, reg *metrics.Registry, logger *slog.Logger) *Server {
	return &Server{cfg: cfg, engine: eng, metrics: reg, logger: logger, startedAt: time.Now().UTC()}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	mux.HandleFunc(s.cfg.Observability.MetricsPath, s.handleMetrics)

	registerV1Routes := func(prefix string) {
		mux.HandleFunc(prefix+"/instances", s.handleInstances)
		mux.HandleFunc(prefix+"/instances/", s.handleInstanceByID)
		mux.HandleFunc(prefix+"/reconcile", s.handleReconcile)
	}

	registerV1Routes("/v1")
	registerV1Routes("/api/v1") // backwards compatibility aliases

	mux.HandleFunc("/api/v1/health", s.handleHealthz)
	return mux
}

func (s *Server) handleInstances(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.engine.ListInstances(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "Unable to list instances.", map[string]any{"error": err.Error()})
			return
		}
		payloads := make([]InstancePayload, 0, len(items))
		for _, rec := range items {
			payloads = append(payloads, toInstancePayload(rec))
		}
		writeJSON(w, http.StatusOK, InstanceListResponse{OK: true, Instances: payloads})
	case http.MethodPost:
		s.handleCreateOrUpsert(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.", nil)
	}
}

func (s *Server) handleCreateOrUpsert(w http.ResponseWriter, r *http.Request) {
	var req CreateInstanceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Body must be a JSON object.", nil)
		return
	}

	labID := req.LabID
	if labID == "" {
		labID = req.LabContentID
	}
	ttlMinutes := req.TTLMinutes
	if ttlMinutes <= 0 && req.TTLSeconds > 0 {
		ttlMinutes = req.TTLSeconds / 60
		if req.TTLSeconds%60 != 0 {
			ttlMinutes++
		}
	}
	if ttlMinutes <= 0 {
		ttlMinutes = s.cfg.Orchestrator.DefaultTTLMinutes
	}

	if req.InstanceID == "" || req.UserID == "" || labID == "" || req.Image == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "Missing required fields.", map[string]any{"required": []string{"instance_id", "user_id", "lab_id", "image"}})
		return
	}

	services := make([]state.ServicePort, 0, len(req.Services)+len(req.Ports))
	for _, sp := range req.Services {
		services = append(services, state.ServicePort{Name: sp.Name, Port: sp.Port, Protocol: sp.Protocol})
	}
	for i, port := range req.Ports {
		services = append(services, state.ServicePort{Name: "port-" + strconv.Itoa(i), Port: port.Container, Protocol: "tcp"})
	}

	input := orchestrator.CreateInput{
		InstanceID:   req.InstanceID,
		UserID:       req.UserID,
		LabContentID: labID,
		Image:        req.Image,
		Services:     services,
		TTLMinutes:   ttlMinutes,
	}
	if req.Flag != nil {
		input.FlagMode = req.Flag.Mode
		input.FlagPath = req.Flag.Path
	}

	rec, created, err := s.engine.CreateInstance(r.Context(), input)
	if err != nil {
		s.writeOrchErr(w, err)
		return
	}
	statusCode := http.StatusOK
	if created {
		statusCode = http.StatusCreated
		s.metrics.IncInstanceStart()
	}
	writeJSON(w, statusCode, CreateInstanceResponse{OK: true, Instance: toInstancePayload(rec)})
}

func (s *Server) handleInstanceByID(w http.ResponseWriter, r *http.Request) {
	path := trimInstancePath(r.URL.Path)
	if path == "" {
		writeError(w, http.StatusNotFound, "not_found", "Instance not found.", nil)
		return
	}
	parts := strings.Split(path, "/")
	instanceID := parts[0]
	if instanceID == "" {
		writeError(w, http.StatusNotFound, "not_found", "Instance not found.", nil)
		return
	}

	if len(parts) == 1 {
		s.handleSingleInstance(w, r, instanceID)
		return
	}
	if len(parts) == 2 {
		switch parts[1] {
		case "start":
			s.handleStartStop(w, r, instanceID, true)
			return
		case "stop":
			s.handleStartStop(w, r, instanceID, false)
			return
		case "extend":
			s.handleExtend(w, r, instanceID)
			return
		}
	}
	writeError(w, http.StatusNotFound, "not_found", "Endpoint not found.", nil)
}

func trimInstancePath(path string) string {
	for _, prefix := range []string{"/v1/instances/", "/api/v1/instances/"} {
		if strings.HasPrefix(path, prefix) {
			return strings.TrimPrefix(path, prefix)
		}
	}
	return ""
}

func (s *Server) handleSingleInstance(w http.ResponseWriter, r *http.Request, instanceID string) {
	switch r.Method {
	case http.MethodGet:
		rec, err := s.engine.GetInstance(r.Context(), instanceID)
		if err != nil {
			s.writeOrchErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, GetInstanceResponse{OK: true, Instance: toInstancePayload(rec)})
	case http.MethodDelete:
		rec, err := s.engine.DeleteInstance(r.Context(), instanceID)
		if err != nil {
			s.writeOrchErr(w, err)
			return
		}
		s.metrics.IncInstanceStop()
		writeJSON(w, http.StatusOK, DeleteInstanceResponse{OK: true, InstanceID: rec.InstanceID, Status: rec.Status})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.", nil)
	}
}

func (s *Server) handleStartStop(w http.ResponseWriter, r *http.Request, instanceID string, start bool) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.", nil)
		return
	}
	var (
		rec state.InstanceRecord
		err error
	)
	if start {
		rec, err = s.engine.StartInstance(r.Context(), instanceID)
		if err == nil {
			s.metrics.IncInstanceStart()
		}
	} else {
		rec, err = s.engine.StopInstance(r.Context(), instanceID)
		if err == nil {
			s.metrics.IncInstanceStop()
		}
	}
	if err != nil {
		s.writeOrchErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, StartStopInstanceResponse{OK: true, InstanceID: rec.InstanceID, Status: rec.Status})
}

func (s *Server) handleExtend(w http.ResponseWriter, r *http.Request, instanceID string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.", nil)
		return
	}
	var req ExtendInstanceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Body must be a JSON object.", nil)
		return
	}
	rec, err := s.engine.ExtendInstance(r.Context(), instanceID, req.ExtendMinutes)
	if err != nil {
		s.writeOrchErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ExtendInstanceResponse{OK: true, InstanceID: rec.InstanceID, ExpiresAt: rec.ExpiresAt})
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.", nil)
		return
	}
	active, err := s.engine.Health(r.Context())
	dockerOK := err == nil
	s.metrics.SetActiveInstances(active)
	status := "ok"
	code := http.StatusOK
	if !dockerOK {
		status = "degraded"
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, HealthResponse{
		Status:   status,
		Version:  s.cfg.Server.Version,
		Uptime:   int64(time.Since(s.startedAt).Seconds()),
		DockerOK: dockerOK,
		WGOK:     true,
	})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.", nil)
		return
	}
	err := s.engine.Ready(r.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, ReadyResponse{Status: "not_ready", Ready: false})
		return
	}
	writeJSON(w, http.StatusOK, ReadyResponse{Status: "ready", Ready: true})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.", nil)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = w.Write([]byte(s.metrics.RenderPrometheus()))
}

func (s *Server) handleReconcile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.", nil)
		return
	}
	summary, err := s.engine.Reconcile(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "reconcile_failed", "Reconciliation failed.", map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, ReconcileResponse{OK: true, Checked: summary.Checked, Imported: summary.Imported, MarkedStopped: summary.MarkedStopped})
}

func (s *Server) writeOrchErr(w http.ResponseWriter, err error) {
	switch err {
	case orchestrator.ErrNotFound:
		writeError(w, http.StatusNotFound, "not_found", "Instance not found.", nil)
	case orchestrator.ErrCapacity:
		writeError(w, http.StatusServiceUnavailable, "capacity_full", "Max concurrent instances reached.", nil)
	case orchestrator.ErrInvalidImage:
		writeError(w, http.StatusUnprocessableEntity, "invalid_image", "Image is not allowed or cannot be pulled.", nil)
	case orchestrator.ErrInvalidState:
		writeError(w, http.StatusConflict, "invalid_state", "Cannot perform operation in current instance state.", nil)
	case orchestrator.ErrTTLExceeded:
		writeError(w, http.StatusBadRequest, "ttl_limit_exceeded", "Requested extension exceeds maximum TTL.", nil)
	default:
		s.logger.Error("orchestrator_error", slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "internal_error", "Operation failed.", map[string]any{"error": err.Error()})
	}
}

func toInstancePayload(rec state.InstanceRecord) InstancePayload {
	uptime := int64(0)
	if !rec.CreatedAt.IsZero() && (rec.Status == "running" || rec.Status == "starting") {
		uptime = int64(time.Since(rec.CreatedAt).Seconds())
	}
	return InstancePayload{
		InstanceID: rec.InstanceID,
		Status:     rec.Status,
		LabIP:      rec.LabIP,
		CreatedAt:  rec.CreatedAt,
		ExpiresAt:  rec.ExpiresAt,
		UptimeSecs: uptime,
		FlagValue:  rec.FlagValue,
		WireGuardPeer: WireGuardPeer{
			ClientPrivateKey: rec.WireGuardPeer.ClientPrivateKey,
			ClientAddress:    rec.WireGuardPeer.ClientAddress,
			ServerPublicKey:  rec.WireGuardPeer.ServerPublicKey,
			ServerEndpoint:   rec.WireGuardPeer.ServerEndpoint,
			AllowedIPs:       rec.WireGuardPeer.AllowedIPs,
			DNS:              rec.WireGuardPeer.DNS,
		},
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, errCode, message string, details any) {
	writeJSON(w, code, ErrorEnvelope{Error: ErrorBody{Code: errCode, Message: message, Details: details}})
}
