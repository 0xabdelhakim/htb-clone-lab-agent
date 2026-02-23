package observability

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/htb-clone-lab-agent/internal/metrics"
)

type ctxKey string

const requestIDKey ctxKey = "request_id"

func RequestIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(requestIDKey).(string)
	return v
}

func Middleware(logger *slog.Logger, reg *metrics.Registry, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = newRequestID()
		}
		traceparent := r.Header.Get("Traceparent")
		ctx := context.WithValue(r.Context(), requestIDKey, requestID)
		r = r.WithContext(ctx)
		w.Header().Set("X-Request-ID", requestID)

		start := time.Now()
		reg.IncRequest(r.URL.Path)
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		reg.ObserveRequestDuration(time.Since(start))
		if rw.status >= 400 {
			reg.IncError()
		}
		logger.Info("http_request",
			slog.String("request_id", requestID),
			slog.String("traceparent", traceparent),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rw.status),
			slog.Int64("duration_ms", time.Since(start).Milliseconds()),
			slog.String("remote_addr", r.RemoteAddr),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(statusCode int) {
	r.status = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func newRequestID() string {
	return time.Now().UTC().Format("20060102T150405.000000000")
}
