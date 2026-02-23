package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/htb-clone-lab-agent/internal/config"
	"github.com/htb-clone-lab-agent/internal/metrics"
	"github.com/htb-clone-lab-agent/internal/orchestrator"
	"github.com/htb-clone-lab-agent/internal/state"
)

type fakeOrch struct {
	mu    sync.Mutex
	items map[string]state.InstanceRecord
}

func newFakeOrch() *fakeOrch { return &fakeOrch{items: map[string]state.InstanceRecord{}} }

func (f *fakeOrch) CreateInstance(_ context.Context, in orchestrator.CreateInput) (state.InstanceRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if rec, ok := f.items[in.InstanceID]; ok {
		return rec, false, nil
	}
	now := time.Now().UTC()
	rec := state.InstanceRecord{InstanceID: in.InstanceID, UserID: in.UserID, LabContentID: in.LabContentID, Image: in.Image, Status: "running", CreatedAt: now, ExpiresAt: now.Add(time.Duration(in.TTLMinutes) * time.Minute)}
	f.items[in.InstanceID] = rec
	return rec, true, nil
}
func (f *fakeOrch) GetInstance(_ context.Context, id string) (state.InstanceRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.items[id]
	if !ok {
		return state.InstanceRecord{}, orchestrator.ErrNotFound
	}
	return rec, nil
}
func (f *fakeOrch) ListInstances(_ context.Context) ([]state.InstanceRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]state.InstanceRecord, 0, len(f.items))
	for _, rec := range f.items {
		out = append(out, rec)
	}
	return out, nil
}
func (f *fakeOrch) StartInstance(_ context.Context, id string) (state.InstanceRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.items[id]
	if !ok {
		return state.InstanceRecord{}, orchestrator.ErrNotFound
	}
	rec.Status = "running"
	f.items[id] = rec
	return rec, nil
}
func (f *fakeOrch) StopInstance(_ context.Context, id string) (state.InstanceRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.items[id]
	if !ok {
		return state.InstanceRecord{}, orchestrator.ErrNotFound
	}
	rec.Status = "stopped"
	f.items[id] = rec
	return rec, nil
}
func (f *fakeOrch) DeleteInstance(_ context.Context, id string) (state.InstanceRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.items[id]
	if !ok {
		return state.InstanceRecord{InstanceID: id, Status: "stopped"}, nil
	}
	rec.Status = "stopped"
	f.items[id] = rec
	return rec, nil
}
func (f *fakeOrch) ExtendInstance(_ context.Context, id string, extendMinutes int) (state.InstanceRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.items[id]
	if !ok {
		return state.InstanceRecord{}, orchestrator.ErrNotFound
	}
	rec.ExpiresAt = rec.ExpiresAt.Add(time.Duration(extendMinutes) * time.Minute)
	f.items[id] = rec
	return rec, nil
}
func (f *fakeOrch) Health(context.Context) (int, error) { return len(f.items), nil }
func (f *fakeOrch) Ready(context.Context) error         { return nil }
func (f *fakeOrch) Reconcile(context.Context) (orchestrator.ReconcileSummary, error) {
	return orchestrator.ReconcileSummary{}, nil
}

func newTestServer() *Server {
	cfg := config.Default()
	reg := metrics.New()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &Server{cfg: cfg, engine: newFakeOrch(), metrics: reg, logger: logger, startedAt: time.Now().UTC()}
}

func TestCreateIdempotency(t *testing.T) {
	s := newTestServer()
	routes := s.Routes()
	body := []byte(`{"instance_id":"i1","user_id":"u1","lab_id":"l1","image":"ghcr.io/labs/x:1","ttl_seconds":7200}`)

	req1 := httptest.NewRequest(http.MethodPost, "/v1/instances", bytes.NewReader(body))
	rr1 := httptest.NewRecorder()
	routes.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/v1/instances", bytes.NewReader(body))
	rr2 := httptest.NewRecorder()
	routes.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("expected 200 on duplicate create, got %d", rr2.Code)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/v1/instances", nil)
	listRR := httptest.NewRecorder()
	routes.ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("expected 200 list, got %d", listRR.Code)
	}
	var listed InstanceListResponse
	if err := json.Unmarshal(listRR.Body.Bytes(), &listed); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	if len(listed.Instances) != 1 {
		t.Fatalf("expected exactly one instance, got %d", len(listed.Instances))
	}
}

func TestDeleteIdempotency(t *testing.T) {
	s := newTestServer()
	routes := s.Routes()
	create := []byte(`{"instance_id":"i2","user_id":"u2","lab_id":"l2","image":"ghcr.io/labs/x:1"}`)
	routes.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/instances", bytes.NewReader(create)))

	del1 := httptest.NewRecorder()
	routes.ServeHTTP(del1, httptest.NewRequest(http.MethodDelete, "/v1/instances/i2", nil))
	if del1.Code != http.StatusOK {
		t.Fatalf("expected first delete 200, got %d", del1.Code)
	}

	del2 := httptest.NewRecorder()
	routes.ServeHTTP(del2, httptest.NewRequest(http.MethodDelete, "/v1/instances/i2", nil))
	if del2.Code != http.StatusOK {
		t.Fatalf("expected second delete 200, got %d", del2.Code)
	}
}

func TestStartStopIdempotency(t *testing.T) {
	s := newTestServer()
	routes := s.Routes()
	create := []byte(`{"instance_id":"i3","user_id":"u3","lab_id":"l3","image":"ghcr.io/labs/x:1"}`)
	routes.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/instances", bytes.NewReader(create)))

	stop1 := httptest.NewRecorder()
	routes.ServeHTTP(stop1, httptest.NewRequest(http.MethodPost, "/v1/instances/i3/stop", nil))
	if stop1.Code != http.StatusOK {
		t.Fatalf("expected first stop 200, got %d", stop1.Code)
	}

	stop2 := httptest.NewRecorder()
	routes.ServeHTTP(stop2, httptest.NewRequest(http.MethodPost, "/v1/instances/i3/stop", nil))
	if stop2.Code != http.StatusOK {
		t.Fatalf("expected second stop 200, got %d", stop2.Code)
	}

	start1 := httptest.NewRecorder()
	routes.ServeHTTP(start1, httptest.NewRequest(http.MethodPost, "/v1/instances/i3/start", nil))
	if start1.Code != http.StatusOK {
		t.Fatalf("expected first start 200, got %d", start1.Code)
	}

	start2 := httptest.NewRecorder()
	routes.ServeHTTP(start2, httptest.NewRequest(http.MethodPost, "/v1/instances/i3/start", nil))
	if start2.Code != http.StatusOK {
		t.Fatalf("expected second start 200, got %d", start2.Code)
	}
}

func TestListInstancesExpectedState(t *testing.T) {
	s := newTestServer()
	routes := s.Routes()
	create1 := []byte(`{"instance_id":"i4","user_id":"u4","lab_id":"l4","image":"ghcr.io/labs/x:1"}`)
	create2 := []byte(`{"instance_id":"i5","user_id":"u5","lab_id":"l5","image":"ghcr.io/labs/x:1"}`)
	routes.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/instances", bytes.NewReader(create1)))
	routes.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/instances", bytes.NewReader(create2)))

	rr := httptest.NewRecorder()
	routes.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/instances", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp InstanceListResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Instances) != 2 {
		t.Fatalf("expected 2 instances, got %d", len(resp.Instances))
	}
}
