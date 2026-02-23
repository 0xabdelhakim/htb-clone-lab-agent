package orchestrator

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"

	"github.com/htb-clone-lab-agent/internal/config"
	"github.com/htb-clone-lab-agent/internal/state"
	"github.com/htb-clone-lab-agent/internal/wireguard"
)

var (
	ErrNotFound     = errors.New("not_found")
	ErrCapacity     = errors.New("capacity_full")
	ErrInvalidImage = errors.New("invalid_image")
	ErrInvalidState = errors.New("invalid_state")
	ErrTTLExceeded  = errors.New("ttl_limit_exceeded")
)

type CreateInput struct {
	InstanceID   string
	UserID       string
	LabContentID string
	Image        string
	Services     []state.ServicePort
	TTLMinutes   int
	FlagMode     string
	FlagPath     string
}

type ReconcileSummary struct {
	Checked       int
	Imported      int
	MarkedStopped int
}

type Engine struct {
	cfg    config.Config
	store  *state.Store
	wg     wireguard.Manager
	docker *client.Client
	log    *slog.Logger
	mu     sync.Mutex
}

func New(ctx context.Context, cfg config.Config, st *state.Store, wg wireguard.Manager, logger *slog.Logger) (*Engine, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	if _, err := cli.Ping(ctx); err != nil {
		return nil, fmt.Errorf("docker ping: %w", err)
	}
	return &Engine{cfg: cfg, store: st, wg: wg, docker: cli, log: logger}, nil
}

func (e *Engine) CreateInstance(ctx context.Context, in CreateInput) (state.InstanceRecord, bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if in.TTLMinutes <= 0 {
		in.TTLMinutes = e.cfg.Orchestrator.DefaultTTLMinutes
	}
	if in.TTLMinutes > e.cfg.Orchestrator.MaxTTLMinutes {
		in.TTLMinutes = e.cfg.Orchestrator.MaxTTLMinutes
	}

	if !e.imageAllowed(in.Image) {
		return state.InstanceRecord{}, false, ErrInvalidImage
	}

	if existing, ok := e.store.Get(in.InstanceID); ok {
		return existing, false, nil
	}
	if e.store.ActiveCount() >= e.cfg.Orchestrator.MaxInstances {
		return state.InstanceRecord{}, false, ErrCapacity
	}

	if rec, ok, err := e.findByDockerLabel(ctx, in.InstanceID); err != nil {
		return state.InstanceRecord{}, false, err
	} else if ok {
		if err := e.store.Upsert(rec); err != nil {
			return state.InstanceRecord{}, false, err
		}
		return rec, false, nil
	}

	if err := e.pullImage(ctx, in.Image); err != nil {
		return state.InstanceRecord{}, false, fmt.Errorf("pull image: %w", err)
	}

	networkName := namespacedName(e.cfg.Orchestrator.NetworkPrefix, in.InstanceID)
	containerName := namespacedName(e.cfg.Orchestrator.ContainerPrefix, in.InstanceID)
	createdAt := time.Now().UTC()
	expiresAt := createdAt.Add(time.Duration(in.TTLMinutes) * time.Minute)
	flagValue := e.generateFlag(in.InstanceID)

	wgPeer, err := e.wg.ProvisionPeer(in.InstanceID, in.UserID)
	if err != nil {
		return state.InstanceRecord{}, false, fmt.Errorf("provision wireguard peer: %w", err)
	}

	if err := e.ensureNetwork(ctx, networkName, in.InstanceID, in.UserID, in.LabContentID); err != nil {
		_ = e.wg.RemovePeer(wgPeer.ClientPublicKey)
		return state.InstanceRecord{}, false, err
	}

	env := []string{}
	if in.FlagMode == "per_instance" {
		env = append(env, "FLAG_VALUE="+flagValue)
	}
	labels := map[string]string{
		"lab_agent.managed":        "true",
		"lab_agent.instance_id":    in.InstanceID,
		"lab_agent.user_id":        in.UserID,
		"lab_agent.lab_content_id": in.LabContentID,
		"lab_agent.network":        networkName,
		"lab_agent.expires_at":     expiresAt.Format(time.RFC3339),
	}

	hc := &container.HostConfig{
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges:true"},
		ReadonlyRootfs: e.cfg.Orchestrator.ContainerReadOnlyRoot,
		Tmpfs:          map[string]string{"/tmp": "size=" + e.cfg.Orchestrator.ContainerTmpfsSize},
		Resources: container.Resources{
			Memory:   e.cfg.Orchestrator.ContainerMemoryBytes,
			NanoCPUs: int64(e.cfg.Orchestrator.ContainerCPUCores * 1e9),
		},
	}
	if e.cfg.Orchestrator.ContainerPidsLimit > 0 {
		p := e.cfg.Orchestrator.ContainerPidsLimit
		hc.PidsLimit = &p
	}

	resp, err := e.docker.ContainerCreate(ctx,
		&container.Config{Image: in.Image, Labels: labels, Env: env},
		hc,
		&network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{networkName: {}}},
		nil,
		containerName,
	)
	if err != nil {
		_ = e.wg.RemovePeer(wgPeer.ClientPublicKey)
		_ = e.removeNetwork(ctx, networkName)
		return state.InstanceRecord{}, false, fmt.Errorf("container create: %w", err)
	}

	if err := e.docker.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		_ = e.removeContainer(ctx, resp.ID)
		_ = e.wg.RemovePeer(wgPeer.ClientPublicKey)
		_ = e.removeNetwork(ctx, networkName)
		return state.InstanceRecord{}, false, fmt.Errorf("container start: %w", err)
	}

	inspect, err := e.docker.ContainerInspect(ctx, resp.ID)
	if err != nil {
		return state.InstanceRecord{}, false, fmt.Errorf("container inspect: %w", err)
	}
	labIP := ""
	if inspect.NetworkSettings != nil {
		if netData, ok := inspect.NetworkSettings.Networks[networkName]; ok && netData != nil {
			labIP = netData.IPAddress
		}
	}

	rec := state.InstanceRecord{
		InstanceID:    in.InstanceID,
		UserID:        in.UserID,
		LabContentID:  in.LabContentID,
		Image:         in.Image,
		Services:      in.Services,
		Status:        "running",
		ContainerName: containerName,
		ContainerID:   resp.ID,
		NetworkName:   networkName,
		LabIP:         labIP,
		CreatedAt:     createdAt,
		ExpiresAt:     expiresAt,
		UpdatedAt:     createdAt,
		FlagValue:     flagValue,
		WireGuardPeer: wgPeer,
	}
	if err := e.store.Upsert(rec); err != nil {
		return state.InstanceRecord{}, false, err
	}
	return rec, true, nil
}

func (e *Engine) GetInstance(ctx context.Context, instanceID string) (state.InstanceRecord, error) {
	rec, ok := e.store.Get(instanceID)
	if !ok {
		return state.InstanceRecord{}, ErrNotFound
	}
	if rec.ContainerID != "" {
		if inspect, err := e.docker.ContainerInspect(ctx, rec.ContainerID); err == nil {
			if inspect.State != nil && !inspect.State.Running && rec.Status == "running" {
				rec.Status = "stopped"
				rec.LastError = "container not running"
				_ = e.store.Upsert(rec)
			}
		}
	}
	return rec, nil
}

func (e *Engine) ListInstances(_ context.Context) ([]state.InstanceRecord, error) {
	return e.store.List(), nil
}

func (e *Engine) StartInstance(ctx context.Context, instanceID string) (state.InstanceRecord, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	rec, ok := e.store.Get(instanceID)
	if !ok {
		return state.InstanceRecord{}, ErrNotFound
	}
	if rec.Status == "running" {
		return rec, nil
	}
	if rec.Status == "expired" {
		return state.InstanceRecord{}, ErrInvalidState
	}
	if rec.ContainerID != "" && e.docker != nil {
		if err := e.docker.ContainerStart(ctx, rec.ContainerID, container.StartOptions{}); err != nil && !strings.Contains(strings.ToLower(err.Error()), "already started") {
			return state.InstanceRecord{}, err
		}
	}
	rec.Status = "running"
	rec.LastError = ""
	rec.UpdatedAt = time.Now().UTC()
	if err := e.store.Upsert(rec); err != nil {
		return state.InstanceRecord{}, err
	}
	return rec, nil
}

func (e *Engine) StopInstance(ctx context.Context, instanceID string) (state.InstanceRecord, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	rec, ok := e.store.Get(instanceID)
	if !ok {
		return state.InstanceRecord{}, ErrNotFound
	}
	if rec.Status == "stopped" {
		return rec, nil
	}
	if rec.ContainerID != "" && e.docker != nil {
		timeout := 10
		if err := e.docker.ContainerStop(ctx, rec.ContainerID, container.StopOptions{Timeout: &timeout}); err != nil {
			lerr := strings.ToLower(err.Error())
			if !strings.Contains(lerr, "not modified") && !strings.Contains(lerr, "not found") {
				return state.InstanceRecord{}, err
			}
		}
	}
	rec.Status = "stopped"
	rec.LastError = ""
	rec.UpdatedAt = time.Now().UTC()
	if err := e.store.Upsert(rec); err != nil {
		return state.InstanceRecord{}, err
	}
	return rec, nil
}

func (e *Engine) DeleteInstance(ctx context.Context, instanceID string) (state.InstanceRecord, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	rec, ok := e.store.Get(instanceID)
	if !ok {
		return state.InstanceRecord{InstanceID: instanceID, Status: "stopped"}, nil
	}
	if rec.Status == "stopped" || rec.Status == "expired" {
		return rec, nil
	}

	_ = e.removeContainer(ctx, rec.ContainerID)
	_ = e.removeNetwork(ctx, rec.NetworkName)
	_ = e.wg.RemovePeer(rec.WireGuardPeer.ClientPublicKey)

	rec.Status = "stopped"
	rec.LastError = ""
	rec.UpdatedAt = time.Now().UTC()
	if err := e.store.Upsert(rec); err != nil {
		return state.InstanceRecord{}, err
	}
	return rec, nil
}

func (e *Engine) ExtendInstance(ctx context.Context, instanceID string, extendMinutes int) (state.InstanceRecord, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	rec, ok := e.store.Get(instanceID)
	if !ok {
		return state.InstanceRecord{}, ErrNotFound
	}
	if rec.Status == "stopped" || rec.Status == "expired" {
		return state.InstanceRecord{}, ErrInvalidState
	}
	if extendMinutes <= 0 {
		return state.InstanceRecord{}, ErrInvalidState
	}
	maxExpires := rec.CreatedAt.Add(time.Duration(e.cfg.Orchestrator.MaxTTLMinutes) * time.Minute)
	next := rec.ExpiresAt.Add(time.Duration(extendMinutes) * time.Minute)
	if next.After(maxExpires) {
		return state.InstanceRecord{}, ErrTTLExceeded
	}
	rec.ExpiresAt = next
	rec.UpdatedAt = time.Now().UTC()
	if err := e.store.Upsert(rec); err != nil {
		return state.InstanceRecord{}, err
	}
	return rec, nil
}

func (e *Engine) Health(ctx context.Context) (int, error) {
	if e.docker == nil {
		return e.store.ActiveCount(), errors.New("docker unavailable")
	}
	_, err := e.docker.Ping(ctx)
	return e.store.ActiveCount(), err
}

func (e *Engine) Ready(ctx context.Context) error {
	if e.docker == nil {
		return errors.New("docker unavailable")
	}
	_, err := e.docker.Ping(ctx)
	return err
}

func (e *Engine) Reconcile(ctx context.Context) (ReconcileSummary, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	summary := ReconcileSummary{}
	containers, err := e.docker.ContainerList(ctx, container.ListOptions{All: true, Filters: filters.NewArgs(filters.Arg("label", "lab_agent.managed=true"))})
	if err != nil {
		return summary, err
	}
	byInstance := map[string]types.Container{}
	for _, c := range containers {
		id := c.Labels["lab_agent.instance_id"]
		if id != "" {
			byInstance[id] = c
		}
	}

	for _, rec := range e.store.List() {
		summary.Checked++
		if rec.Status == "running" || rec.Status == "starting" || rec.Status == "stopping" {
			if _, ok := byInstance[rec.InstanceID]; !ok {
				rec.Status = "stopped"
				rec.LastError = "reconciled: missing container"
				rec.UpdatedAt = time.Now().UTC()
				if err := e.store.Upsert(rec); err != nil {
					return summary, err
				}
				summary.MarkedStopped++
			}
		}
	}

	for instID, c := range byInstance {
		if _, ok := e.store.Get(instID); ok {
			continue
		}
		rec := state.InstanceRecord{
			InstanceID:    instID,
			UserID:        c.Labels["lab_agent.user_id"],
			LabContentID:  c.Labels["lab_agent.lab_content_id"],
			Image:         c.Image,
			Status:        "running",
			ContainerID:   c.ID,
			ContainerName: firstName(c.Names),
			NetworkName:   c.Labels["lab_agent.network"],
			CreatedAt:     time.Now().UTC(),
			UpdatedAt:     time.Now().UTC(),
			ExpiresAt:     parseRFC3339OrDefault(c.Labels["lab_agent.expires_at"], time.Now().UTC().Add(time.Hour)),
			LastError:     "reconciled: imported orphan",
		}
		if err := e.store.Upsert(rec); err != nil {
			return summary, err
		}
		summary.Imported++
	}
	return summary, nil
}

func (e *Engine) ExpireDue(ctx context.Context) error {
	now := time.Now().UTC()
	for _, rec := range e.store.List() {
		if (rec.Status == "running" || rec.Status == "starting") && !rec.ExpiresAt.After(now) {
			_, _ = e.DeleteInstance(ctx, rec.InstanceID)
			rec.Status = "expired"
			rec.LastError = "ttl expired"
			rec.UpdatedAt = now
			_ = e.store.Upsert(rec)
		}
	}
	return nil
}

func (e *Engine) ensureNetwork(ctx context.Context, name, instanceID, userID, labContentID string) error {
	_, err := e.docker.NetworkInspect(ctx, name, network.InspectOptions{})
	if err == nil {
		return nil
	}
	_, err = e.docker.NetworkCreate(ctx, name, network.CreateOptions{Driver: "bridge", Labels: map[string]string{
		"lab_agent.managed":        "true",
		"lab_agent.instance_id":    instanceID,
		"lab_agent.user_id":        userID,
		"lab_agent.lab_content_id": labContentID,
	}})
	if err != nil {
		return fmt.Errorf("network create: %w", err)
	}
	return nil
}

func (e *Engine) removeNetwork(ctx context.Context, name string) error {
	if name == "" {
		return nil
	}
	if err := e.docker.NetworkRemove(ctx, name); err != nil && !strings.Contains(strings.ToLower(err.Error()), "not found") {
		return err
	}
	return nil
}

func (e *Engine) removeContainer(ctx context.Context, containerID string) error {
	if containerID == "" {
		return nil
	}
	timeout := 10
	if err := e.docker.ContainerStop(ctx, containerID, container.StopOptions{Timeout: &timeout}); err != nil {
		e.log.Warn("container stop warning", slog.String("container_id", containerID), slog.String("error", err.Error()))
	}
	if err := e.docker.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true}); err != nil && !strings.Contains(strings.ToLower(err.Error()), "not found") {
		return err
	}
	return nil
}

func (e *Engine) pullImage(ctx context.Context, image string) error {
	reader, err := e.docker.ImagePull(ctx, image, types.ImagePullOptions{})
	if err != nil {
		return err
	}
	defer reader.Close()
	_, _ = io.Copy(io.Discard, reader)
	return nil
}

func (e *Engine) imageAllowed(image string) bool {
	for _, p := range e.cfg.Orchestrator.ImageAllowPrefixes {
		if strings.HasPrefix(image, p) {
			return true
		}
	}
	return false
}

func (e *Engine) findByDockerLabel(ctx context.Context, instanceID string) (state.InstanceRecord, bool, error) {
	args := filters.NewArgs(filters.Arg("label", "lab_agent.instance_id="+instanceID))
	containers, err := e.docker.ContainerList(ctx, container.ListOptions{All: true, Filters: args})
	if err != nil {
		return state.InstanceRecord{}, false, err
	}
	if len(containers) == 0 {
		return state.InstanceRecord{}, false, nil
	}
	c := containers[0]
	rec := state.InstanceRecord{
		InstanceID:    instanceID,
		UserID:        c.Labels["lab_agent.user_id"],
		LabContentID:  c.Labels["lab_agent.lab_content_id"],
		Image:         c.Image,
		Status:        "running",
		ContainerID:   c.ID,
		ContainerName: firstName(c.Names),
		NetworkName:   c.Labels["lab_agent.network"],
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     parseRFC3339OrDefault(c.Labels["lab_agent.expires_at"], time.Now().UTC().Add(time.Hour)),
		UpdatedAt:     time.Now().UTC(),
		LastError:     "idempotent recover from docker",
	}
	return rec, true, nil
}

func (e *Engine) generateFlag(instanceID string) string {
	secret := e.cfg.Orchestrator.FlagSecret
	if secret == "" {
		secret = "lab-agent-flag-secret-dev"
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(instanceID))
	return "FLAG{" + hex.EncodeToString(mac.Sum(nil))[:32] + "}"
}

func namespacedName(prefix, instanceID string) string {
	clean := strings.NewReplacer("-", "", ":", "", "_", "", "/", "").Replace(strings.ToLower(instanceID))
	if len(clean) > 24 {
		clean = clean[:24]
	}
	if clean == "" {
		clean = "unknown"
	}
	return fmt.Sprintf("%s-%s", prefix, clean)
}

func firstName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return strings.TrimPrefix(names[0], "/")
}

func parseRFC3339OrDefault(v string, fallback time.Time) time.Time {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t
	}
	return fallback
}
