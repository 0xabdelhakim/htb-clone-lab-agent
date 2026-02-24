package api

import "time"

type ServicePort struct {
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type PortBinding struct {
	Container int  `json:"container"`
	Public    bool `json:"public"`
}

type ResourceSpec struct {
	CPU      int `json:"cpu"`
	MemoryMB int `json:"memory_mb"`
}

type FlagSpec struct {
	Mode string `json:"mode"`
	Path string `json:"path"`
}

type CreateInstanceRequest struct {
	InstanceID   string            `json:"instance_id"`
	UserID       string            `json:"user_id"`
	LabID        string            `json:"lab_id"`
	LabContentID string            `json:"lab_content_id"`
	Image        string            `json:"image"`
	Resources    ResourceSpec      `json:"resources"`
	Ports        []PortBinding     `json:"ports"`
	Services     []ServicePort     `json:"services"`
	Env          map[string]string `json:"env"`
	TTLSeconds   int               `json:"ttl_seconds"`
	TTLMinutes   int               `json:"ttl_minutes"`
	Flag         *FlagSpec         `json:"flag,omitempty"`
}

type StartStopInstanceResponse struct {
	OK         bool   `json:"ok"`
	InstanceID string `json:"instance_id"`
	Status     string `json:"status"`
}

type ExtendInstanceRequest struct {
	ExtendMinutes int `json:"extend_minutes"`
}

type InstanceListResponse struct {
	OK        bool              `json:"ok"`
	Instances []InstancePayload `json:"instances"`
}

type ErrorEnvelope struct {
	Error ErrorBody `json:"error"`
}

type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

type WireGuardPeer struct {
	ClientPrivateKey string `json:"client_private_key"`
	ClientAddress    string `json:"client_address"`
	ServerPublicKey  string `json:"server_public_key"`
	ServerEndpoint   string `json:"server_endpoint"`
	AllowedIPs       string `json:"allowed_ips"`
	DNS              string `json:"dns"`
}

type InstancePayload struct {
	InstanceID    string        `json:"instance_id"`
	Status        string        `json:"status"`
	LabIP         string        `json:"lab_ip,omitempty"`
	CreatedAt     time.Time     `json:"created_at"`
	ExpiresAt     time.Time     `json:"expires_at"`
	UptimeSecs    int64         `json:"uptime_seconds,omitempty"`
	FlagValue     string        `json:"flag_value,omitempty"`
	WireGuardPeer WireGuardPeer `json:"wireguard_peer"`
}

type CreateInstanceResponse struct {
	OK       bool            `json:"ok"`
	Instance InstancePayload `json:"instance"`
}

type GetInstanceResponse = CreateInstanceResponse

type DeleteInstanceResponse struct {
	OK         bool   `json:"ok"`
	InstanceID string `json:"instance_id"`
	Status     string `json:"status"`
}

type ExtendInstanceResponse struct {
	OK         bool      `json:"ok"`
	InstanceID string    `json:"instance_id"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type HealthResponse struct {
	Status   string `json:"status"`
	Version  string `json:"version"`
	Uptime   int64  `json:"uptime_seconds"`
	DockerOK bool   `json:"docker_ok"`
	WGOK     bool   `json:"wg_ok"`
}

type ReadyResponse struct {
	Status string `json:"status"`
	Ready  bool   `json:"ready"`
}

type ReconcileResponse struct {
	OK            bool `json:"ok"`
	Checked       int  `json:"checked"`
	Imported      int  `json:"imported"`
	MarkedStopped int  `json:"marked_stopped"`
}


