package state

import "time"

type ServicePort struct {
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type WireGuardPeer struct {
	ClientPrivateKey string `json:"client_private_key"`
	ClientPublicKey  string `json:"client_public_key"`
	ClientAddress    string `json:"client_address"`
	ServerPublicKey  string `json:"server_public_key"`
	ServerEndpoint   string `json:"server_endpoint"`
	AllowedIPs       string `json:"allowed_ips"`
	DNS              string `json:"dns"`
}

type InstanceRecord struct {
	InstanceID    string        `json:"instance_id"`
	UserID        string        `json:"user_id"`
	LabContentID  string        `json:"lab_content_id"`
	Image         string        `json:"image"`
	Services      []ServicePort `json:"services"`
	Status        string        `json:"status"`
	ContainerName string        `json:"container_name"`
	ContainerID   string        `json:"container_id"`
	NetworkName   string        `json:"network_name"`
	LabIP         string        `json:"lab_ip"`
	CreatedAt     time.Time     `json:"created_at"`
	ExpiresAt     time.Time     `json:"expires_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
	FlagValue     string        `json:"flag_value"`
	WireGuardPeer WireGuardPeer `json:"wireguard_peer"`
	LastError     string        `json:"last_error"`
}

type Snapshot struct {
	Instances map[string]InstanceRecord `json:"instances"`
	UpdatedAt time.Time                 `json:"updated_at"`
}
