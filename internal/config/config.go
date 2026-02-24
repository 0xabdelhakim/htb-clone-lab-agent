package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server         ServerConfig    `yaml:"server"`
	Auth           AuthConfig      `yaml:"auth"`
	RateLimit      RateLimitConfig `yaml:"rate_limit"`
	Storage        StorageConfig   `yaml:"storage"`
	Orchestrator   OrchConfig      `yaml:"orchestrator"`
	WireGuard      WireGuardConfig `yaml:"wireguard"`
	Reconciliation ReconcileConfig `yaml:"reconciliation"`
	Observability  ObsConfig       `yaml:"observability"`
}

type ServerConfig struct {
	ListenAddr           string `yaml:"listen_addr"`
	Version              string `yaml:"version"`
	ReadTimeoutSeconds   int    `yaml:"read_timeout_seconds"`
	WriteTimeoutSeconds  int    `yaml:"write_timeout_seconds"`
	IdleTimeoutSeconds   int    `yaml:"idle_timeout_seconds"`
	HealthPublic         bool   `yaml:"health_public"`
	TLSCertFile          string `yaml:"tls_cert_file"`
	TLSKeyFile           string `yaml:"tls_key_file"`
	TLSClientCAFile      string `yaml:"tls_client_ca_file"`
	TLSRequireClientCert bool   `yaml:"tls_require_client_cert"`
}

type AuthConfig struct {
	Mode            string `yaml:"mode"`
	BearerToken     string `yaml:"bearer_token"`
	HMACSecret      string `yaml:"hmac_secret"`
	HMACSkewSeconds int    `yaml:"hmac_skew_seconds"`
	NonceTTLSeconds int    `yaml:"nonce_ttl_seconds"`
}

type RateLimitConfig struct {
	Enabled     bool    `yaml:"enabled"`
	GlobalRPS   float64 `yaml:"global_rps"`
	GlobalBurst int     `yaml:"global_burst"`
	PerIPRPS    float64 `yaml:"per_ip_rps"`
	PerIPBurst  int     `yaml:"per_ip_burst"`
}

type StorageConfig struct {
	StateFile string `yaml:"state_file"`
}

type OrchConfig struct {
	MaxInstances          int      `yaml:"max_instances"`
	ImageAllowPrefixes    []string `yaml:"image_allow_prefixes"`
	RegistryUsername      string   `yaml:"registry_username"`
	RegistryToken         string   `yaml:"registry_token"`
	RegistryServerAddress string   `yaml:"registry_server_address"`
	DefaultTTLMinutes     int      `yaml:"default_ttl_minutes"`
	MaxTTLMinutes         int      `yaml:"max_ttl_minutes"`
	ContainerPrefix       string   `yaml:"container_prefix"`
	NetworkPrefix         string   `yaml:"network_prefix"`
	ContainerMemoryBytes  int64    `yaml:"container_memory_bytes"`
	ContainerCPUCores     float64  `yaml:"container_cpu_cores"`
	ContainerPidsLimit    int64    `yaml:"container_pids_limit"`
	ContainerReadOnlyRoot bool     `yaml:"container_read_only_root"`
	ContainerTmpfsSize    string   `yaml:"container_tmpfs_size"`
	FlagSecret            string   `yaml:"flag_secret"`
}

type WireGuardConfig struct {
	Mode            string `yaml:"mode"`
	Interface       string `yaml:"interface"`
	ServerPublicKey string `yaml:"server_public_key"`
	ServerEndpoint  string `yaml:"server_endpoint"`
	AllowedIPs      string `yaml:"allowed_ips"`
	DNS             string `yaml:"dns"`
}

type ReconcileConfig struct {
	IntervalSeconds int `yaml:"interval_seconds"`
}

type ObsConfig struct {
	LogLevel    string `yaml:"log_level"`
	MetricsPath string `yaml:"metrics_path"`
	EnablePprof bool   `yaml:"enable_pprof"`
}

func Default() Config {
	return Config{
		Server: ServerConfig{
			ListenAddr:          ":9000",
			Version:             "dev",
			ReadTimeoutSeconds:  10,
			WriteTimeoutSeconds: 30,
			IdleTimeoutSeconds:  60,
			HealthPublic:        true,
		},
		Auth: AuthConfig{
			Mode:            "hmac",
			HMACSkewSeconds: 300,
			NonceTTLSeconds: 360,
		},
		RateLimit: RateLimitConfig{
			Enabled:     true,
			GlobalRPS:   100,
			GlobalBurst: 200,
			PerIPRPS:    20,
			PerIPBurst:  40,
		},
		Storage: StorageConfig{
			StateFile: "/var/lib/lab-agent/state.json",
		},
		Orchestrator: OrchConfig{
			MaxInstances:          50,
			ImageAllowPrefixes:    []string{"ghcr.io/labs/", "ghcr.io/"},
			RegistryServerAddress: "ghcr.io",
			DefaultTTLMinutes:     60,
			MaxTTLMinutes:         180,
			ContainerPrefix:       "inst",
			NetworkPrefix:         "labinst",
			ContainerMemoryBytes:  512 * 1024 * 1024,
			ContainerCPUCores:     1.0,
			ContainerPidsLimit:    256,
			ContainerReadOnlyRoot: true,
			ContainerTmpfsSize:    "64m",
		},
		WireGuard: WireGuardConfig{
			Mode:       "mock",
			Interface:  "wg0",
			AllowedIPs: "10.13.0.0/16",
			DNS:        "10.13.0.1",
		},
		Reconciliation: ReconcileConfig{IntervalSeconds: 60},
		Observability:  ObsConfig{LogLevel: "info", MetricsPath: "/metrics"},
	}
}

func Load() (Config, error) {
	cfg := Default()

	configFile := os.Getenv("LAB_AGENT_CONFIG_FILE")
	if configFile != "" {
		if err := loadYAML(&cfg, configFile); err != nil {
			return cfg, err
		}
	}
	applyEnv(&cfg)
	if err := validate(cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func loadYAML(cfg *Config, file string) error {
	b, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return fmt.Errorf("parse config yaml: %w", err)
	}
	return nil
}

func applyEnv(cfg *Config) {
	setString(&cfg.Server.ListenAddr, "LAB_AGENT_LISTEN_ADDR")
	setString(&cfg.Server.Version, "LAB_AGENT_VERSION")
	setInt(&cfg.Server.ReadTimeoutSeconds, "LAB_AGENT_READ_TIMEOUT_SECONDS")
	setInt(&cfg.Server.WriteTimeoutSeconds, "LAB_AGENT_WRITE_TIMEOUT_SECONDS")
	setInt(&cfg.Server.IdleTimeoutSeconds, "LAB_AGENT_IDLE_TIMEOUT_SECONDS")
	setBool(&cfg.Server.HealthPublic, "LAB_AGENT_HEALTH_PUBLIC")
	setString(&cfg.Server.TLSCertFile, "LAB_AGENT_TLS_CERT_FILE")
	setString(&cfg.Server.TLSKeyFile, "LAB_AGENT_TLS_KEY_FILE")
	setString(&cfg.Server.TLSClientCAFile, "LAB_AGENT_TLS_CLIENT_CA_FILE")
	setBool(&cfg.Server.TLSRequireClientCert, "LAB_AGENT_TLS_REQUIRE_CLIENT_CERT")

	setString(&cfg.Auth.Mode, "LAB_AGENT_AUTH_MODE")
	setString(&cfg.Auth.BearerToken, "LAB_AGENT_TOKEN")
	setString(&cfg.Auth.HMACSecret, "LAB_AGENT_HMAC_SECRET")
	setInt(&cfg.Auth.HMACSkewSeconds, "LAB_AGENT_HMAC_SKEW_SECONDS")
	setInt(&cfg.Auth.NonceTTLSeconds, "LAB_AGENT_NONCE_TTL_SECONDS")

	setBool(&cfg.RateLimit.Enabled, "LAB_AGENT_RATE_LIMIT_ENABLED")
	setFloat64(&cfg.RateLimit.GlobalRPS, "LAB_AGENT_RATE_LIMIT_GLOBAL_RPS")
	setInt(&cfg.RateLimit.GlobalBurst, "LAB_AGENT_RATE_LIMIT_GLOBAL_BURST")
	setFloat64(&cfg.RateLimit.PerIPRPS, "LAB_AGENT_RATE_LIMIT_PER_IP_RPS")
	setInt(&cfg.RateLimit.PerIPBurst, "LAB_AGENT_RATE_LIMIT_PER_IP_BURST")

	setString(&cfg.Storage.StateFile, "LAB_AGENT_STATE_FILE")

	setInt(&cfg.Orchestrator.MaxInstances, "MAX_INSTANCES")
	setCSV(&cfg.Orchestrator.ImageAllowPrefixes, "LAB_AGENT_IMAGE_ALLOW_PREFIXES")
	setString(&cfg.Orchestrator.RegistryUsername, "LAB_AGENT_REGISTRY_USERNAME")
	setString(&cfg.Orchestrator.RegistryToken, "LAB_AGENT_REGISTRY_TOKEN")
	setString(&cfg.Orchestrator.RegistryServerAddress, "LAB_AGENT_REGISTRY_SERVER_ADDRESS")
	setInt(&cfg.Orchestrator.DefaultTTLMinutes, "DEFAULT_TTL_MINUTES")
	setInt(&cfg.Orchestrator.MaxTTLMinutes, "MAX_TTL_MINUTES")
	setString(&cfg.Orchestrator.ContainerPrefix, "LAB_AGENT_CONTAINER_PREFIX")
	setString(&cfg.Orchestrator.NetworkPrefix, "LAB_AGENT_NETWORK_PREFIX")
	setInt64(&cfg.Orchestrator.ContainerMemoryBytes, "CONTAINER_MEMORY_BYTES")
	setFloat64(&cfg.Orchestrator.ContainerCPUCores, "CONTAINER_CPU_CORES")
	setInt64(&cfg.Orchestrator.ContainerPidsLimit, "CONTAINER_PIDS_LIMIT")
	setBool(&cfg.Orchestrator.ContainerReadOnlyRoot, "CONTAINER_READ_ONLY_ROOT")
	setString(&cfg.Orchestrator.ContainerTmpfsSize, "CONTAINER_TMPFS_SIZE")
	setString(&cfg.Orchestrator.FlagSecret, "FLAG_SECRET")

	setString(&cfg.WireGuard.Mode, "LAB_AGENT_WG_MODE")
	setString(&cfg.WireGuard.Interface, "LAB_AGENT_WG_INTERFACE")
	setString(&cfg.WireGuard.ServerPublicKey, "LAB_AGENT_WG_SERVER_PUBLIC_KEY")
	setString(&cfg.WireGuard.ServerEndpoint, "LAB_AGENT_WG_SERVER_ENDPOINT")
	setString(&cfg.WireGuard.AllowedIPs, "LAB_AGENT_WG_ALLOWED_IPS")
	setString(&cfg.WireGuard.DNS, "LAB_AGENT_WG_DNS")

	setInt(&cfg.Reconciliation.IntervalSeconds, "LAB_AGENT_RECONCILE_INTERVAL_SECONDS")

	setString(&cfg.Observability.LogLevel, "LAB_AGENT_LOG_LEVEL")
	setString(&cfg.Observability.MetricsPath, "LAB_AGENT_METRICS_PATH")
	setBool(&cfg.Observability.EnablePprof, "LAB_AGENT_ENABLE_PPROF")
}

func validate(cfg Config) error {
	if cfg.Server.ListenAddr == "" {
		return errors.New("listen addr is required")
	}
	if cfg.Orchestrator.MaxInstances <= 0 {
		return errors.New("max instances must be > 0")
	}
	if cfg.Orchestrator.DefaultTTLMinutes <= 0 || cfg.Orchestrator.MaxTTLMinutes <= 0 {
		return errors.New("ttl values must be > 0")
	}
	if cfg.Orchestrator.DefaultTTLMinutes > cfg.Orchestrator.MaxTTLMinutes {
		return errors.New("default ttl cannot exceed max ttl")
	}
	mode := strings.ToLower(cfg.Auth.Mode)
	switch mode {
	case "bearer", "hmac", "either":
	default:
		return fmt.Errorf("invalid auth mode: %s", cfg.Auth.Mode)
	}
	if mode == "bearer" && cfg.Auth.BearerToken == "" {
		return errors.New("LAB_AGENT_TOKEN is required in bearer mode")
	}
	if mode == "hmac" && cfg.Auth.HMACSecret == "" {
		return errors.New("LAB_AGENT_HMAC_SECRET is required in hmac mode")
	}
	if mode == "either" && cfg.Auth.BearerToken == "" && cfg.Auth.HMACSecret == "" {
		return errors.New("either mode requires at least one auth secret (token or hmac)")
	}
	if cfg.Auth.HMACSkewSeconds <= 0 {
		return errors.New("hmac skew must be > 0")
	}
	if cfg.Auth.NonceTTLSeconds <= 0 {
		return errors.New("nonce ttl must be > 0")
	}
	if cfg.Auth.NonceTTLSeconds < cfg.Auth.HMACSkewSeconds+60 {
		return errors.New("nonce ttl must be >= hmac skew + 60 seconds")
	}
	if cfg.RateLimit.Enabled {
		if cfg.RateLimit.GlobalRPS <= 0 || cfg.RateLimit.GlobalBurst <= 0 {
			return errors.New("global rate limit values must be > 0")
		}
		if cfg.RateLimit.PerIPRPS <= 0 || cfg.RateLimit.PerIPBurst <= 0 {
			return errors.New("per-ip rate limit values must be > 0")
		}
	}
	return nil
}

func setString(dst *string, key string) {
	if v := os.Getenv(key); v != "" {
		*dst = v
	}
}
func setCSV(dst *[]string, key string) {
	if v := os.Getenv(key); v != "" {
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		if len(out) > 0 {
			*dst = out
		}
	}
}
func setBool(dst *bool, key string) {
	if v := os.Getenv(key); v != "" {
		if p, err := strconv.ParseBool(v); err == nil {
			*dst = p
		}
	}
}
func setInt(dst *int, key string) {
	if v := os.Getenv(key); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			*dst = p
		}
	}
}
func setInt64(dst *int64, key string) {
	if v := os.Getenv(key); v != "" {
		if p, err := strconv.ParseInt(v, 10, 64); err == nil {
			*dst = p
		}
	}
}
func setFloat64(dst *float64, key string) {
	if v := os.Getenv(key); v != "" {
		if p, err := strconv.ParseFloat(v, 64); err == nil {
			*dst = p
		}
	}
}
