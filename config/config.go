// Package config loads daemon configuration from a YAML file with environment
// variable overrides.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the daemon's full configuration.
type Config struct {
	Server       ServerConfig       `yaml:"server"`
	Store        StoreConfig        `yaml:"store"`
	Identity     IdentityConfig     `yaml:"identity"`
	Verify       VerifyConfig       `yaml:"verify"`
	Auth         AuthConfig         `yaml:"auth"`
	Integrations IntegrationsConfig `yaml:"integrations"`
}

// AuthConfig selects how callers authenticate to the control plane.
type AuthConfig struct {
	// Mode is "api_key" (default) or "oidc".
	Mode string     `yaml:"mode"`
	OIDC OIDCConfig `yaml:"oidc"`
}

// OIDCConfig configures bearer-token validation against an external IdP (Entra,
// Okta, Auth0, ...). The token's sub claim becomes the sponsor identity.
type OIDCConfig struct {
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`
	JWKSURL  string `yaml:"jwks_url"`
}

// IntegrationsConfig holds optional external integrations.
type IntegrationsConfig struct {
	SIEMWebhook SIEMWebhookConfig `yaml:"siem_webhook"`
}

// SIEMWebhookConfig configures batched audit-event export to an HTTP endpoint
// (Datadog, Splunk, Elastic, ...). Header values may reference environment
// variables as ${VAR}. An empty URL disables export.
type SIEMWebhookConfig struct {
	URL           string            `yaml:"url"`
	Headers       map[string]string `yaml:"headers"`
	BatchSize     int               `yaml:"batch_size"`
	FlushInterval string            `yaml:"flush_interval"`
}

// Auth mode constants.
const (
	AuthModeAPIKey = "api_key"
	AuthModeOIDC   = "oidc"
)

// ServerConfig configures the HTTP listener.
type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	// TLSCert and TLSKey, when both set, enable TLS on the listener.
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
	// RateLimitRPS is the sustained request rate (per second). 0 disables.
	RateLimitRPS float64 `yaml:"rate_limit_rps"`
	// RateLimitBurst is the token-bucket burst size (defaults to RateLimitRPS).
	RateLimitBurst int `yaml:"rate_limit_burst"`
	// APIKeys are the accepted bearer keys for api_key auth. When empty, the
	// daemon auto-generates one on first run (see cmd/adtpd).
	APIKeys []string `yaml:"api_keys"`
}

// StoreConfig selects and configures the storage backend.
type StoreConfig struct {
	Backend  string `yaml:"backend"`  // "memory" or "postgres"
	Postgres string `yaml:"postgres"` // connection string when backend is postgres
}

// IdentityConfig configures the daemon's own (platform) identity.
type IdentityConfig struct {
	PlatformDID     string `yaml:"platform_did"`
	PlatformKeyPath string `yaml:"platform_key"`
}

// VerifyConfig configures verification policy.
type VerifyConfig struct {
	MaxChainDepth    int    `yaml:"max_chain_depth"`
	ClockSkewSeconds int64  `yaml:"clock_skew_seconds"`
	DefaultRiskTier  string `yaml:"default_risk_tier"`
	// ReconcileIntervalMinutes sets how often the daemon re-checks the
	// registration index for missed entries. 0 disables periodic reconciliation
	// (startup reconciliation still runs). Default: 0 (disabled).
	ReconcileIntervalMinutes int `yaml:"reconcile_interval_minutes"`
}

// Config errors.
var (
	ErrInvalidPort    = errors.New("invalid server port")
	ErrInvalidBackend = errors.New("invalid store backend")
	ErrMissingDSN     = errors.New("postgres backend requires a connection string")
	ErrInvalidAuthMode  = errors.New("invalid auth mode")
	ErrIncompleteOIDC   = errors.New("oidc auth requires issuer, audience, and jwks_url")
	ErrInvalidRiskTier  = errors.New("invalid risk tier (must be HIGH, MEDIUM, LOW, or ANALYTICS)")
	ErrIncompleteTLS    = errors.New("tls_cert and tls_key must both be set")
)

// Default returns the built-in defaults.
func Default() *Config {
	return &Config{
		// Bind to localhost by default; the daemon exposes an unauthenticated-by-
		// default control plane and MUST run behind an authenticating gateway
		// before any wider exposure.
		Server: ServerConfig{Host: "127.0.0.1", Port: 8080},
		Store:  StoreConfig{Backend: "memory"},
		Identity: IdentityConfig{
			PlatformKeyPath: "platform.key",
		},
		// DefaultRiskTier HIGH so revocation lookups fail CLOSED by default
		// (a lookup error denies rather than degrade-accepting).
		Verify: VerifyConfig{MaxChainDepth: 10, ClockSkewSeconds: 60, DefaultRiskTier: "HIGH"},
		Auth:   AuthConfig{Mode: AuthModeAPIKey},
	}
}

// Load reads configuration from path (if it exists), overlays it on the
// defaults, applies environment overrides, and validates the result. A missing
// file is not an error — the defaults plus environment are used.
func Load(path string) (*Config, error) {
	cfg := Default()

	if path != "" {
		data, err := os.ReadFile(path)
		switch {
		case err == nil:
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("adtp/config: parse %s: %w", path, err)
			}
		case errors.Is(err, os.ErrNotExist):
			// Fall through to defaults + environment.
		default:
			return nil, fmt.Errorf("adtp/config: read %s: %w", path, err)
		}
	}

	if err := applyEnv(cfg); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func applyEnv(cfg *Config) error {
	if v := os.Getenv("ADTP_SERVER_HOST"); v != "" {
		cfg.Server.Host = v
	}
	if v := os.Getenv("ADTP_SERVER_PORT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("adtp/config: %w: ADTP_SERVER_PORT=%q", ErrInvalidPort, v)
		}
		cfg.Server.Port = n
	}
	if v := os.Getenv("ADTP_SERVER_API_KEYS"); v != "" {
		cfg.Server.APIKeys = nil
		for _, k := range strings.Split(v, ",") {
			if k = strings.TrimSpace(k); k != "" {
				cfg.Server.APIKeys = append(cfg.Server.APIKeys, k)
			}
		}
	}
	if v := os.Getenv("ADTP_SERVER_TLS_CERT"); v != "" {
		cfg.Server.TLSCert = v
	}
	if v := os.Getenv("ADTP_SERVER_TLS_KEY"); v != "" {
		cfg.Server.TLSKey = v
	}
	if v := os.Getenv("ADTP_STORE_BACKEND"); v != "" {
		cfg.Store.Backend = v
	}
	if v := os.Getenv("ADTP_STORE_POSTGRES"); v != "" {
		cfg.Store.Postgres = v
	}
	if v := os.Getenv("ADTP_IDENTITY_PLATFORM_DID"); v != "" {
		cfg.Identity.PlatformDID = v
	}
	if v := os.Getenv("ADTP_IDENTITY_PLATFORM_KEY"); v != "" {
		cfg.Identity.PlatformKeyPath = v
	}
	if v := os.Getenv("ADTP_VERIFY_MAX_CHAIN_DEPTH"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("adtp/config: ADTP_VERIFY_MAX_CHAIN_DEPTH=%q: %w", v, err)
		}
		cfg.Verify.MaxChainDepth = n
	}
	if v := os.Getenv("ADTP_VERIFY_CLOCK_SKEW_SECONDS"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("adtp/config: ADTP_VERIFY_CLOCK_SKEW_SECONDS=%q: %w", v, err)
		}
		cfg.Verify.ClockSkewSeconds = n
	}
	if v := os.Getenv("ADTP_VERIFY_DEFAULT_RISK_TIER"); v != "" {
		cfg.Verify.DefaultRiskTier = v
	}
	return nil
}

func (c *Config) validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("adtp/config: %w: %d", ErrInvalidPort, c.Server.Port)
	}
	if (c.Server.TLSCert == "") != (c.Server.TLSKey == "") {
		return fmt.Errorf("adtp/config: %w", ErrIncompleteTLS)
	}
	switch c.Store.Backend {
	case "memory":
	case "postgres":
		if c.Store.Postgres == "" {
			return fmt.Errorf("adtp/config: %w", ErrMissingDSN)
		}
	default:
		return fmt.Errorf("adtp/config: %w: %q", ErrInvalidBackend, c.Store.Backend)
	}
	if c.Verify.MaxChainDepth <= 0 {
		c.Verify.MaxChainDepth = 10
	}
	if c.Verify.ClockSkewSeconds <= 0 {
		c.Verify.ClockSkewSeconds = 60
	}
	if c.Verify.DefaultRiskTier == "" {
		c.Verify.DefaultRiskTier = "HIGH"
	}
	switch c.Verify.DefaultRiskTier {
	case "HIGH", "MEDIUM", "LOW", "ANALYTICS":
	default:
		return fmt.Errorf("adtp/config: %w: %q", ErrInvalidRiskTier, c.Verify.DefaultRiskTier)
	}
	if c.Auth.Mode == "" {
		c.Auth.Mode = AuthModeAPIKey
	}
	switch c.Auth.Mode {
	case AuthModeAPIKey:
	case AuthModeOIDC:
		if c.Auth.OIDC.Issuer == "" || c.Auth.OIDC.Audience == "" || c.Auth.OIDC.JWKSURL == "" {
			return fmt.Errorf("adtp/config: %w", ErrIncompleteOIDC)
		}
	default:
		return fmt.Errorf("adtp/config: %w: %q", ErrInvalidAuthMode, c.Auth.Mode)
	}
	return nil
}

// Addr returns the host:port listen address.
func (c *Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}

// TLSEnabled reports whether TLS is configured.
func (c *Config) TLSEnabled() bool {
	return c.Server.TLSCert != "" && c.Server.TLSKey != ""
}
