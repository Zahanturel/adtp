package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDefault(t *testing.T) {
	c := Default()
	if c.Server.Port != 8080 || c.Store.Backend != "memory" || c.Verify.MaxChainDepth != 10 {
		t.Errorf("unexpected defaults: %+v", c)
	}
	// Fail-closed / least-exposure defaults.
	if c.Server.Host != "127.0.0.1" {
		t.Errorf("default host = %q, want 127.0.0.1 (localhost only)", c.Server.Host)
	}
	if c.Verify.DefaultRiskTier != "HIGH" {
		t.Errorf("default risk tier = %q, want HIGH (revocation fail-closed)", c.Verify.DefaultRiskTier)
	}
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Server.Port != 8080 {
		t.Errorf("port = %d, want default 8080", c.Server.Port)
	}
}

func TestLoadYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	yaml := "server:\n  host: 127.0.0.1\n  port: 9000\nstore:\n  backend: memory\nverify:\n  max_chain_depth: 5\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Server.Host != "127.0.0.1" || c.Server.Port != 9000 || c.Verify.MaxChainDepth != 5 {
		t.Errorf("loaded config = %+v", c)
	}
	if c.Addr() != "127.0.0.1:9000" {
		t.Errorf("Addr = %q", c.Addr())
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("ADTP_SERVER_PORT", "7777")
	t.Setenv("ADTP_STORE_BACKEND", "memory")
	t.Setenv("ADTP_VERIFY_CLOCK_SKEW_SECONDS", "30")
	c, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Server.Port != 7777 || c.Verify.ClockSkewSeconds != 30 {
		t.Errorf("env overrides not applied: %+v", c)
	}
}

func TestValidate(t *testing.T) {
	t.Run("bad port", func(t *testing.T) {
		t.Setenv("ADTP_SERVER_PORT", "70000")
		if _, err := Load(""); !errors.Is(err, ErrInvalidPort) {
			t.Errorf("err = %v, want ErrInvalidPort", err)
		}
	})
	t.Run("bad backend", func(t *testing.T) {
		t.Setenv("ADTP_STORE_BACKEND", "mongodb")
		if _, err := Load(""); !errors.Is(err, ErrInvalidBackend) {
			t.Errorf("err = %v, want ErrInvalidBackend", err)
		}
	})
	t.Run("postgres without dsn", func(t *testing.T) {
		t.Setenv("ADTP_STORE_BACKEND", "postgres")
		if _, err := Load(""); !errors.Is(err, ErrMissingDSN) {
			t.Errorf("err = %v, want ErrMissingDSN", err)
		}
	})
}

func TestEnvBadInts(t *testing.T) {
	t.Setenv("ADTP_SERVER_PORT", "abc")
	if _, err := Load(""); !errors.Is(err, ErrInvalidPort) {
		t.Errorf("err = %v, want ErrInvalidPort", err)
	}
}

func TestEnvOverridesAll(t *testing.T) {
	t.Setenv("ADTP_SERVER_HOST", "10.0.0.1")
	t.Setenv("ADTP_STORE_BACKEND", "postgres")
	t.Setenv("ADTP_STORE_POSTGRES", "postgres://localhost/adtp")
	t.Setenv("ADTP_IDENTITY_PLATFORM_DID", "did:key:zPlatform")
	t.Setenv("ADTP_IDENTITY_PLATFORM_KEY", "/etc/adtp/platform.key")
	t.Setenv("ADTP_VERIFY_MAX_CHAIN_DEPTH", "7")
	t.Setenv("ADTP_VERIFY_DEFAULT_RISK_TIER", "HIGH")

	c, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Server.Host != "10.0.0.1" || c.Store.Backend != "postgres" ||
		c.Store.Postgres != "postgres://localhost/adtp" || c.Identity.PlatformDID != "did:key:zPlatform" ||
		c.Identity.PlatformKeyPath != "/etc/adtp/platform.key" || c.Verify.MaxChainDepth != 7 ||
		c.Verify.DefaultRiskTier != "HIGH" {
		t.Errorf("env overrides not all applied: %+v", c)
	}
}

func TestValidateAuth(t *testing.T) {
	t.Run("default mode is api_key", func(t *testing.T) {
		if Default().Auth.Mode != AuthModeAPIKey {
			t.Errorf("default auth mode = %q, want api_key", Default().Auth.Mode)
		}
	})
	t.Run("oidc requires issuer/audience/jwks", func(t *testing.T) {
		c := Default()
		c.Auth.Mode = AuthModeOIDC
		if err := c.validate(); !errors.Is(err, ErrIncompleteOIDC) {
			t.Errorf("err = %v, want ErrIncompleteOIDC", err)
		}
	})
	t.Run("complete oidc validates", func(t *testing.T) {
		c := Default()
		c.Auth = AuthConfig{Mode: AuthModeOIDC, OIDC: OIDCConfig{Issuer: "https://idp", Audience: "api://adtp", JWKSURL: "https://idp/jwks"}}
		if err := c.validate(); err != nil {
			t.Errorf("validate(complete oidc) = %v", err)
		}
	})
	t.Run("unknown mode rejected", func(t *testing.T) {
		c := Default()
		c.Auth.Mode = "telepathy"
		if err := c.validate(); !errors.Is(err, ErrInvalidAuthMode) {
			t.Errorf("err = %v, want ErrInvalidAuthMode", err)
		}
	})
}

func TestEnvBadClockSkewAndDepth(t *testing.T) {
	t.Run("bad clock skew", func(t *testing.T) {
		t.Setenv("ADTP_VERIFY_CLOCK_SKEW_SECONDS", "nope")
		if _, err := Load(""); err == nil {
			t.Errorf("expected error for bad clock skew")
		}
	})
	t.Run("bad max depth", func(t *testing.T) {
		t.Setenv("ADTP_VERIFY_MAX_CHAIN_DEPTH", "nope")
		if _, err := Load(""); err == nil {
			t.Errorf("expected error for bad max depth")
		}
	})
}
