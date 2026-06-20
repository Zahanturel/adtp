package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Zahanturel/adtp/config"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestKeyFromBytes(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	t.Run("full key", func(t *testing.T) {
		k, err := keyFromBytes(priv)
		if err != nil || len(k) != ed25519.PrivateKeySize {
			t.Errorf("keyFromBytes(full) = (%d, %v)", len(k), err)
		}
	})
	t.Run("seed", func(t *testing.T) {
		k, err := keyFromBytes(priv.Seed())
		if err != nil || len(k) != ed25519.PrivateKeySize {
			t.Errorf("keyFromBytes(seed) = (%d, %v)", len(k), err)
		}
	})
	t.Run("invalid length", func(t *testing.T) {
		if _, err := keyFromBytes([]byte{1, 2, 3}); err == nil {
			t.Errorf("keyFromBytes(short) = nil, want error")
		}
	})
}

func TestLoadOrCreatePlatformKey(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Identity.PlatformKeyPath = filepath.Join(dir, "platform.key")

	key, did, err := loadOrCreatePlatformKey(cfg, testLogger())
	if err != nil || did == "" || len(key) != ed25519.PrivateKeySize {
		t.Fatalf("generate = (%d, %q, %v)", len(key), did, err)
	}
	// Second call loads the persisted key and yields the same DID.
	key2, did2, err := loadOrCreatePlatformKey(cfg, testLogger())
	if err != nil || did2 != did {
		t.Fatalf("reload = (%q, %v), want %q", did2, err, did)
	}
	if !key.Equal(key2) {
		t.Errorf("reloaded key differs")
	}
}

func TestLoadOrCreateAPIKeys(t *testing.T) {
	t.Run("configured keys win", func(t *testing.T) {
		cfg := config.Default()
		cfg.Server.APIKeys = []string{"key-a", " key-b ", ""}
		keys, err := loadOrCreateAPIKeys(cfg, testLogger())
		if err != nil {
			t.Fatalf("loadOrCreateAPIKeys: %v", err)
		}
		if len(keys) != 2 || !keys["key-a"] || !keys["key-b"] {
			t.Errorf("keys = %v, want {key-a, key-b}", keys)
		}
	})

	t.Run("generate and persist when none", func(t *testing.T) {
		dir := t.TempDir()
		cfg := config.Default()
		cfg.Identity.PlatformKeyPath = filepath.Join(dir, "platform.key")
		keys, err := loadOrCreateAPIKeys(cfg, testLogger())
		if err != nil || len(keys) != 1 {
			t.Fatalf("generate = (%d, %v)", len(keys), err)
		}
		// The key was persisted; a second call reads it back unchanged.
		keys2, err := loadOrCreateAPIKeys(cfg, testLogger())
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		for k := range keys {
			if !keys2[k] {
				t.Errorf("persisted key %q not reloaded", k)
			}
		}
	})

	t.Run("read existing file", func(t *testing.T) {
		dir := t.TempDir()
		cfg := config.Default()
		cfg.Identity.PlatformKeyPath = filepath.Join(dir, "platform.key")
		if err := os.WriteFile(apiKeyPath(cfg), []byte("file-key\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		keys, err := loadOrCreateAPIKeys(cfg, testLogger())
		if err != nil || !keys["file-key"] {
			t.Errorf("keys = %v, err = %v, want file-key", keys, err)
		}
	})
}

func TestNewServiceMemory(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Identity.PlatformKeyPath = filepath.Join(dir, "platform.key")

	svc, st, err := newService(context.Background(), cfg, testLogger())
	if err != nil {
		t.Fatalf("newService: %v", err)
	}
	defer st.Close()

	if svc.PlatformDID == "" {
		t.Errorf("PlatformDID empty")
	}
	if len(svc.APIKeys) == 0 {
		t.Errorf("APIKeys empty; daemon would be unauthenticated")
	}
	if svc.StartTime == 0 {
		t.Errorf("StartTime not set")
	}
	// The instance id file was persisted alongside the platform key.
	if _, err := os.Stat(filepath.Join(dir, "instance.id")); err != nil {
		t.Errorf("instance.id not persisted: %v", err)
	}
}

func TestNewServiceWithOIDCAndSIEM(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Identity.PlatformKeyPath = filepath.Join(dir, "platform.key")
	cfg.Auth = config.AuthConfig{Mode: config.AuthModeOIDC, OIDC: config.OIDCConfig{
		Issuer: "https://idp.example.com", Audience: "api://adtp", JWKSURL: "https://idp.example.com/jwks",
	}}
	cfg.Integrations.SIEMWebhook = config.SIEMWebhookConfig{
		URL: "https://siem.example.com/ingest", BatchSize: 5, FlushInterval: "1s",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // stops the SIEM flush goroutine
	svc, st, err := newService(ctx, cfg, testLogger())
	if err != nil {
		t.Fatalf("newService: %v", err)
	}
	defer st.Close()
	if svc.OIDC == nil {
		t.Errorf("OIDC verifier not configured")
	}
	if svc.SIEM == nil {
		t.Errorf("SIEM exporter not configured")
	}
}

func TestNewServiceSIEMBadInterval(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Identity.PlatformKeyPath = filepath.Join(dir, "platform.key")
	cfg.Integrations.SIEMWebhook = config.SIEMWebhookConfig{URL: "https://x", FlushInterval: "not-a-duration"}
	if _, _, err := newService(context.Background(), cfg, testLogger()); err == nil {
		t.Errorf("newService(bad flush_interval) = nil, want error")
	}
}

func TestNewStore(t *testing.T) {
	cfg := config.Default() // memory backend
	st, err := newStore(cfg)
	if err != nil {
		t.Fatalf("newStore(memory): %v", err)
	}
	st.Close()
}

func TestNewStorePostgresInvalidDSN(t *testing.T) {
	cfg := config.Default()
	cfg.Store.Backend = "postgres"
	cfg.Store.Postgres = "garbage" // fails to parse — returns fast, no connect hang
	if _, err := newStore(cfg); err == nil {
		t.Errorf("newStore(bad postgres dsn) = nil, want error")
	}
}

func TestLoadPlatformKeyInvalidFile(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Identity.PlatformKeyPath = filepath.Join(dir, "platform.key")
	if err := os.WriteFile(cfg.Identity.PlatformKeyPath, []byte("short"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := loadOrCreatePlatformKey(cfg, testLogger()); err == nil {
		t.Errorf("loadOrCreatePlatformKey(invalid file) = nil, want error")
	}
}

func TestLoadPlatformKeyDIDMismatchWarns(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Identity.PlatformKeyPath = filepath.Join(dir, "platform.key")
	_, did, err := loadOrCreatePlatformKey(cfg, testLogger())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// A configured DID that disagrees with the key file logs a warning and the
	// key file's DID wins.
	cfg.Identity.PlatformDID = "did:key:zWrongConfigured"
	_, did2, err := loadOrCreatePlatformKey(cfg, testLogger())
	if err != nil || did2 != did {
		t.Errorf("reload with mismatched DID = (%q, %v), want %q", did2, err, did)
	}
}

func TestNewServicePropagatesKeyError(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Identity.PlatformKeyPath = filepath.Join(dir, "platform.key")
	if err := os.WriteFile(cfg.Identity.PlatformKeyPath, []byte("bad"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := newService(context.Background(), cfg, testLogger()); err == nil {
		t.Errorf("newService(bad key) = nil, want error")
	}
}

func TestPersistInstanceBadPathDoesNotPanic(t *testing.T) {
	cfg := config.Default()
	cfg.Identity.PlatformKeyPath = filepath.Join(t.TempDir(), "missing-subdir", "platform.key")
	// Directory does not exist, so the write fails; persistInstance must log and
	// continue rather than fail startup.
	persistInstance(cfg, "instance-x", 123, testLogger())
}

func TestServeListenError(t *testing.T) {
	// An invalid port makes ListenAndServe fail; serve must surface the error.
	srv := &http.Server{Addr: "127.0.0.1:999999", Handler: http.NewServeMux()}
	if err := serve(context.Background(), srv, config.Default(), testLogger()); err == nil {
		t.Errorf("serve(bad addr) = nil, want listen error")
	}
}

func TestServeGracefulShutdown(t *testing.T) {
	srv := &http.Server{Addr: "127.0.0.1:0", Handler: http.NewServeMux()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // request shutdown immediately
	if err := serve(ctx, srv, config.Default(), testLogger()); err != nil {
		t.Errorf("serve(canceled) = %v, want nil after graceful shutdown", err)
	}
}

func TestRun(t *testing.T) {
	t.Setenv("ADTP_SERVER_PORT", strconv.Itoa(freePort(t)))
	t.Setenv("ADTP_IDENTITY_PLATFORM_KEY", filepath.Join(t.TempDir(), "platform.key"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // shut down immediately
	if err := run(ctx, ""); err != nil {
		t.Errorf("run(canceled) = %v, want nil", err)
	}
}

func TestRunBadConfig(t *testing.T) {
	t.Setenv("ADTP_SERVER_PORT", "70000") // invalid port -> config.Load fails
	if err := run(context.Background(), ""); err == nil {
		t.Errorf("run(bad config) = nil, want error")
	}
}

func TestRunServer(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Identity.PlatformKeyPath = filepath.Join(dir, "platform.key")
	cfg.Server.Port = 0 // bind a random free port

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // shut down as soon as it is up
	if err := runServer(ctx, cfg, testLogger()); err != nil {
		t.Errorf("runServer(canceled) = %v, want nil", err)
	}
}
