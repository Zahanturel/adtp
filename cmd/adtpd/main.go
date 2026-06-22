// Command adtpd is the ADTP daemon: it loads configuration, initializes a
// storage backend and the platform identity, and serves the v1 HTTP API.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	v1 "github.com/Zahanturel/adtp/api/v1"
	"github.com/Zahanturel/adtp/config"
	"github.com/Zahanturel/adtp/internal/identity"
	"github.com/Zahanturel/adtp/internal/revocation"
	"github.com/Zahanturel/adtp/internal/siem"
	"github.com/Zahanturel/adtp/internal/verify"
	"github.com/Zahanturel/adtp/store"
	"github.com/Zahanturel/adtp/store/memory"
	"github.com/Zahanturel/adtp/store/postgres"
)

var (
	version = "dev"
	commit  = "none"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to the YAML config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("adtpd %s (%s)\n", version, commit)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, *configPath); err != nil {
		fmt.Fprintln(os.Stderr, "adtpd:", err)
		os.Exit(1)
	}
}

// run loads configuration and serves until ctx is canceled. Flag parsing and
// signal wiring live in main so run is directly testable.
func run(ctx context.Context, configPath string) error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	return runServer(ctx, cfg, logger)
}

// runServer builds the service and HTTP server from cfg and serves until ctx is
// canceled. It is the testable core of run() (which only adds flag parsing and
// signal handling).
func runServer(ctx context.Context, cfg *config.Config, logger *slog.Logger) error {
	svc, st, err := newService(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer st.Close()

	// Reconcile the registration index on startup to backfill any entries
	// missed by a prior crash between PutCredential and Register.
	report, err := revocation.Reconcile(ctx, st, st, st.Audit())
	if err != nil {
		logger.Warn("startup reconciliation failed", "error", err)
	} else if report.RepairsApplied > 0 {
		logger.Info("startup reconciliation", "walked", report.CredentialsWalked, "repairs", report.RepairsApplied, "errors", report.Errors)
	}

	if mins := cfg.Verify.ReconcileIntervalMinutes; mins > 0 {
		interval := time.Duration(mins) * time.Minute
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					r, err := revocation.Reconcile(ctx, st, st, st.Audit())
					if err != nil {
						logger.Warn("periodic reconciliation failed", "error", err)
					} else if r.RepairsApplied > 0 {
						logger.Info("periodic reconciliation", "walked", r.CredentialsWalked, "repairs", r.RepairsApplied, "errors", r.Errors)
					}
				}
			}
		}()
		logger.Info("periodic reconciliation enabled", "interval_minutes", mins)
	}

	srv := &http.Server{
		Addr:              cfg.Addr(),
		Handler:           v1.NewRouter(svc),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	logger.Info("adtpd listening", "addr", cfg.Addr(), "tls", cfg.TLSEnabled(), "backend", cfg.Store.Backend, "platform_did", svc.PlatformDID)
	return serve(ctx, srv, cfg, logger)
}

// newService assembles the daemon's Service: storage backend, platform identity,
// API keys, nonce cache, boot time, and optional OIDC auth / SIEM export. The
// returned store is the caller's to Close. SIEM export runs until ctx is done.
func newService(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*v1.Service, store.Store, error) {
	st, err := newStore(cfg)
	if err != nil {
		return nil, nil, err
	}

	key, did, err := loadOrCreatePlatformKey(cfg, logger)
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	apiKeys, err := loadOrCreateAPIKeys(cfg, logger)
	if err != nil {
		st.Close()
		return nil, nil, err
	}

	startTime := time.Now().Unix()
	nonceCache := verify.NewMemoryNonceCache()
	persistInstance(cfg, nonceCache.InstanceID(), startTime, logger)

	svc := &v1.Service{
		Store:       st,
		Keys:        identity.NewMemoryKeyStore(),
		PlatformKey: key,
		PlatformDID: did,
		Config:      cfg,
		NonceCache:  nonceCache,
		Logger:      logger,
		APIKeys:     apiKeys,
		StartTime:   startTime,
	}

	if cfg.Auth.Mode == config.AuthModeOIDC {
		svc.OIDC = v1.NewOIDCVerifier(cfg.Auth.OIDC.Issuer, cfg.Auth.OIDC.Audience, cfg.Auth.OIDC.JWKSURL)
		logger.Info("OIDC sponsor auth enabled", "issuer", cfg.Auth.OIDC.Issuer, "audience", cfg.Auth.OIDC.Audience)
	}

	if cfg.Integrations.SIEMWebhook.URL != "" {
		exporter, err := newSIEMExporter(cfg, logger)
		if err != nil {
			st.Close()
			return nil, nil, err
		}
		exporter.Start(ctx)
		svc.SIEM = exporter
		logger.Info("SIEM audit export enabled", "url", cfg.Integrations.SIEMWebhook.URL)
	}

	return svc, st, nil
}

// newSIEMExporter builds the audit-export client from config, parsing the
// flush-interval duration string.
func newSIEMExporter(cfg *config.Config, logger *slog.Logger) (*siem.Exporter, error) {
	wc := cfg.Integrations.SIEMWebhook
	interval := 10 * time.Second
	if wc.FlushInterval != "" {
		d, err := time.ParseDuration(wc.FlushInterval)
		if err != nil {
			return nil, fmt.Errorf("invalid siem flush_interval %q: %w", wc.FlushInterval, err)
		}
		interval = d
	}
	return siem.NewExporter(siem.Config{
		URL:           wc.URL,
		Headers:       wc.Headers,
		BatchSize:     wc.BatchSize,
		FlushInterval: interval,
	}, logger), nil
}

// serve runs srv until ctx is canceled, then gracefully shuts it down. A listen
// failure is returned immediately.
func serve(ctx context.Context, srv *http.Server, cfg *config.Config, logger *slog.Logger) error {
	serveErr := make(chan error, 1)
	go func() {
		var err error
		if cfg.TLSEnabled() {
			err = srv.ListenAndServeTLS(cfg.Server.TLSCert, cfg.Server.TLSKey)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		logger.Info("adtpd shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func newStore(cfg *config.Config) (store.Store, error) {
	switch cfg.Store.Backend {
	case "postgres":
		return postgres.NewPostgresStore(cfg.Store.Postgres)
	default:
		return memory.New(), nil
	}
}

// loadOrCreatePlatformKey reads the platform Ed25519 key from disk, generating
// and persisting one on first run so startup is frictionless.
func loadOrCreatePlatformKey(cfg *config.Config, logger *slog.Logger) (ed25519.PrivateKey, string, error) {
	path := cfg.Identity.PlatformKeyPath
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		key, kerr := keyFromBytes(data)
		if kerr != nil {
			return nil, "", fmt.Errorf("platform key %s: %w", path, kerr)
		}
		did := identity.EncodeDID(key.Public().(ed25519.PublicKey))
		if cfg.Identity.PlatformDID != "" && cfg.Identity.PlatformDID != did {
			logger.Warn("config platform_did does not match key file; using key file", "config", cfg.Identity.PlatformDID, "key", did)
		}
		return key, did, nil
	case errors.Is(err, os.ErrNotExist):
		did, key, gerr := identity.GenerateDID()
		if gerr != nil {
			return nil, "", gerr
		}
		if werr := os.WriteFile(path, key, 0o600); werr != nil {
			return nil, "", fmt.Errorf("write platform key %s: %w", path, werr)
		}
		logger.Info("generated platform identity", "did", did, "key_path", path)
		return key, did, nil
	default:
		return nil, "", fmt.Errorf("read platform key %s: %w", path, err)
	}
}

// loadOrCreateAPIKeys returns the set of accepted API keys. Configured keys
// (config file or ADTP_SERVER_API_KEYS) take precedence. Otherwise a key is read
// from, or generated and persisted to, a file alongside the platform key, so the
// daemon is never unauthenticated yet remains frictionless on first run.
func loadOrCreateAPIKeys(cfg *config.Config, logger *slog.Logger) (map[string]bool, error) {
	keys := map[string]bool{}
	for _, k := range cfg.Server.APIKeys {
		if k = strings.TrimSpace(k); k != "" {
			keys[k] = true
		}
	}
	if len(keys) > 0 {
		return keys, nil
	}

	path := apiKeyPath(cfg)
	data, err := os.ReadFile(path)
	if err == nil {
		if k := strings.TrimSpace(string(data)); k != "" {
			keys[k] = true
			return keys, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read api key %s: %w", path, err)
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generate api key: %w", err)
	}
	k := base64.RawURLEncoding.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(k), 0o600); err != nil {
		return nil, fmt.Errorf("write api key %s: %w", path, err)
	}
	logger.Warn("generated a random API key (no keys configured); read it from the file and store it securely", "path", path)
	keys[k] = true
	return keys, nil
}

// apiKeyPath returns the on-disk location of the auto-generated API key: a file
// named "api.key" alongside the platform key.
func apiKeyPath(cfg *config.Config) string {
	return filepath.Join(filepath.Dir(cfg.Identity.PlatformKeyPath), "api.key")
}

// persistInstance records the nonce-cache instance id and boot time to a file
// alongside the platform key. It is best-effort: a write failure is logged but
// never blocks startup. Each boot generates a fresh instance id; the recorded
// boot time backs the pre-boot invocation-replay defense (Fix 12).
func persistInstance(cfg *config.Config, instanceID string, startTime int64, logger *slog.Logger) {
	path := filepath.Join(filepath.Dir(cfg.Identity.PlatformKeyPath), "instance.id")
	content := fmt.Sprintf("%s\n%d\n", instanceID, startTime)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		logger.Warn("could not persist nonce-cache instance id", "path", path, "error", err)
		return
	}
	logger.Info("nonce-cache instance", "id", instanceID, "start_time", startTime)
}

func keyFromBytes(data []byte) (ed25519.PrivateKey, error) {
	switch len(data) {
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(data), nil
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(data), nil
	default:
		return nil, fmt.Errorf("expected %d or %d key bytes, got %d", ed25519.PrivateKeySize, ed25519.SeedSize, len(data))
	}
}
