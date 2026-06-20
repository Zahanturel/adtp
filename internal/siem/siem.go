// Package siem batches audit events and exports them to an external HTTP sink
// (Datadog, Splunk, Elastic, or any webhook). It is best-effort and out of the
// authorization hot path: export failures never affect verification or the
// durable audit log.
package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/Zahanturel/adtp/internal/audit"
)

// Config configures the SIEM webhook export.
type Config struct {
	URL           string
	Headers       map[string]string
	BatchSize     int
	FlushInterval time.Duration
}

const (
	defaultBatchSize     = 100
	defaultFlushInterval = 10 * time.Second
	maxBufferedFactor    = 10 // cap the buffer at BatchSize*this to bound memory
)

// Exporter buffers audit entries and flushes them to the configured webhook in
// batches, on an interval or when a batch fills.
type Exporter struct {
	url           string
	headers       map[string]string
	batchSize     int
	flushInterval time.Duration
	maxBuffered   int
	client        *http.Client
	logger        *slog.Logger

	mu  sync.Mutex
	buf []audit.AuditEntry

	flushNow chan struct{}
}

// NewExporter builds an Exporter. Header values may reference environment
// variables as ${VAR}; they are resolved once here.
func NewExporter(cfg Config, logger *slog.Logger) *Exporter {
	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = defaultBatchSize
	}
	interval := cfg.FlushInterval
	if interval <= 0 {
		interval = defaultFlushInterval
	}
	headers := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		headers[k] = expandEnv(v)
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Exporter{
		url:           cfg.URL,
		headers:       headers,
		batchSize:     batchSize,
		flushInterval: interval,
		maxBuffered:   batchSize * maxBufferedFactor,
		client:        &http.Client{Timeout: 15 * time.Second},
		logger:        logger,
		flushNow:      make(chan struct{}, 1),
	}
}

// Enqueue adds an entry to the buffer. It never blocks. When the buffer reaches
// the batch size it signals an immediate flush; if the buffer is over its cap
// (the sink is persistently failing) the oldest entries are dropped.
func (e *Exporter) Enqueue(entry audit.AuditEntry) {
	e.mu.Lock()
	e.buf = append(e.buf, entry)
	if len(e.buf) > e.maxBuffered {
		drop := len(e.buf) - e.maxBuffered
		e.buf = e.buf[drop:]
		e.logger.Warn("siem buffer full; dropping oldest audit events", "dropped", drop)
	}
	full := len(e.buf) >= e.batchSize
	e.mu.Unlock()
	if full {
		select {
		case e.flushNow <- struct{}{}:
		default:
		}
	}
}

// Start runs the flush loop until ctx is canceled, flushing once more on exit.
func (e *Exporter) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(e.flushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				e.Flush()
			case <-e.flushNow:
				e.Flush()
			case <-ctx.Done():
				e.Flush()
				return
			}
		}
	}()
}

// Flush sends the buffered batch to the webhook. On failure the batch is
// requeued (subject to the buffer cap) to retry on the next flush.
func (e *Exporter) Flush() {
	e.mu.Lock()
	if len(e.buf) == 0 {
		e.mu.Unlock()
		return
	}
	batch := e.buf
	e.buf = nil
	e.mu.Unlock()

	if err := e.post(batch); err != nil {
		e.logger.Warn("siem export failed; requeuing", "count", len(batch), "error", err)
		e.mu.Lock()
		e.buf = append(batch, e.buf...)
		if len(e.buf) > e.maxBuffered {
			drop := len(e.buf) - e.maxBuffered
			e.buf = e.buf[drop:]
			e.logger.Warn("siem requeue overflow; dropping oldest audit events", "dropped", drop)
		}
		e.mu.Unlock()
	}
}

func (e *Exporter) post(batch []audit.AuditEntry) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range e.headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("siem webhook returned status %d", resp.StatusCode)
	}
	return nil
}

// Buffered reports the number of entries awaiting export (for tests/metrics).
func (e *Exporter) Buffered() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.buf)
}

func expandEnv(v string) string {
	return os.Expand(v, os.Getenv)
}
