package siem

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Zahanturel/adtp/internal/audit"
)

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func captureServer(t *testing.T, status int) (*httptest.Server, chan []audit.AuditEntry, chan http.Header) {
	t.Helper()
	batches := make(chan []audit.AuditEntry, 8)
	headers := make(chan http.Header, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b []audit.AuditEntry
		_ = json.NewDecoder(r.Body).Decode(&b)
		batches <- b
		headers <- r.Header.Clone()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, batches, headers
}

func TestExporterFlushPostsBatch(t *testing.T) {
	srv, batches, headers := captureServer(t, http.StatusOK)
	t.Setenv("TEST_SIEM_KEY", "secret-123")

	e := NewExporter(Config{
		URL:           srv.URL,
		Headers:       map[string]string{"DD-API-KEY": "${TEST_SIEM_KEY}"},
		BatchSize:     10,
		FlushInterval: time.Hour,
	}, testLogger())

	for _, et := range []string{"A", "B", "C"} {
		e.Enqueue(audit.AuditEntry{EventType: et})
	}
	e.Flush()

	batch := <-batches
	if len(batch) != 3 {
		t.Errorf("batch size = %d, want 3", len(batch))
	}
	h := <-headers
	if h.Get("DD-API-KEY") != "secret-123" {
		t.Errorf("header = %q, want resolved env value", h.Get("DD-API-KEY"))
	}
	if h.Get("Content-Type") != "application/json" {
		t.Errorf("content-type = %q", h.Get("Content-Type"))
	}
	if e.Buffered() != 0 {
		t.Errorf("buffer not drained: %d", e.Buffered())
	}
}

func TestExporterAutoFlushOnBatchFull(t *testing.T) {
	srv, batches, _ := captureServer(t, http.StatusOK)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	e := NewExporter(Config{URL: srv.URL, BatchSize: 2, FlushInterval: time.Hour}, testLogger())
	e.Start(ctx)

	e.Enqueue(audit.AuditEntry{EventType: "X"})
	e.Enqueue(audit.AuditEntry{EventType: "Y"}) // reaches batch size -> auto flush

	select {
	case batch := <-batches:
		if len(batch) != 2 {
			t.Errorf("auto-flush batch = %d, want 2", len(batch))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for auto-flush")
	}
}

func TestExporterRequeuesOnFailure(t *testing.T) {
	srv, batches, _ := captureServer(t, http.StatusInternalServerError)
	e := NewExporter(Config{URL: srv.URL, BatchSize: 10, FlushInterval: time.Hour}, testLogger())

	e.Enqueue(audit.AuditEntry{EventType: "A"})
	e.Flush()
	<-batches // the failing POST still delivered a body

	if e.Buffered() == 0 {
		t.Errorf("entry dropped on failure; want requeue")
	}
}

func TestExporterFlushEmptyNoop(t *testing.T) {
	e := NewExporter(Config{URL: "http://127.0.0.1:0", BatchSize: 2, FlushInterval: time.Hour}, testLogger())
	e.Flush() // nothing buffered: must not panic or POST
	if e.Buffered() != 0 {
		t.Errorf("buffered = %d, want 0", e.Buffered())
	}
}

func TestExporterBufferCap(t *testing.T) {
	// No consumer is started, so the buffer grows until capped at BatchSize*10.
	e := NewExporter(Config{URL: "http://127.0.0.1:0", BatchSize: 2, FlushInterval: time.Hour}, testLogger())
	for i := 0; i < 50; i++ {
		e.Enqueue(audit.AuditEntry{EventType: "x"})
	}
	if got := e.Buffered(); got > 2*maxBufferedFactor {
		t.Errorf("buffer not capped: %d > %d", got, 2*maxBufferedFactor)
	}
}

func TestExporterDefaults(t *testing.T) {
	e := NewExporter(Config{URL: "http://x"}, nil) // zero batch/interval, nil logger
	if e.batchSize != defaultBatchSize || e.flushInterval != defaultFlushInterval {
		t.Errorf("defaults not applied: batch=%d interval=%v", e.batchSize, e.flushInterval)
	}
}
