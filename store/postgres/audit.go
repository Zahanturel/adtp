package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/adtp/adtp/internal/audit"
)

// auditChainLockKey is the fixed advisory-lock key that serializes audit
// appends. A hash chain links each entry to the previous one, so appends cannot
// run concurrently and still form a valid chain; the lock guarantees the
// MAX(seq)/prev_hash read and the insert are atomic across connections.
const auditChainLockKey int64 = 0x41445450_4C4F47 // "ADTPLOG"

// postgresAuditLog is the PostgreSQL-backed hash-linked audit log. Sequence
// numbers and hash linkage are computed in Go inside a transaction so the
// linkage is identical to the in-memory log (Section 14).
type postgresAuditLog struct {
	pool *pgxpool.Pool
}

var _ audit.AuditLog = (*postgresAuditLog)(nil)

func (l *postgresAuditLog) Append(entry audit.AuditEntry) error {
	ctx := context.Background()
	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("aitp/store/postgres: audit begin: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, auditChainLockKey); err != nil {
		return fmt.Errorf("aitp/store/postgres: audit lock: %w", err)
	}

	var seq int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(seq), 0) FROM audit_log`).Scan(&seq); err != nil {
		return fmt.Errorf("aitp/store/postgres: audit seq: %w", err)
	}
	seq++

	var prevHash string
	err = tx.QueryRow(ctx, `SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&prevHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("aitp/store/postgres: audit prev: %w", err)
	}

	entry.Seq = seq
	if entry.Ts == 0 {
		entry.Ts = time.Now().Unix()
	}
	if entry.Payload == nil {
		entry.Payload = map[string]any{}
	}
	entry.PrevHash = prevHash

	hash, err := audit.ComputeEntryHash(entry.Seq, entry.Ts, entry.PrevHash,
		entry.EventType, entry.AgentID, entry.CredCID, entry.ChainHash, entry.Payload)
	if err != nil {
		return err
	}
	entry.EntryHash = hash
	entry.EntryID = fmt.Sprintf("ae_%d_%s", entry.Seq, hash[:12])

	payloadJSON, err := json.Marshal(entry.Payload)
	if err != nil {
		return fmt.Errorf("aitp/store/postgres: audit payload: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO audit_log (seq, entry_id, ts, event_type, agent_id, cred_cid, chain_hash, payload, prev_hash, entry_hash)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		entry.Seq, entry.EntryID, entry.Ts, entry.EventType, entry.AgentID, entry.CredCID,
		entry.ChainHash, string(payloadJSON), entry.PrevHash, entry.EntryHash); err != nil {
		return fmt.Errorf("aitp/store/postgres: audit insert: %w", err)
	}
	return tx.Commit(ctx)
}

func (l *postgresAuditLog) Query(filter audit.AuditFilter) ([]audit.AuditEntry, error) {
	q := `SELECT seq, entry_id, ts, event_type, COALESCE(agent_id,''), COALESCE(cred_cid,''),
	             COALESCE(chain_hash,''), payload, prev_hash, entry_hash
	      FROM audit_log WHERE 1 = 1`
	var args []any
	if filter.EventType != "" {
		args = append(args, filter.EventType)
		q += fmt.Sprintf(" AND event_type = $%d", len(args))
	}
	if filter.AgentID != "" {
		args = append(args, filter.AgentID)
		q += fmt.Sprintf(" AND agent_id = $%d", len(args))
	}
	if filter.Since != 0 {
		args = append(args, filter.Since)
		q += fmt.Sprintf(" AND ts >= $%d", len(args))
	}
	q += " ORDER BY seq"

	rows, err := l.pool.Query(context.Background(), q, args...)
	if err != nil {
		return nil, fmt.Errorf("aitp/store/postgres: audit query: %w", err)
	}
	defer rows.Close()

	var out []audit.AuditEntry
	for rows.Next() {
		var (
			e           audit.AuditEntry
			payloadJSON []byte
		)
		if err := rows.Scan(&e.Seq, &e.EntryID, &e.Ts, &e.EventType, &e.AgentID, &e.CredCID,
			&e.ChainHash, &payloadJSON, &e.PrevHash, &e.EntryHash); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payloadJSON, &e.Payload); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (l *postgresAuditLog) VerifyChain() error {
	rows, err := l.pool.Query(context.Background(),
		`SELECT seq, ts, event_type, COALESCE(agent_id,''), COALESCE(cred_cid,''),
		        COALESCE(chain_hash,''), payload, prev_hash, entry_hash
		 FROM audit_log ORDER BY seq`)
	if err != nil {
		return fmt.Errorf("aitp/store/postgres: audit verify: %w", err)
	}
	defer rows.Close()

	prev := ""
	for rows.Next() {
		var (
			seq         int64
			ts          int64
			eventType   string
			agentID     string
			credCID     string
			chainHash   string
			payloadJSON []byte
			prevHash    string
			entryHash   string
		)
		if err := rows.Scan(&seq, &ts, &eventType, &agentID, &credCID, &chainHash, &payloadJSON, &prevHash, &entryHash); err != nil {
			return err
		}
		if prevHash != prev {
			return fmt.Errorf("aitp/store/postgres: %w: seq %d prev_hash break", audit.ErrChainTampered, seq)
		}
		var payload map[string]any
		if err := json.Unmarshal(payloadJSON, &payload); err != nil {
			return err
		}
		hash, err := audit.ComputeEntryHash(seq, ts, prevHash, eventType, agentID, credCID, chainHash, payload)
		if err != nil {
			return err
		}
		if hash != entryHash {
			return fmt.Errorf("aitp/store/postgres: %w: seq %d hash mismatch", audit.ErrChainTampered, seq)
		}
		prev = entryHash
	}
	return rows.Err()
}
