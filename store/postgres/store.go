// Package postgres is the PostgreSQL storage backend. It implements the unified
// store.Store interface over a pgx connection pool, with transactional writes
// for the operations that must be atomic.
package postgres

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/adtp/adtp/internal/audit"
	"github.com/adtp/adtp/internal/credential"
	"github.com/adtp/adtp/internal/lifecycle"
	"github.com/adtp/adtp/internal/revocation"
	"github.com/adtp/adtp/store"
)

// Schema is the SQL DDL applied on first connect.
//
//go:embed schema.sql
var Schema string

// Store errors.
var (
	ErrAgentNotFound      = errors.New("agent not found")
	ErrCredentialNotFound = errors.New("credential not found")
	ErrInvalidAgent       = errors.New("invalid agent")
)

// PostgresStore is a PostgreSQL-backed store.
type PostgresStore struct {
	pool  *pgxpool.Pool
	audit *postgresAuditLog
}

var _ store.Store = (*PostgresStore)(nil)

// NewPostgresStore connects to connString, applies the schema (idempotently),
// and returns the store.
func NewPostgresStore(connString string) (*PostgresStore, error) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("aitp/store/postgres: connect: %w", err)
	}
	if _, err := pool.Exec(ctx, Schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("aitp/store/postgres: migrate: %w", err)
	}
	return &PostgresStore{pool: pool, audit: &postgresAuditLog{pool: pool}}, nil
}

// Close releases the connection pool.
func (s *PostgresStore) Close() error {
	s.pool.Close()
	return nil
}

// --- agents ---

func (s *PostgresStore) PutAgent(a *lifecycle.Agent) error {
	if a == nil || a.DID == "" {
		return fmt.Errorf("aitp/store/postgres: %w", ErrInvalidAgent)
	}
	_, err := s.pool.Exec(context.Background(),
		`INSERT INTO agents (did, sponsor_did, state, registered_at, activated_at)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (did) DO UPDATE SET state = EXCLUDED.state, activated_at = EXCLUDED.activated_at`,
		a.DID, a.SponsorDID, string(a.State), a.RegisteredAt, a.ActivatedAt)
	if err != nil {
		return fmt.Errorf("aitp/store/postgres: put agent: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetAgent(did string) (*lifecycle.Agent, error) {
	var (
		a     lifecycle.Agent
		state string
	)
	err := s.pool.QueryRow(context.Background(),
		`SELECT did, sponsor_did, state, registered_at, COALESCE(activated_at, 0)
		 FROM agents WHERE did = $1`, did).
		Scan(&a.DID, &a.SponsorDID, &state, &a.RegisteredAt, &a.ActivatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("aitp/store/postgres: %w: %s", ErrAgentNotFound, did)
	}
	if err != nil {
		return nil, fmt.Errorf("aitp/store/postgres: get agent: %w", err)
	}
	a.State = lifecycle.AgentState(state)
	return &a, nil
}

// --- credentials / proof store ---

func (s *PostgresStore) PutCredential(raw []byte) (string, error) {
	cid := credential.ComputeCID(raw)
	iss, aud, exp, err := credentialMeta(raw)
	if err != nil {
		return "", fmt.Errorf("aitp/store/postgres: parse credential: %w", err)
	}
	_, err = s.pool.Exec(context.Background(),
		`INSERT INTO credentials (cid, raw_bytes, issuer_did, audience_did, exp, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (cid) DO NOTHING`,
		cid, raw, iss, aud, exp, time.Now().Unix())
	if err != nil {
		return "", fmt.Errorf("aitp/store/postgres: put credential: %w", err)
	}
	return cid, nil
}

func (s *PostgresStore) Get(cid string) ([]byte, error) {
	var raw []byte
	err := s.pool.QueryRow(context.Background(),
		`SELECT raw_bytes FROM credentials WHERE cid = $1`, cid).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("aitp/store/postgres: %w: %s", ErrCredentialNotFound, cid)
	}
	if err != nil {
		return nil, fmt.Errorf("aitp/store/postgres: get credential: %w", err)
	}
	return raw, nil
}

func (s *PostgresStore) ListCredentials() ([]string, error) {
	rows, err := s.pool.Query(context.Background(),
		`SELECT cid FROM credentials ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("aitp/store/postgres: list credentials: %w", err)
	}
	defer rows.Close()
	return collectStrings(rows)
}

// --- registration index ---

func (s *PostgresStore) Register(credentialCID string, chainCIDs []string) error {
	ctx := context.Background()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("aitp/store/postgres: begin: %w", err)
	}
	defer tx.Rollback(ctx)
	for _, c := range chainCIDs {
		if _, err := tx.Exec(ctx,
			`INSERT INTO registration_index (credential_cid, chain_cid)
			 VALUES ($1, $2) ON CONFLICT DO NOTHING`, credentialCID, c); err != nil {
			return fmt.Errorf("aitp/store/postgres: register: %w", err)
		}
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) FindDescendants(cid string) ([]string, error) {
	rows, err := s.pool.Query(context.Background(),
		`SELECT credential_cid FROM registration_index
		 WHERE chain_cid = $1 AND credential_cid <> $1 ORDER BY credential_cid`, cid)
	if err != nil {
		return nil, fmt.Errorf("aitp/store/postgres: find descendants: %w", err)
	}
	defer rows.Close()
	return collectStrings(rows)
}

func (s *PostgresStore) Contains(credentialCID, chainCID string) bool {
	var one int
	err := s.pool.QueryRow(context.Background(),
		`SELECT 1 FROM registration_index WHERE credential_cid = $1 AND chain_cid = $2`,
		credentialCID, chainCID).Scan(&one)
	return err == nil
}

// --- revocation ---

func (s *PostgresStore) Revoke(e revocation.RevocationEntry) error {
	if e.Subject.CID == "" && e.Subject.DID == "" {
		return fmt.Errorf("aitp/store/postgres: %w", revocation.ErrMissingSubject)
	}
	if err := revocation.VerifyEntrySelfSignature(&e); err != nil {
		return err
	}
	ctx := context.Background()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("aitp/store/postgres: begin: %w", err)
	}
	defer tx.Rollback(ctx)

	// Serialize concurrent revocations for the same subject so the MAX(seq)+1 read
	// and the insert are atomic (the UNIQUE constraint is the backstop). The lock
	// is released on commit/rollback.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, e.Subject.CID+"\x00"+e.Subject.DID); err != nil {
		return fmt.Errorf("aitp/store/postgres: revoke lock: %w", err)
	}

	var maxSeq int64
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(MAX(seq), 0) FROM revocation_entries WHERE subject_cid = $1 AND subject_did = $2`,
		e.Subject.CID, e.Subject.DID).Scan(&maxSeq); err != nil {
		return fmt.Errorf("aitp/store/postgres: seq lookup: %w", err)
	}
	if e.Seq <= maxSeq {
		return fmt.Errorf("aitp/store/postgres: %w: seq %d <= %d", revocation.ErrSequenceRollback, e.Seq, maxSeq)
	}

	hash, err := e.Hash()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO revocation_entries
		 (subject_cid, subject_did, scope, status, seq, authority_did, authority_basis, authority_proof, iat, prev_hash, entry_hash, sig)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		e.Subject.CID, e.Subject.DID, string(e.Scope), string(e.Status), e.Seq,
		e.Authority.DID, string(e.Authority.Basis), e.Authority.Proof, e.Iat, e.Prev, hash, e.Sig); err != nil {
		return fmt.Errorf("aitp/store/postgres: insert revocation: %w", err)
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) GetStatus(subject string) (*revocation.RevocationEntry, error) {
	row := s.pool.QueryRow(context.Background(),
		`SELECT subject_cid, subject_did, scope, status, seq, authority_did, authority_basis, authority_proof, iat, prev_hash, sig
		 FROM revocation_entries WHERE subject_cid = $1 OR subject_did = $1 ORDER BY seq DESC LIMIT 1`, subject)
	e, err := scanRevocation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("aitp/store/postgres: get status: %w", err)
	}
	if e.Status == revocation.StatusReinstated {
		return nil, nil
	}
	return e, nil
}

func (s *PostgresStore) CurrentSeq(subject string) int64 {
	var seq int64
	_ = s.pool.QueryRow(context.Background(),
		`SELECT COALESCE(MAX(seq), 0) FROM revocation_entries WHERE subject_cid = $1 OR subject_did = $1`,
		subject).Scan(&seq)
	return seq
}

func (s *PostgresStore) RevocationEntries() ([]revocation.RevocationEntry, error) {
	rows, err := s.pool.Query(context.Background(),
		`SELECT DISTINCT ON (COALESCE(NULLIF(subject_cid, ''), subject_did))
		   subject_cid, subject_did, scope, status, seq, authority_did, authority_basis, authority_proof, iat, prev_hash, sig
		 FROM revocation_entries
		 ORDER BY COALESCE(NULLIF(subject_cid, ''), subject_did), seq DESC`)
	if err != nil {
		return nil, fmt.Errorf("aitp/store/postgres: revocation entries: %w", err)
	}
	defer rows.Close()

	var out []revocation.RevocationEntry
	for rows.Next() {
		e, err := scanRevocation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

// Audit returns the PostgreSQL-backed audit log.
func (s *PostgresStore) Audit() audit.AuditLog { return s.audit }

// --- helpers ---

// credentialMeta extracts the issuer, audience, and expiry from a serialized
// credential (UCAN token or RESTRICT block) for the indexed columns.
func credentialMeta(raw []byte) (issuer, audience string, exp int64, err error) {
	if t := bytes.TrimSpace(raw); len(t) > 0 && t[0] == '{' {
		b, perr := credential.ParseRestrictBlock(raw)
		if perr != nil {
			return "", "", 0, perr
		}
		return b.Iss, b.Aud, b.Exp, nil
	}
	u, perr := credential.ParseUCAN(string(raw))
	if perr != nil {
		return "", "", 0, perr
	}
	return u.Payload.Iss, u.Payload.Aud, u.Payload.Exp, nil
}

func collectStrings(rows pgx.Rows) ([]string, error) {
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// scanRevocation maps a row into a RevocationEntry. The typ is the invariant
// tag, reconstructed rather than stored.
func scanRevocation(row pgx.Row) (*revocation.RevocationEntry, error) {
	var (
		e      revocation.RevocationEntry
		scope  string
		status string
		basis  string
	)
	if err := row.Scan(&e.Subject.CID, &e.Subject.DID, &scope, &status, &e.Seq,
		&e.Authority.DID, &basis, &e.Authority.Proof, &e.Iat, &e.Prev, &e.Sig); err != nil {
		return nil, err
	}
	e.Typ = revocation.RevocationEntryTyp
	e.Scope = revocation.RevocationScope(scope)
	e.Status = revocation.RevocationStatus(status)
	e.Authority.Basis = revocation.RevocationAuthority(basis)
	return &e, nil
}
