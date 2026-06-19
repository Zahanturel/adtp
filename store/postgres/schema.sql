-- AITP PostgreSQL storage schema.
-- Applied by the daemon at startup (driver integration arrives in Phase 4).

CREATE TABLE IF NOT EXISTS agents (
    did           TEXT PRIMARY KEY,
    sponsor_did   TEXT NOT NULL,
    state         TEXT NOT NULL DEFAULT 'REGISTERED',
    registered_at BIGINT NOT NULL,
    activated_at  BIGINT,
    metadata      JSONB
);

CREATE TABLE IF NOT EXISTS credentials (
    cid          TEXT PRIMARY KEY,
    raw_bytes    BYTEA NOT NULL,
    issuer_did   TEXT NOT NULL,
    audience_did TEXT NOT NULL,
    exp          BIGINT NOT NULL,
    created_at   BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS registration_index (
    credential_cid TEXT NOT NULL,
    chain_cid      TEXT NOT NULL,
    PRIMARY KEY (credential_cid, chain_cid)
);

-- The cascade query (FindDescendants) walks chain_cid; this index is the
-- GIN-equivalent that keeps cascade enumeration efficient.
CREATE INDEX IF NOT EXISTS idx_reg_chain_cid ON registration_index (chain_cid);

CREATE TABLE IF NOT EXISTS revocation_entries (
    id              BIGSERIAL PRIMARY KEY,
    subject_cid     TEXT,
    subject_did     TEXT,
    scope           TEXT NOT NULL,
    status          TEXT NOT NULL,
    seq             BIGINT NOT NULL,
    authority_did   TEXT NOT NULL,
    authority_basis TEXT NOT NULL,
    authority_proof TEXT NOT NULL DEFAULT '',
    iat             BIGINT NOT NULL,
    prev_hash       TEXT NOT NULL DEFAULT '',
    entry_hash      TEXT NOT NULL,
    sig             TEXT NOT NULL,
    -- Prevents two concurrent revocations from assigning the same per-subject
    -- sequence (subject_cid/subject_did are stored as '' rather than NULL, so the
    -- constraint applies). Defense-in-depth alongside the per-subject advisory
    -- lock taken in Revoke.
    UNIQUE (subject_cid, subject_did, seq)
);

CREATE INDEX IF NOT EXISTS idx_rev_subject ON revocation_entries (subject_cid, subject_did);

CREATE TABLE IF NOT EXISTS audit_log (
    seq        BIGSERIAL PRIMARY KEY,
    entry_id   TEXT UNIQUE NOT NULL,
    ts         BIGINT NOT NULL,
    event_type TEXT NOT NULL,
    agent_id   TEXT,
    cred_cid   TEXT,
    chain_hash TEXT,
    payload    JSONB NOT NULL,
    prev_hash  TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
