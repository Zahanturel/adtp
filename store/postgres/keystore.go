// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Zahanturel/adtp/internal/identity"
)

// KeyStore is a PostgreSQL-backed identity.KeyStore. It exists so that agent
// keys survive a daemon restart: with the in-memory store, every agent
// registered before a restart becomes unusable afterwards — the credentials
// still verify, but the daemon can no longer sign as the agent, so delegation
// and custodial invocation both fail.
//
// SECURITY: keys are stored as raw plaintext bytes. The daemon is custodial by
// design — it signs on each agent's behalf and therefore must recover the key
// material — so read access to the agent_keys table is equivalent to
// impersonating every agent in it. See the schema comment and README "Status".
type KeyStore struct {
	pool *pgxpool.Pool
}

// Compile-time assertion that KeyStore satisfies the interface.
var _ identity.KeyStore = (*KeyStore)(nil)

// Keys returns the store's PostgreSQL-backed key store. It shares the store's
// connection pool, so closing the store also closes the key store.
func (s *PostgresStore) Keys() *KeyStore {
	return &KeyStore{pool: s.pool}
}

// Store saves priv under did, replacing any existing key for that DID. The
// interface is context-free, so the package-level background context is used;
// calls are short single-statement round trips.
func (k *KeyStore) Store(did string, priv ed25519.PrivateKey) error {
	if did == "" {
		return fmt.Errorf("adtp/store/postgres: %w", identity.ErrEmptyDID)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("adtp/store/postgres: %w: have %d bytes, want %d",
			identity.ErrInvalidPrivateKey, len(priv), ed25519.PrivateKeySize)
	}
	_, err := k.pool.Exec(context.Background(),
		`INSERT INTO agent_keys (did, private_key, created_at) VALUES ($1, $2, $3)
		 ON CONFLICT (did) DO UPDATE SET private_key = EXCLUDED.private_key`,
		did, []byte(priv), time.Now().Unix())
	if err != nil {
		return fmt.Errorf("adtp/store/postgres: store key: %w", err)
	}
	return nil
}

// Load returns the private key for did, or identity.ErrKeyNotFound.
func (k *KeyStore) Load(did string) (ed25519.PrivateKey, error) {
	var raw []byte
	err := k.pool.QueryRow(context.Background(),
		`SELECT private_key FROM agent_keys WHERE did = $1`, did).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("adtp/store/postgres: %w: %s", identity.ErrKeyNotFound, did)
	}
	if err != nil {
		return nil, fmt.Errorf("adtp/store/postgres: load key: %w", err)
	}
	// A row whose length is wrong is corrupt, not merely absent: ed25519.Sign
	// panics on a wrong-sized key, so reject it here rather than at use.
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("adtp/store/postgres: %w: stored key for %s is %d bytes, want %d",
			identity.ErrInvalidPrivateKey, did, len(raw), ed25519.PrivateKeySize)
	}
	out := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(out, raw)
	return out, nil
}

// Delete removes the key for did, or returns identity.ErrKeyNotFound.
func (k *KeyStore) Delete(did string) error {
	tag, err := k.pool.Exec(context.Background(),
		`DELETE FROM agent_keys WHERE did = $1`, did)
	if err != nil {
		return fmt.Errorf("adtp/store/postgres: delete key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("adtp/store/postgres: %w: %s", identity.ErrKeyNotFound, did)
	}
	return nil
}

// List returns the stored DIDs in ascending order. A query failure yields nil;
// the interface has no error return, and every caller treats the result as
// advisory.
func (k *KeyStore) List() []string {
	rows, err := k.pool.Query(context.Background(),
		`SELECT did FROM agent_keys ORDER BY did`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	dids, err := collectStrings(rows)
	if err != nil {
		return nil
	}
	return dids
}
