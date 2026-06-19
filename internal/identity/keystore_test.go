package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"sync"
	"testing"
)

func mustKey(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	did, priv, err := GenerateDID()
	if err != nil {
		t.Fatalf("GenerateDID: %v", err)
	}
	return did, priv
}

func TestMemoryKeyStoreStoreLoad(t *testing.T) {
	ks := NewMemoryKeyStore()
	did, priv := mustKey(t)

	if err := ks.Store(did, priv); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, err := ks.Load(did)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(got, priv) {
		t.Errorf("loaded key does not match stored key")
	}
}

func TestMemoryKeyStoreLoadMissing(t *testing.T) {
	ks := NewMemoryKeyStore()
	if _, err := ks.Load("did:key:zMissing"); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Load(missing) = %v, want ErrKeyNotFound", err)
	}
}

func TestMemoryKeyStoreDelete(t *testing.T) {
	ks := NewMemoryKeyStore()
	did, priv := mustKey(t)
	if err := ks.Store(did, priv); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if err := ks.Delete(did); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := ks.Load(did); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Load after Delete = %v, want ErrKeyNotFound", err)
	}
	if err := ks.Delete(did); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Delete(missing) = %v, want ErrKeyNotFound", err)
	}
}

func TestMemoryKeyStoreStoreErrors(t *testing.T) {
	ks := NewMemoryKeyStore()
	_, priv := mustKey(t)

	if err := ks.Store("", priv); !errors.Is(err, ErrEmptyDID) {
		t.Errorf("Store(empty did) = %v, want ErrEmptyDID", err)
	}
	if err := ks.Store("did:key:zX", ed25519.PrivateKey{1, 2, 3}); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Errorf("Store(short key) = %v, want ErrInvalidPrivateKey", err)
	}
}

func TestMemoryKeyStoreList(t *testing.T) {
	ks := NewMemoryKeyStore()
	if got := ks.List(); len(got) != 0 {
		t.Errorf("List(empty) = %v, want empty", got)
	}

	dids := make([]string, 3)
	for i := range dids {
		did, priv := mustKey(t)
		dids[i] = did
		if err := ks.Store(did, priv); err != nil {
			t.Fatalf("Store: %v", err)
		}
	}

	got := ks.List()
	if len(got) != 3 {
		t.Fatalf("List length = %d, want 3", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Errorf("List not sorted ascending: %v", got)
		}
	}
}

// TestMemoryKeyStoreStoreIsolation verifies that the store owns a private copy
// of key material: mutating the caller's slice after Store, or the slice
// returned by Load, must not affect what is stored.
func TestMemoryKeyStoreStoreIsolation(t *testing.T) {
	ks := NewMemoryKeyStore()
	did, priv := mustKey(t)
	original := bytes.Clone(priv)

	if err := ks.Store(did, priv); err != nil {
		t.Fatalf("Store: %v", err)
	}
	// Mutating the caller's slice must not change the stored key.
	for i := range priv {
		priv[i] = 0
	}
	got, err := ks.Load(did)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("store did not isolate caller's slice")
	}

	// Mutating a loaded slice must not change the stored key.
	for i := range got {
		got[i] = 0
	}
	again, err := ks.Load(did)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(again, original) {
		t.Errorf("load did not isolate returned slice")
	}
}

// TestMemoryKeyStoreConcurrent exercises concurrent access; run with -race to
// detect data races.
func TestMemoryKeyStoreConcurrent(t *testing.T) {
	ks := NewMemoryKeyStore()
	const workers = 16

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			seed := make([]byte, ed25519.SeedSize)
			if _, err := rand.Read(seed); err != nil {
				return
			}
			priv := ed25519.NewKeyFromSeed(seed)
			did := EncodeDID(priv.Public().(ed25519.PublicKey))
			for i := 0; i < 100; i++ {
				_ = ks.Store(did, priv)
				_, _ = ks.Load(did)
				_ = ks.List()
				_ = ks.Delete(did)
			}
		}()
	}
	wg.Wait()
}

func TestMemoryKeyStoreSatisfiesInterface(t *testing.T) {
	var ks KeyStore = NewMemoryKeyStore()
	if reflect.TypeOf(ks) == nil {
		t.Fatal("nil store")
	}
}
