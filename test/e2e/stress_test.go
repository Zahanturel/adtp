//go:build e2e

package e2e

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStress_ConcurrentVerification(t *testing.T) {
	d := startDaemon(t)

	agent := d.registerAgent(t, "stress@zerith.sh")
	cid, _ := d.issueCredential(t, agent, []map[string]any{
		toolInvokeCap("tool://server/*"),
	}, 3600)

	// Sanity check.
	ok, _, errCode := d.verify(t, cid, "tool/invoke", "tool://server/search", nil)
	if !ok {
		t.Fatalf("sanity verify failed: %s", errCode)
	}

	const workers = 50
	const requestsPerWorker = 20

	var (
		wg       sync.WaitGroup
		passed   atomic.Int64
		failed   atomic.Int64
		errored  atomic.Int64
	)

	start := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < requestsPerWorker; i++ {
				ok, _, _ := d.verify(t, cid, "tool/invoke", "tool://server/search", nil)
				if ok {
					passed.Add(1)
				} else {
					failed.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	total := passed.Load() + failed.Load() + errored.Load()
	rps := float64(total) / elapsed.Seconds()

	t.Logf("concurrent verification: %d workers x %d requests", workers, requestsPerWorker)
	t.Logf("  total: %d  passed: %d  failed: %d  errored: %d", total, passed.Load(), failed.Load(), errored.Load())
	t.Logf("  elapsed: %s  rps: %.0f", elapsed.Round(time.Millisecond), rps)

	if failed.Load() > 0 {
		t.Fatalf("%d verifications returned authorized=false (expected all to pass)", failed.Load())
	}
	if errored.Load() > 0 {
		t.Fatalf("%d verifications errored", errored.Load())
	}
}

func TestStress_ConcurrentVerifyAfterRevoke(t *testing.T) {
	d := startDaemon(t)

	agentA := d.registerAgent(t, "stress@zerith.sh")
	agentB := d.registerAgent(t, "stress@zerith.sh")

	rootCID, _ := d.issueCredential(t, agentA, []map[string]any{
		toolInvokeCap("tool://server/*"),
		delegateCap("tool://server/*", 5),
	}, 3600)

	now := time.Now().Unix()
	_, delegatedCID := d.delegate(t, rootCID, agentB, "restrict", 4, []map[string]any{
		timeWindowCaveat(now-60, now+3600),
	})

	// Revoke the root — cascade kills the delegation.
	code := d.revoke(t, rootCID, "subtree", "COMPROMISED")
	if code != 200 {
		t.Fatalf("revoke: got %d", code)
	}

	// Now hammer verification concurrently — every request must be denied.
	const workers = 50
	const requestsPerWorker = 20

	var (
		wg      sync.WaitGroup
		denied  atomic.Int64
		allowed atomic.Int64
	)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < requestsPerWorker; i++ {
				ok, _, _ := d.verify(t, delegatedCID, "tool/invoke", "tool://server/search", nil)
				if ok {
					allowed.Add(1)
				} else {
					denied.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	t.Logf("post-revocation stress: %d denied, %d allowed", denied.Load(), allowed.Load())

	if allowed.Load() > 0 {
		t.Fatalf("CRITICAL: %d verifications passed after revocation — revocation is not watertight under concurrency", allowed.Load())
	}
}
