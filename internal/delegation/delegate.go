// SPDX-License-Identifier: Apache-2.0

package delegation

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/Zahanturel/adtp/internal/credential"
)

// Issuance errors.
var (
	ErrCannotDelegate = errors.New("credential does not authorize delegation")
	ErrDepthExhausted = errors.New("delegation depth is exhausted")
)

// ParentFromUCAN derives the delegation context from a UCAN. The delegable
// depth is taken from a delegation_depth constraint on the credential's
// agent/delegate capability; its absence means the credential may not delegate
// (Section 8.1).
func ParentFromUCAN(u *credential.UCAN, cid string) (credential.DelegationParent, error) {
	depth, ok := delegableDepth(u)
	if !ok {
		return credential.DelegationParent{}, fmt.Errorf("adtp/delegation: %w: no agent/delegate capability with delegation_depth", ErrCannotDelegate)
	}
	return credential.DelegationParent{
		CID: cid,
		Aud: u.Payload.Aud,
		Exp: u.Payload.Exp,
		Nbf: u.Payload.Nbf,
		DL:  depth,
	}, nil
}

// ParentFromBlock derives the delegation context from a RESTRICT block, whose
// depth-left it carries directly.
func ParentFromBlock(b *credential.RestrictBlock, cid string) credential.DelegationParent {
	return credential.DelegationParent{
		CID: cid,
		Aud: b.Aud,
		Exp: b.Exp,
		Nbf: b.Nbf,
		DL:  b.DL,
	}
}

func delegableDepth(u *credential.UCAN) (int, bool) {
	for _, c := range u.Payload.Att {
		if c.Can != credential.CanAgentDelegate {
			continue
		}
		for _, con := range c.Constraints {
			if dd, ok := con.(credential.DelegationDepthConstraint); ok {
				return dd.Max, true
			}
		}
	}
	return 0, false
}

// DelegateRestrict issues a RESTRICT delegation from parent to audDID with the
// given caveats and child depth-left, signs it with signerKey, stores it, and
// returns the block and its CID. depth must be strictly below the parent's
// depth-left.
func DelegateRestrict(parent credential.DelegationParent, audDID string, caveats credential.Constraints, depth int, signerKey ed25519.PrivateKey, store *MemoryProofStore) (*credential.RestrictBlock, string, error) {
	if parent.DL <= 0 {
		return nil, "", fmt.Errorf("adtp/delegation: %w: parent depth-left %d", ErrDepthExhausted, parent.DL)
	}
	block, raw, err := credential.CreateRestrictBlock(parent, audDID, depth, caveats, signerKey)
	if err != nil {
		return nil, "", err
	}
	return block, store.Put(raw), nil
}
