// Package credential implements ADTP credentials: content identifiers (CIDs),
// UCAN JWT creation and parsing, and capability/constraint definitions.
package credential

import (
	"crypto/sha256"
	"encoding/base32"
)

// CID profile (specification SD-5): CIDv1, raw codec (0x55), multihash
// sha2-256, computed over the complete serialized credential bytes. Because prf
// links pin this CID, they pin both content and signature.
const (
	cidV1           = 0x01 // CIDv1 version byte
	codecRaw        = 0x55 // multicodec "raw"
	multihashSHA256 = 0x12 // multihash code for sha2-256
	sha256Size      = 0x20 // sha2-256 digest length, in bytes
)

// cidBase32 is the multibase 'b' encoding: RFC 4648 base32, lowercase, no
// padding.
var cidBase32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// ComputeCID returns the CIDv1 of data as a base32 multibase string. Every CID
// produced here begins with "bafkrei", the fixed prefix of a CIDv1 with raw
// codec and a sha2-256 multihash.
func ComputeCID(data []byte) string {
	digest := sha256.Sum256(data)

	buf := make([]byte, 0, 4+sha256Size)
	buf = append(buf, cidV1, codecRaw, multihashSHA256, sha256Size)
	buf = append(buf, digest[:]...)

	return "b" + cidBase32.EncodeToString(buf)
}

// VerifyCID reports whether cid is the CID of data. It is used when loading a
// credential from a content-addressed store to detect tampering or
// cache poisoning (SD-5).
func VerifyCID(data []byte, cid string) bool {
	return ComputeCID(data) == cid
}
