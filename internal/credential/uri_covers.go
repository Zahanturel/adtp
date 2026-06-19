package credential

import "strings"

// URICovers reports whether the parent capability URI covers the child URI
// (specification Section 7.2). Both URIs are canonicalized first; any URI that
// fails canonicalization — for example one carrying an encoded separator or a
// dot-segment — causes URICovers to return false (fail closed), which is what
// makes this safe against the URI_COVERS bypass class.
//
// Coverage requires equal scheme, equal authority, and a positional,
// equal-length match of path segments. A single "*" segment in the parent
// matches exactly one non-empty child segment. "**" is reserved and unsupported,
// so coverage never spans more segments than the parent specifies.
func URICovers(parent, child string) bool {
	p, err := CanonicalizeURI(parent)
	if err != nil {
		return false
	}
	c, err := CanonicalizeURI(child)
	if err != nil {
		return false
	}
	if p == c {
		return true
	}

	pScheme, pAuthority, pPath, ok := splitCanonicalURI(p)
	if !ok {
		return false
	}
	cScheme, cAuthority, cPath, ok := splitCanonicalURI(c)
	if !ok {
		return false
	}
	if pScheme != cScheme || pAuthority != cAuthority {
		return false
	}

	pSeg := strings.Split(pPath, "/")
	cSeg := strings.Split(cPath, "/")
	if len(pSeg) != len(cSeg) {
		return false
	}
	for i := range pSeg {
		if pSeg[i] == "*" {
			// A wildcard matches exactly one non-empty segment.
			if cSeg[i] == "" {
				return false
			}
			continue
		}
		if pSeg[i] != cSeg[i] {
			return false
		}
	}
	return true
}

// splitCanonicalURI decomposes a canonical "scheme://authority[/path]" URI. The
// path retains its leading slash, or is empty when absent.
func splitCanonicalURI(u string) (scheme, authority, path string, ok bool) {
	i := strings.Index(u, "://")
	if i <= 0 {
		return "", "", "", false
	}
	scheme = u[:i]
	rest := u[i+3:]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		return scheme, rest[:j], rest[j:], true
	}
	return scheme, rest, "", true
}
