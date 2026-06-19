package credential

import "testing"

func TestURICovers(t *testing.T) {
	tests := []struct {
		name   string
		parent string
		child  string
		want   bool
	}{
		{"wildcard matches one segment", "mcp://s/*", "mcp://s/tool", true},
		{"wildcard does not span segments", "mcp://s/*", "mcp://s/a/b", false},
		{"distinct segments", "mcp://s/a", "mcp://s/b", false},
		{"identity", "mcp://s/a", "mcp://s/a", true},
		{"scheme case normalized", "MCP://S/tool", "mcp://s/tool", true},
		{"trailing slash significant", "mcp://s/a", "mcp://s/a/", false},
		{"deeper exact match", "mcp://s/a/b", "mcp://s/a/b", true},
		{"wildcard in middle", "mcp://s/*/c", "mcp://s/b/c", true},
		{"wildcard in middle wrong tail", "mcp://s/*/c", "mcp://s/b/d", false},
		{"wildcard rejects empty segment", "mcp://s/*", "mcp://s/", false},
		{"different scheme", "mcp://s/a", "https://s/a", false},
		{"different authority", "mcp://s1/a", "mcp://s2/a", false},
		{"parent shorter is not prefix-covered", "mcp://s/a", "mcp://s/a/b", false},
		{"child shorter", "mcp://s/a/b", "mcp://s/a", false},
		{"authority only identity", "https://example.com", "https://example.com", true},

		// Adversarial inputs: any URI that fails canonicalization is not covered.
		{"encoded dot-dot traversal rejected", "mcp://s/*", "mcp://s/%2e%2e/admin", false},
		{"encoded separator rejected in child", "mcp://s/*", "mcp://s/a%2Fb", false},
		{"encoded separator rejected in parent", "mcp://s/a%2Fb", "mcp://s/a/b", false},
		{"literal dot-dot rejected", "mcp://s/a", "mcp://s/../a", false},
		{"encoded nul rejected", "mcp://s/*", "mcp://s/a%00", false},
		{"malformed parent", "not-a-uri", "mcp://s/a", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := URICovers(tt.parent, tt.child); got != tt.want {
				t.Errorf("URICovers(%q, %q) = %v, want %v", tt.parent, tt.child, got, tt.want)
			}
		})
	}
}
