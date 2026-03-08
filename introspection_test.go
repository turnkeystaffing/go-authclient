package authclient

import "testing"

func TestIntrospectionResponse_Scopes(t *testing.T) {
	tests := []struct {
		name     string
		scope    string
		expected []string
	}{
		{"empty scope returns nil", "", nil},
		{"single scope", "openid", []string{"openid"}},
		{"multiple scopes", "openid profile audit:read", []string{"openid", "profile", "audit:read"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &IntrospectionResponse{Scope: tt.scope}
			got := resp.Scopes()
			if len(got) != len(tt.expected) {
				t.Fatalf("Scopes(%q) = %v (len %d), want %v (len %d)", tt.scope, got, len(got), tt.expected, len(tt.expected))
			}
			for i, s := range got {
				if s != tt.expected[i] {
					t.Errorf("Scopes(%q)[%d] = %s, want %s", tt.scope, i, s, tt.expected[i])
				}
			}
		})
	}
}
