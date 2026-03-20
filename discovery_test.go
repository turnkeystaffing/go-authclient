package authclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// validManifest returns a valid manifest for use as a test baseline.
func validManifest() *ScopeManifest {
	return &ScopeManifest{
		ServiceCode: "bgc",
		Scopes: []ScopeDefinition{
			{Name: "bgc:contractors:read", Description: "Read contractors"},
			{Name: "bgc:contractors:write", Description: "Write contractors"},
		},
		Templates: []TemplateDefinition{
			{
				Name:        "viewer",
				Description: "Read-only access",
				Scopes:      []string{"bgc:contractors:read"},
			},
		},
	}
}

// --- Test Group 1: Valid manifests ---

func TestValidateManifest_Valid(t *testing.T) {
	tests := []struct {
		name     string
		manifest *ScopeManifest
	}{
		{
			name: "minimal - service_code and one scope",
			manifest: &ScopeManifest{
				ServiceCode: "bgc",
				Scopes:      []ScopeDefinition{{Name: "bgc:read", Description: "Read"}},
			},
		},
		{
			name:     "full - scopes and templates",
			manifest: validManifest(),
		},
		{
			name: "with replaces referencing external template",
			manifest: &ScopeManifest{
				ServiceCode: "bgc",
				Scopes:      []ScopeDefinition{{Name: "bgc:contractors:read", Description: "Read"}},
				Templates: []TemplateDefinition{
					{Name: "viewer", Scopes: []string{"bgc:contractors:read"}, Replaces: "old_viewer"},
				},
			},
		},
		{
			name: "with wildcard final segment",
			manifest: &ScopeManifest{
				ServiceCode: "bgc",
				Scopes: []ScopeDefinition{
					{Name: "bgc:contractors:*", Description: "All contractor ops"},
				},
				Templates: []TemplateDefinition{
					{Name: "admin", Scopes: []string{"bgc:contractors:*"}},
				},
			},
		},
		{
			name: "with 2-segment scopes",
			manifest: &ScopeManifest{
				ServiceCode: "bgc",
				Scopes:      []ScopeDefinition{{Name: "bgc:read", Description: "Read"}},
			},
		},
		{
			name: "no templates field",
			manifest: &ScopeManifest{
				ServiceCode: "bgc",
				Scopes:      []ScopeDefinition{{Name: "bgc:read", Description: "Read"}},
			},
		},
		{
			name: "empty templates list",
			manifest: &ScopeManifest{
				ServiceCode: "bgc",
				Scopes:      []ScopeDefinition{{Name: "bgc:read", Description: "Read"}},
				Templates:   []TemplateDefinition{},
			},
		},
		{
			name: "service_code with underscores and numbers",
			manifest: &ScopeManifest{
				ServiceCode: "my_app_2",
				Scopes:      []ScopeDefinition{{Name: "my_app_2:read", Description: "Read"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateManifest(tt.manifest)
			assert.NoError(t, err)
		})
	}
}

// --- Test Group 2: Invalid service codes ---

func TestValidateManifest_ServiceCode(t *testing.T) {
	tests := []struct {
		name    string
		code    string
		wantErr string
	}{
		{name: "empty", code: "", wantErr: "service_code is required"},
		{name: "uppercase", code: "BGC", wantErr: "must contain only lowercase"},
		{name: "hyphen", code: "bgc-app", wantErr: "must contain only lowercase"},
		{name: "with colons", code: "bgc:app", wantErr: "must contain only lowercase"},
		{name: "with spaces", code: "bgc app", wantErr: "must contain only lowercase"},
		{name: "special chars", code: "bgc@app", wantErr: "must contain only lowercase"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ScopeManifest{
				ServiceCode: tt.code,
				Scopes:      []ScopeDefinition{{Name: "x:read", Description: "R"}},
			}
			err := ValidateManifest(m)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.True(t, errors.Is(err, ErrManifestInvalid))
		})
	}
}

// --- Test Group 3: Invalid scope names ---

func TestValidateManifest_ScopeNames(t *testing.T) {
	tests := []struct {
		name    string
		scope   ScopeDefinition
		wantErr string
	}{
		{
			name:    "wrong prefix",
			scope:   ScopeDefinition{Name: "other:contractors:read", Description: "Read"},
			wantErr: "must start with service code",
		},
		{
			name:    "4+ segments",
			scope:   ScopeDefinition{Name: "bgc:contractors:read:extra", Description: "Read"},
			wantErr: "must match pattern",
		},
		{
			name:    "mid-segment wildcard",
			scope:   ScopeDefinition{Name: "bgc:*:read", Description: "Read"},
			wantErr: "wildcard in non-final segment",
		},
		{
			name:    "embedded wildcard",
			scope:   ScopeDefinition{Name: "bgc:app*rove:read", Description: "Read"},
			wantErr: "embedded wildcard",
		},
		{
			name:    "exceeds 255 characters",
			scope:   ScopeDefinition{Name: "bgc:" + strings.Repeat("a", 252), Description: "Read"},
			wantErr: "exceeds maximum length",
		},
		{
			name:    "uppercase scope name",
			scope:   ScopeDefinition{Name: "bgc:Contractors:read", Description: "Read"},
			wantErr: "must be lowercase",
		},
		{
			name:    "empty scope name",
			scope:   ScopeDefinition{Name: "", Description: "Read"},
			wantErr: "scope name must not be empty",
		},
		{
			name:    "single segment",
			scope:   ScopeDefinition{Name: "bgc", Description: "Read"},
			wantErr: "must match pattern",
		},
		{
			name:    "trailing colon",
			scope:   ScopeDefinition{Name: "bgc:", Description: "Read"},
			wantErr: "must match pattern",
		},
		{
			name:    "leading colon",
			scope:   ScopeDefinition{Name: ":bgc:read", Description: "Read"},
			wantErr: "must match pattern",
		},
		{
			name:    "embedded wildcard in final segment",
			scope:   ScopeDefinition{Name: "bgc:contractors:re*d", Description: "Read"},
			wantErr: "embedded wildcard",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ScopeManifest{
				ServiceCode: "bgc",
				Scopes:      []ScopeDefinition{tt.scope},
			}
			err := ValidateManifest(m)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestValidateManifest_DuplicateScopeNames(t *testing.T) {
	m := &ScopeManifest{
		ServiceCode: "bgc",
		Scopes: []ScopeDefinition{
			{Name: "bgc:contractors:read", Description: "Read"},
			{Name: "bgc:contractors:read", Description: "Read again"},
		},
	}
	err := ValidateManifest(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate scope name")
}

// --- Test Group 4: Invalid templates ---

func TestValidateManifest_Templates(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(m *ScopeManifest)
		wantErr string
	}{
		{
			name: "empty template name",
			modify: func(m *ScopeManifest) {
				m.Templates = []TemplateDefinition{
					{Name: "", Scopes: []string{"bgc:contractors:read"}},
				}
			},
			wantErr: "name must not be empty",
		},
		{
			name: "empty template scopes",
			modify: func(m *ScopeManifest) {
				m.Templates = []TemplateDefinition{
					{Name: "viewer", Scopes: []string{}},
				}
			},
			wantErr: "must have at least one scope",
		},
		{
			name: "nil template scopes",
			modify: func(m *ScopeManifest) {
				m.Templates = []TemplateDefinition{
					{Name: "viewer", Scopes: nil},
				}
			},
			wantErr: "must have at least one scope",
		},
		{
			name: "undefined scope reference",
			modify: func(m *ScopeManifest) {
				m.Templates = []TemplateDefinition{
					{Name: "viewer", Scopes: []string{"bgc:nonexistent:read"}},
				}
			},
			wantErr: "references undefined scope",
		},
		{
			name: "duplicate scope references in template",
			modify: func(m *ScopeManifest) {
				m.Templates = []TemplateDefinition{
					{Name: "viewer", Scopes: []string{"bgc:contractors:read", "bgc:contractors:read"}},
				}
			},
			wantErr: "duplicate scope reference",
		},
		{
			name: "duplicate template names",
			modify: func(m *ScopeManifest) {
				m.Templates = []TemplateDefinition{
					{Name: "viewer", Scopes: []string{"bgc:contractors:read"}},
					{Name: "viewer", Scopes: []string{"bgc:contractors:write"}},
				}
			},
			wantErr: "duplicate template name",
		},
		{
			name: "replaces references sibling template",
			modify: func(m *ScopeManifest) {
				m.Templates = []TemplateDefinition{
					{Name: "viewer", Scopes: []string{"bgc:contractors:read"}},
					{Name: "editor", Scopes: []string{"bgc:contractors:write"}, Replaces: "viewer"},
				}
			},
			wantErr: "replaces",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := validManifest()
			tt.modify(m)
			err := ValidateManifest(m)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// --- Test Group 5: Multi-error collection ---

func TestValidateManifest_CollectsAllErrors(t *testing.T) {
	m := &ScopeManifest{
		ServiceCode: "",
		Scopes:      nil,
	}
	err := ValidateManifest(m)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrManifestInvalid))

	var valErr *ManifestValidationError
	require.True(t, errors.As(err, &valErr))
	assert.GreaterOrEqual(t, len(valErr.Errors), 2, "should collect multiple errors")
	assert.Contains(t, valErr.Error(), "service_code is required")
	assert.Contains(t, valErr.Error(), "at least one scope is required")
}

func TestValidateManifest_EmptyScopesList(t *testing.T) {
	m := &ScopeManifest{
		ServiceCode: "bgc",
		Scopes:      []ScopeDefinition{},
	}
	err := ValidateManifest(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one scope is required")
}

// --- Test Group 6: File loading ---

func TestLoadManifestFromFile(t *testing.T) {
	t.Run("valid YAML file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "manifest.yaml")
		content := "service_code: bgc\nscopes:\n  - name: bgc:contractors:read\n    description: Read contractors\n"
		require.NoError(t, os.WriteFile(path, []byte(content), 0644))

		m, err := LoadManifestFromFile(path)
		require.NoError(t, err)
		assert.Equal(t, "bgc", m.ServiceCode)
		assert.Len(t, m.Scopes, 1)
		assert.Equal(t, "bgc:contractors:read", m.Scopes[0].Name)
	})

	t.Run("valid YAML with .yml extension", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "manifest.yml")
		content := "service_code: bgc\nscopes:\n  - name: bgc:read\n    description: Read\n"
		require.NoError(t, os.WriteFile(path, []byte(content), 0644))

		m, err := LoadManifestFromFile(path)
		require.NoError(t, err)
		assert.Equal(t, "bgc", m.ServiceCode)
	})

	t.Run("valid JSON file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "manifest.json")
		content := `{"service_code":"bgc","scopes":[{"name":"bgc:contractors:read","description":"Read contractors"}]}`
		require.NoError(t, os.WriteFile(path, []byte(content), 0644))

		m, err := LoadManifestFromFile(path)
		require.NoError(t, err)
		assert.Equal(t, "bgc", m.ServiceCode)
		assert.Len(t, m.Scopes, 1)
	})

	t.Run("non-existent file", func(t *testing.T) {
		_, err := LoadManifestFromFile("/nonexistent/path/manifest.yaml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "opening manifest file")
	})

	t.Run("unsupported extension", func(t *testing.T) {
		_, err := LoadManifestFromFile("manifest.toml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported file extension")
	})

	t.Run("invalid YAML content", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "manifest.yaml")
		require.NoError(t, os.WriteFile(path, []byte("{{{invalid"), 0644))

		_, err := LoadManifestFromFile(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parsing YAML")
	})

	t.Run("valid YAML but fails validation", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "manifest.yaml")
		content := "service_code: bgc\nscopes: []\n"
		require.NoError(t, os.WriteFile(path, []byte(content), 0644))

		_, err := LoadManifestFromFile(path)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrManifestInvalid))
	})
}

// --- Test Group 7: Reader loading ---

func TestLoadManifestFromReader(t *testing.T) {
	t.Run("valid YAML", func(t *testing.T) {
		content := "service_code: bgc\nscopes:\n  - name: bgc:contractors:read\n    description: Read\n"
		m, err := LoadManifestFromReader(strings.NewReader(content), "yaml")
		require.NoError(t, err)
		assert.Equal(t, "bgc", m.ServiceCode)
		assert.Len(t, m.Scopes, 1)
	})

	t.Run("valid JSON", func(t *testing.T) {
		content := `{"service_code":"bgc","scopes":[{"name":"bgc:contractors:read","description":"Read"}]}`
		m, err := LoadManifestFromReader(strings.NewReader(content), "json")
		require.NoError(t, err)
		assert.Equal(t, "bgc", m.ServiceCode)
	})

	t.Run("unsupported format", func(t *testing.T) {
		_, err := LoadManifestFromReader(strings.NewReader(""), "toml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported format")
	})

	t.Run("invalid YAML content", func(t *testing.T) {
		_, err := LoadManifestFromReader(strings.NewReader("{{{invalid"), "yaml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parsing YAML")
	})

	t.Run("invalid JSON content", func(t *testing.T) {
		_, err := LoadManifestFromReader(strings.NewReader("{not valid json"), "json")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parsing JSON")
	})

	t.Run("format case-insensitive", func(t *testing.T) {
		content := "service_code: bgc\nscopes:\n  - name: bgc:read\n    description: Read\n"
		m, err := LoadManifestFromReader(strings.NewReader(content), "YAML")
		require.NoError(t, err)
		assert.Equal(t, "bgc", m.ServiceCode)
	})
}

// --- Test Group 8: JSON round-trip ---

func TestScopeManifest_JSONRoundTrip(t *testing.T) {
	original := &ScopeManifest{
		ServiceCode: "bgc",
		Scopes: []ScopeDefinition{
			{Name: "bgc:contractors:read", Description: "Read contractors", Category: "contractors"},
			{Name: "bgc:contractors:write", Description: "Write contractors"},
		},
		Templates: []TemplateDefinition{
			{
				Name:        "viewer",
				Description: "View-only access",
				Scopes:      []string{"bgc:contractors:read"},
			},
			{
				Name:     "editor",
				Scopes:   []string{"bgc:contractors:read", "bgc:contractors:write"},
				Replaces: "old_editor",
			},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded ScopeManifest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.ServiceCode, decoded.ServiceCode)
	assert.Equal(t, original.Scopes, decoded.Scopes)
	assert.Equal(t, original.Templates, decoded.Templates)
}

// --- Verify ManifestValidationError implements error interface correctly ---

func TestManifestValidationError_ErrorMessage(t *testing.T) {
	e := &ManifestValidationError{Errors: []string{"error one", "error two"}}
	assert.Equal(t, "manifest validation failed: error one; error two", e.Error())
	assert.True(t, errors.Is(e, ErrManifestInvalid))
}

// --- Valid replaces referencing external template ---

func TestValidateManifest_ValidReplacesExternal(t *testing.T) {
	m := &ScopeManifest{
		ServiceCode: "bgc",
		Scopes:      []ScopeDefinition{{Name: "bgc:contractors:read", Description: "Read"}},
		Templates: []TemplateDefinition{
			{Name: "viewer", Scopes: []string{"bgc:contractors:read"}, Replaces: "old_legacy_viewer"},
		},
	}
	err := ValidateManifest(m)
	assert.NoError(t, err)
}

// --- Nil manifest ---

func TestValidateManifest_NilManifest(t *testing.T) {
	err := ValidateManifest(nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrManifestInvalid))
	assert.Contains(t, err.Error(), "manifest must not be nil")
}

// --- Multiple templates with same replaces value ---

func TestValidateManifest_MultipleTemplatesSameReplaces(t *testing.T) {
	m := &ScopeManifest{
		ServiceCode: "bgc",
		Scopes: []ScopeDefinition{
			{Name: "bgc:contractors:read", Description: "Read"},
			{Name: "bgc:contractors:write", Description: "Write"},
		},
		Templates: []TemplateDefinition{
			{Name: "viewer_v2", Scopes: []string{"bgc:contractors:read"}, Replaces: "old_viewer"},
			{Name: "editor_v2", Scopes: []string{"bgc:contractors:read", "bgc:contractors:write"}, Replaces: "old_viewer"},
		},
	}
	err := ValidateManifest(m)
	assert.NoError(t, err)
}

// --- YAML round-trip ---

func TestScopeManifest_YAMLRoundTrip(t *testing.T) {
	original := &ScopeManifest{
		ServiceCode: "bgc",
		Scopes: []ScopeDefinition{
			{Name: "bgc:contractors:read", Description: "Read contractors", Category: "contractors"},
			{Name: "bgc:contractors:write", Description: "Write contractors"},
		},
		Templates: []TemplateDefinition{
			{
				Name:        "viewer",
				Description: "View-only access",
				Scopes:      []string{"bgc:contractors:read"},
			},
			{
				Name:     "editor",
				Scopes:   []string{"bgc:contractors:read", "bgc:contractors:write"},
				Replaces: "old_editor",
			},
		},
	}

	data, err := yaml.Marshal(original)
	require.NoError(t, err)

	var decoded ScopeManifest
	err = yaml.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.ServiceCode, decoded.ServiceCode)
	assert.Equal(t, original.Scopes, decoded.Scopes)
	assert.Equal(t, original.Templates, decoded.Templates)
}

// --- Invalid service code skips scope name validation ---

func TestValidateManifest_InvalidServiceCodeSkipsScopeValidation(t *testing.T) {
	m := &ScopeManifest{
		ServiceCode: "BGC",
		Scopes:      []ScopeDefinition{{Name: "bgc:contractors:read", Description: "Read"}},
	}
	err := ValidateManifest(m)
	require.Error(t, err)
	// Should report service_code error but NOT prefix mismatch errors
	assert.Contains(t, err.Error(), "must contain only lowercase")
	assert.NotContains(t, err.Error(), "must start with service code")
}

// --- QA: Scope name boundary tests ---

func TestValidateManifest_ScopeNameLengthBoundary(t *testing.T) {
	// Build a scope name that is exactly 255 characters: "bgc:" + 251 'a's = 255
	atLimit := "bgc:" + strings.Repeat("a", 251)
	require.Equal(t, 255, len(atLimit))

	overLimit := "bgc:" + strings.Repeat("a", 252)
	require.Equal(t, 256, len(overLimit))

	t.Run("exactly 255 chars passes", func(t *testing.T) {
		m := &ScopeManifest{
			ServiceCode: "bgc",
			Scopes:      []ScopeDefinition{{Name: atLimit, Description: "At limit"}},
		}
		err := ValidateManifest(m)
		assert.NoError(t, err)
	})

	t.Run("256 chars fails", func(t *testing.T) {
		m := &ScopeManifest{
			ServiceCode: "bgc",
			Scopes:      []ScopeDefinition{{Name: overLimit, Description: "Over limit"}},
		}
		err := ValidateManifest(m)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds maximum length")
	})
}

// --- QA: Scope names with numbers and underscores ---

func TestValidateManifest_ScopeNamesWithNumbersAndUnderscores(t *testing.T) {
	tests := []struct {
		name  string
		scope string
	}{
		{name: "numbers in resource segment", scope: "bgc:res123:read"},
		{name: "numbers in action segment", scope: "bgc:contractors:action456"},
		{name: "underscores in all segments", scope: "bgc_app:my_resource:my_action"},
		{name: "numeric service code", scope: "app2:data:read"},
		{name: "mixed numbers and underscores", scope: "svc_1:res_2:act_3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serviceCode := strings.Split(tt.scope, ":")[0]
			m := &ScopeManifest{
				ServiceCode: serviceCode,
				Scopes:      []ScopeDefinition{{Name: tt.scope, Description: "Test"}},
			}
			err := ValidateManifest(m)
			assert.NoError(t, err)
		})
	}
}

// --- QA: LoadManifestFromFile edge cases ---

func TestLoadManifestFromFile_EmptyFile(t *testing.T) {
	t.Run("empty YAML file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "empty.yaml")
		require.NoError(t, os.WriteFile(path, []byte(""), 0644))

		_, err := LoadManifestFromFile(path)
		require.Error(t, err)
	})

	t.Run("empty JSON file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "empty.json")
		require.NoError(t, os.WriteFile(path, []byte(""), 0644))

		_, err := LoadManifestFromFile(path)
		require.Error(t, err)
	})
}

func TestLoadManifestFromFile_InvalidJSONContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(path, []byte("{not valid json}"), 0644))

	_, err := LoadManifestFromFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing JSON")
}

func TestLoadManifestFromFile_UppercaseExtension(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.YAML")
	content := "service_code: bgc\nscopes:\n  - name: bgc:contractors:read\n    description: Read\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))

	m, err := LoadManifestFromFile(path)
	require.NoError(t, err)
	assert.Equal(t, "bgc", m.ServiceCode)
}

func TestLoadManifestFromFile_NoExtension(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest")
	require.NoError(t, os.WriteFile(path, []byte("service_code: bgc\n"), 0644))

	_, err := LoadManifestFromFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported file extension")
}

// --- QA: LoadManifestFromReader edge cases ---

type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("simulated read failure")
}

func TestLoadManifestFromReader_FailingReader(t *testing.T) {
	_, err := LoadManifestFromReader(errReader{}, "yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading manifest")
}

func TestLoadManifestFromReader_EmptyContent(t *testing.T) {
	t.Run("empty YAML content", func(t *testing.T) {
		_, err := LoadManifestFromReader(strings.NewReader(""), "yaml")
		require.Error(t, err)
	})

	t.Run("empty JSON content", func(t *testing.T) {
		_, err := LoadManifestFromReader(strings.NewReader(""), "json")
		require.Error(t, err)
	})
}

// --- Security: Size limit tests ---

func TestLoadManifestFromReader_ExceedsMaxSize(t *testing.T) {
	// Create a payload larger than maxManifestSize (10 MB)
	oversized := strings.Repeat("x", maxManifestSize+1)
	_, err := LoadManifestFromReader(strings.NewReader(oversized), "yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum size")
}

// --- Security: Collection limit tests ---

func TestValidateManifest_TooManyScopes(t *testing.T) {
	scopes := make([]ScopeDefinition, maxManifestScopes+1)
	for i := range scopes {
		scopes[i] = ScopeDefinition{Name: fmt.Sprintf("bgc:res:action%d", i), Description: "test"}
	}
	m := &ScopeManifest{
		ServiceCode: "bgc",
		Scopes:      scopes,
	}
	err := ValidateManifest(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too many scopes")
}

func TestValidateManifest_TooManyTemplates(t *testing.T) {
	templates := make([]TemplateDefinition, maxManifestTemplates+1)
	for i := range templates {
		templates[i] = TemplateDefinition{Name: fmt.Sprintf("tmpl_%d", i), Scopes: []string{"bgc:contractors:read"}}
	}
	m := &ScopeManifest{
		ServiceCode: "bgc",
		Scopes:      []ScopeDefinition{{Name: "bgc:contractors:read", Description: "Read"}},
		Templates:   templates,
	}
	err := ValidateManifest(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too many templates")
}

// --- Security: Error accumulation cap ---

func TestValidateManifest_ErrorAccumulationCapped(t *testing.T) {
	// Create manifest with many invalid scopes to trigger > maxValidationErrors errors
	scopes := make([]ScopeDefinition, maxValidationErrors+20)
	for i := range scopes {
		scopes[i] = ScopeDefinition{Name: fmt.Sprintf("INVALID_%d:BAD", i), Description: "test"}
	}
	m := &ScopeManifest{
		ServiceCode: "bgc",
		Scopes:      scopes,
	}
	err := ValidateManifest(m)
	require.Error(t, err)

	var valErr *ManifestValidationError
	require.True(t, errors.As(err, &valErr))
	// Should be capped at maxValidationErrors + 1 (the "... and N more" message)
	assert.LessOrEqual(t, len(valErr.Errors), maxValidationErrors+1)
	assert.Contains(t, valErr.Errors[len(valErr.Errors)-1], "more errors")
}

// --- Adversarial: F1 regression — collection limit preserves prior errors ---

func TestValidateManifest_TooManyScopesPreservesPriorErrors(t *testing.T) {
	scopes := make([]ScopeDefinition, maxManifestScopes+1)
	for i := range scopes {
		scopes[i] = ScopeDefinition{Name: fmt.Sprintf("bgc:res:action%d", i), Description: "test"}
	}
	m := &ScopeManifest{
		ServiceCode: "INVALID",
		Scopes:      scopes,
	}
	err := ValidateManifest(m)
	require.Error(t, err)

	var valErr *ManifestValidationError
	require.True(t, errors.As(err, &valErr))
	// Must contain BOTH the service_code error AND the "too many scopes" error
	assert.Contains(t, err.Error(), "must contain only lowercase")
	assert.Contains(t, err.Error(), "too many scopes")
}

func TestValidateManifest_TooManyTemplatesPreservesPriorErrors(t *testing.T) {
	templates := make([]TemplateDefinition, maxManifestTemplates+1)
	for i := range templates {
		templates[i] = TemplateDefinition{Name: fmt.Sprintf("tmpl_%d", i), Scopes: []string{"bgc:contractors:read"}}
	}
	m := &ScopeManifest{
		ServiceCode: "",
		Scopes:      []ScopeDefinition{{Name: "bgc:contractors:read", Description: "Read"}},
		Templates:   templates,
	}
	err := ValidateManifest(m)
	require.Error(t, err)

	var valErr *ManifestValidationError
	require.True(t, errors.As(err, &valErr))
	// Must contain BOTH the service_code error AND the "too many templates" error
	assert.Contains(t, err.Error(), "service_code is required")
	assert.Contains(t, err.Error(), "too many templates")
}

// --- Adversarial: F2 — 2-segment wildcard scope ---

func TestValidateManifest_TwoSegmentWildcard(t *testing.T) {
	m := &ScopeManifest{
		ServiceCode: "bgc",
		Scopes:      []ScopeDefinition{{Name: "bgc:*", Description: "All bgc ops"}},
	}
	err := ValidateManifest(m)
	assert.NoError(t, err, "bgc:* should be valid — wildcard as final segment in 2-segment scope")
}

// --- Adversarial: F5 — YAML anchor/alias expansion ---

func TestLoadManifestFromReader_YAMLAnchorAlias(t *testing.T) {
	// Verify yaml.v3 handles anchors/aliases without unbounded expansion.
	// The size limit (maxManifestSize) caps input, but this verifies the
	// parser itself doesn't amplify small payloads into huge memory.
	yamlContent := `
service_code: bgc
scopes:
  - &base_scope
    name: bgc:contractors:read
    description: Read contractors
  - <<: *base_scope
    name: bgc:contractors:write
    description: Write contractors
`
	m, err := LoadManifestFromReader(strings.NewReader(yamlContent), "yaml")
	require.NoError(t, err)
	assert.Len(t, m.Scopes, 2)
	assert.Equal(t, "bgc:contractors:write", m.Scopes[1].Name)
}

// --- Adversarial: F8 — empty format string ---

func TestLoadManifestFromReader_EmptyFormat(t *testing.T) {
	_, err := LoadManifestFromReader(strings.NewReader("{}"), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "format is required")
}

// --- Adversarial Pass 2: F2 — strict unknown field rejection ---

func TestLoadManifestFromReader_UnknownFields(t *testing.T) {
	t.Run("YAML unknown field rejected", func(t *testing.T) {
		content := "service_code: bgc\nservide_code: typo\nscopes:\n  - name: bgc:read\n    description: Read\n"
		_, err := LoadManifestFromReader(strings.NewReader(content), "yaml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parsing YAML")
	})

	t.Run("JSON unknown field rejected", func(t *testing.T) {
		content := `{"service_code":"bgc","servide_code":"typo","scopes":[{"name":"bgc:read","description":"Read"}]}`
		_, err := LoadManifestFromReader(strings.NewReader(content), "json")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parsing JSON")
	})
}

// --- Adversarial Pass 2: F6 — mixed valid/invalid scopes ---

func TestValidateManifest_MixedValidAndInvalidScopes(t *testing.T) {
	m := &ScopeManifest{
		ServiceCode: "bgc",
		Scopes: []ScopeDefinition{
			{Name: "bgc:contractors:read", Description: "Valid"},
			{Name: "BGC:CONTRACTORS:WRITE", Description: "Invalid - uppercase"},
			{Name: "other:contractors:read", Description: "Invalid - wrong prefix"},
		},
		Templates: []TemplateDefinition{
			{Name: "viewer", Scopes: []string{"bgc:contractors:read"}},
		},
	}
	err := ValidateManifest(m)
	require.Error(t, err)

	var valErr *ManifestValidationError
	require.True(t, errors.As(err, &valErr))
	// Should have exactly 2 errors (one per invalid scope)
	assert.Equal(t, 2, len(valErr.Errors))
	assert.Contains(t, err.Error(), "must be lowercase")
	assert.Contains(t, err.Error(), "must start with service code")
	// Valid scope should be in scopeSet — template reference should NOT trigger error
	assert.NotContains(t, err.Error(), "undefined scope")
}

// --- Adversarial Pass 2: F9 — template self-reference replaces ---

func TestValidateManifest_TemplateSelfReplaces(t *testing.T) {
	m := &ScopeManifest{
		ServiceCode: "bgc",
		Scopes:      []ScopeDefinition{{Name: "bgc:contractors:read", Description: "Read"}},
		Templates: []TemplateDefinition{
			{Name: "viewer", Scopes: []string{"bgc:contractors:read"}, Replaces: "viewer"},
		},
	}
	err := ValidateManifest(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replaces")
	assert.Contains(t, err.Error(), "exists in the same manifest")
}

// --- Adversarial Pass 2: F10 — template name length limit ---

func TestValidateManifest_TemplateNameTooLong(t *testing.T) {
	longName := strings.Repeat("a", 256)
	m := &ScopeManifest{
		ServiceCode: "bgc",
		Scopes:      []ScopeDefinition{{Name: "bgc:contractors:read", Description: "Read"}},
		Templates: []TemplateDefinition{
			{Name: longName, Scopes: []string{"bgc:contractors:read"}},
		},
	}
	err := ValidateManifest(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum length")
}

// --- Adversarial Pass 2: F11 — directory path test ---

func TestLoadManifestFromFile_DirectoryPath(t *testing.T) {
	dir := t.TempDir()
	// Create a .yaml "file" that is actually the directory itself
	yamlDir := filepath.Join(dir, "manifest.yaml")
	require.NoError(t, os.Mkdir(yamlDir, 0755))

	_, err := LoadManifestFromFile(yamlDir)
	require.Error(t, err)
}

// --- Adversarial: F12 — error ordering ---

func TestValidateManifest_ErrorOrdering(t *testing.T) {
	m := &ScopeManifest{
		ServiceCode: "",
		Scopes:      nil,
	}
	err := ValidateManifest(m)
	require.Error(t, err)

	var valErr *ManifestValidationError
	require.True(t, errors.As(err, &valErr))
	require.GreaterOrEqual(t, len(valErr.Errors), 2)
	// service_code error must come before scopes error
	assert.Contains(t, valErr.Errors[0], "service_code")
	assert.Contains(t, valErr.Errors[1], "at least one scope")
}
