package authclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ErrManifestInvalid is a sentinel error for manifest validation failures.
// Use errors.Is(err, ErrManifestInvalid) to check if an error is a manifest validation error.
var ErrManifestInvalid = errors.New("manifest validation failed")

// ManifestValidationError collects all validation issues found in a scope manifest.
// It wraps ErrManifestInvalid for errors.Is() compatibility.
type ManifestValidationError struct {
	Errors []string
}

func (e *ManifestValidationError) Error() string {
	return fmt.Sprintf("manifest validation failed: %s", strings.Join(e.Errors, "; "))
}

func (e *ManifestValidationError) Unwrap() error {
	return ErrManifestInvalid
}

// ScopeManifest declares a service's scopes and templates for discovery by the auth service.
// It is the root type serialized as JSON (for HTTP discovery) or YAML (for file-based manifests).
type ScopeManifest struct {
	ServiceCode string               `json:"service_code" yaml:"service_code"`
	Scopes      []ScopeDefinition    `json:"scopes" yaml:"scopes"`
	Templates   []TemplateDefinition `json:"templates,omitempty" yaml:"templates,omitempty"`
}

// ScopeDefinition declares a single scope within a service manifest.
type ScopeDefinition struct {
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description" yaml:"description"`
	Category    string `json:"category,omitempty" yaml:"category,omitempty"`
}

// TemplateDefinition declares a scope template that groups related scopes for role-based assignment.
// The optional Replaces field references an external template name in the auth service that this
// template supersedes during sync.
type TemplateDefinition struct {
	Name        string   `json:"name" yaml:"name"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Scopes      []string `json:"scopes" yaml:"scopes"`
	Replaces    string   `json:"replaces,omitempty" yaml:"replaces,omitempty"`
}

// maxManifestSize is the maximum size in bytes for a manifest payload (10 MB).
// This prevents denial-of-service via oversized inputs. Follows the same defensive
// pattern as maxResponseBodySize in introspection_client.go and token_provider.go.
const maxManifestSize = 10 << 20 // 10 MB

// maxManifestScopes is the maximum number of scope definitions allowed in a manifest.
const maxManifestScopes = 10000

// maxManifestTemplates is the maximum number of template definitions allowed in a manifest.
const maxManifestTemplates = 1000

// maxTemplateNameLength is the maximum length of a template name.
const maxTemplateNameLength = 255

// maxValidationErrors is the maximum number of validation errors collected before truncation.
const maxValidationErrors = 50

// scopeNamePattern matches valid scope names: 2-3 colon-separated segments of lowercase
// alphanumeric characters, underscores, and wildcards (*). The first segment is the service
// code (validated separately by serviceCodePattern, which excludes wildcards).
// CONTRACT: Must match get-native-auth's scopeNamePattern in
// internal/scopes/validation/scope_validator.go. Divergence causes sync failures.
var scopeNamePattern = regexp.MustCompile(`^[a-z0-9_]+(?::[a-z0-9_*]+){1,2}$`)

var serviceCodePattern = regexp.MustCompile(`^[a-z0-9_]+$`)

func validateServiceCode(code string) error {
	if code == "" {
		return errors.New("service_code is required")
	}
	if !serviceCodePattern.MatchString(code) {
		return fmt.Errorf("service_code %q must contain only lowercase letters, numbers, and underscores", code)
	}
	return nil
}

func validateScopeName(name, serviceCode string) error {
	if name == "" {
		return errors.New("scope name must not be empty")
	}
	if len(name) > 255 {
		return fmt.Errorf("scope name exceeds maximum length of 255 characters (%d)", len(name))
	}
	if name != strings.ToLower(name) {
		return fmt.Errorf("scope name %q must be lowercase", name)
	}
	if !scopeNamePattern.MatchString(name) {
		return fmt.Errorf("scope name %q must match pattern service:resource:action (2-3 colon-separated lowercase segments)", name)
	}

	segments := strings.Split(name, ":")
	if segments[0] != serviceCode {
		return fmt.Errorf("scope name %q must start with service code %q", name, serviceCode)
	}

	// Reject embedded wildcards: wildcard must be the entire segment (e.g., "app*rove" -> error).
	for _, seg := range segments[1:] {
		if seg != "*" && strings.Contains(seg, "*") {
			return fmt.Errorf("scope name %q contains embedded wildcard; wildcard (*) must be the entire segment", name)
		}
	}

	// Reject mid-segment wildcards: wildcard only allowed as final segment (e.g., "bgc:*:read" -> error).
	// Start at index 1 to skip service code (already validated by serviceCodePattern, which excludes *).
	for _, seg := range segments[1 : len(segments)-1] {
		if seg == "*" {
			return fmt.Errorf("scope name %q has wildcard in non-final segment; wildcard (*) is only allowed as the final segment", name)
		}
	}

	return nil
}

// ValidateManifest validates a ScopeManifest, collecting all validation errors.
// Returns a *ManifestValidationError (wrapping ErrManifestInvalid) if any issues are found.
func ValidateManifest(m *ScopeManifest) error {
	if m == nil {
		return &ManifestValidationError{Errors: []string{"manifest must not be nil"}}
	}

	var errs []string

	serviceCodeValid := true
	if err := validateServiceCode(m.ServiceCode); err != nil {
		errs = append(errs, err.Error())
		serviceCodeValid = false
	}

	scopesDefined := len(m.Scopes) > 0
	if !scopesDefined {
		errs = append(errs, "at least one scope is required")
	}
	if len(m.Scopes) > maxManifestScopes {
		errs = append(errs, fmt.Sprintf("too many scopes: %d (max %d)", len(m.Scopes), maxManifestScopes))
		return &ManifestValidationError{Errors: errs}
	}
	if len(m.Templates) > maxManifestTemplates {
		errs = append(errs, fmt.Sprintf("too many templates: %d (max %d)", len(m.Templates), maxManifestTemplates))
		return &ManifestValidationError{Errors: errs}
	}

	scopeSet := make(map[string]bool, len(m.Scopes))
	for _, s := range m.Scopes {
		if serviceCodeValid {
			if err := validateScopeName(s.Name, m.ServiceCode); err != nil {
				errs = append(errs, err.Error())
			}
		}
		if s.Name != "" && scopeSet[s.Name] {
			errs = append(errs, fmt.Sprintf("duplicate scope name %q", s.Name))
		}
		if s.Name != "" {
			scopeSet[s.Name] = true
		}
	}

	templateNames := make(map[string]bool, len(m.Templates))
	for i, tmpl := range m.Templates {
		templateLabel := tmpl.Name
		if templateLabel == "" {
			templateLabel = fmt.Sprintf("(template at index %d)", i)
			errs = append(errs, fmt.Sprintf("template at index %d: name must not be empty", i))
		} else if len(tmpl.Name) > maxTemplateNameLength {
			errs = append(errs, fmt.Sprintf("template name exceeds maximum length of %d characters (%d)", maxTemplateNameLength, len(tmpl.Name)))
		} else if templateNames[tmpl.Name] {
			errs = append(errs, fmt.Sprintf("duplicate template name %q", tmpl.Name))
		}
		if tmpl.Name != "" {
			templateNames[tmpl.Name] = true
		}

		if len(tmpl.Scopes) == 0 {
			errs = append(errs, fmt.Sprintf("template %s must have at least one scope", templateLabel))
		}

		scopeRefSet := make(map[string]bool, len(tmpl.Scopes))
		for _, ref := range tmpl.Scopes {
			if scopesDefined && !scopeSet[ref] {
				errs = append(errs, fmt.Sprintf("template %s references undefined scope %q", templateLabel, ref))
			}
			if scopeRefSet[ref] {
				errs = append(errs, fmt.Sprintf("template %s has duplicate scope reference %q", templateLabel, ref))
			}
			scopeRefSet[ref] = true
		}
	}

	for i, tmpl := range m.Templates {
		if tmpl.Replaces != "" && templateNames[tmpl.Replaces] {
			label := tmpl.Name
			if label == "" {
				label = fmt.Sprintf("(template at index %d)", i)
			}
			errs = append(errs, fmt.Sprintf("template %s replaces %q which exists in the same manifest; replaces must reference an external template", label, tmpl.Replaces))
		}
	}

	if len(errs) > maxValidationErrors {
		remaining := len(errs) - maxValidationErrors
		errs = append(errs[:maxValidationErrors], fmt.Sprintf("... and %d more errors", remaining))
	}
	if len(errs) > 0 {
		return &ManifestValidationError{Errors: errs}
	}
	return nil
}

// LoadManifestFromFile reads, parses, and validates a scope manifest from a file.
// The format is auto-detected by extension: .yaml/.yml for YAML, .json for JSON.
//
// Security: The path parameter is used as-is. Callers must sanitize user-supplied
// paths to prevent directory traversal. Error messages may contain the file path.
func LoadManifestFromFile(path string) (*ScopeManifest, error) {
	ext := strings.ToLower(filepath.Ext(path))
	var format string
	switch ext {
	case ".yaml", ".yml":
		format = "yaml"
	case ".json":
		format = "json"
	default:
		return nil, fmt.Errorf("unsupported file extension %q; use .yaml, .yml, or .json", ext)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening manifest file: %w", err)
	}
	defer f.Close()

	return LoadManifestFromReader(f, format)
}

// LoadManifestFromReader parses and validates a scope manifest from a reader.
// Format must be "yaml" or "json". Input is limited to maxManifestSize bytes;
// callers providing user-controlled readers should also apply their own size limits.
func LoadManifestFromReader(r io.Reader, format string) (*ScopeManifest, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxManifestSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}
	if len(data) > maxManifestSize {
		return nil, fmt.Errorf("manifest exceeds maximum size of %d bytes", maxManifestSize)
	}

	var m ScopeManifest
	switch strings.ToLower(format) {
	case "yaml":
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&m); err != nil {
			return nil, fmt.Errorf("parsing YAML manifest: %w", err)
		}
	case "json":
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&m); err != nil {
			return nil, fmt.Errorf("parsing JSON manifest: %w", err)
		}
	case "":
		return nil, errors.New("format is required; use \"yaml\" or \"json\"")
	default:
		return nil, fmt.Errorf("unsupported format %q; use \"yaml\" or \"json\"", format)
	}

	if err := ValidateManifest(&m); err != nil {
		return nil, err
	}

	return &m, nil
}
