package executor

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const RegistryAuthSchemaV1 = "steward.registry-auth.v1"

type registryAuthV1 struct {
	SchemaVersion string `json:"schema_version"`
	Registry      string `json:"registry"`
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	IdentityToken string `json:"identity_token,omitempty"`
	RegistryToken string `json:"registry_token,omitempty"`
}

// EncodeRegistryAuth validates an owner-only secret rendered by an external
// provider and converts it to Docker's URL-safe X-Registry-Auth value. The
// encoded value is held only in Executor memory and is never exposed to a
// workload, command, receipt, or scheduling observation.
func EncodeRegistryAuth(raw []byte, expectedRegistry string) (string, error) {
	if len(raw) == 0 || len(raw) > 64<<10 || !ValidRegistryAuthority(expectedRegistry) {
		return "", errors.New("registry authentication input is invalid or unbounded")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var auth registryAuthV1
	if err := decoder.Decode(&auth); err != nil {
		return "", errors.New("registry authentication is not strict JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return "", errors.New("registry authentication contains trailing JSON")
	}
	passwordMode := auth.Username != "" || auth.Password != ""
	tokenModes := 0
	if auth.IdentityToken != "" {
		tokenModes++
	}
	if auth.RegistryToken != "" {
		tokenModes++
	}
	if auth.SchemaVersion != RegistryAuthSchemaV1 || auth.Registry != expectedRegistry ||
		passwordMode && (auth.Username == "" || auth.Password == "") ||
		boolInt(passwordMode)+tokenModes != 1 || !boundedRegistrySecret(auth.Username) ||
		!boundedRegistrySecret(auth.Password) || !boundedRegistrySecret(auth.IdentityToken) ||
		!boundedRegistrySecret(auth.RegistryToken) {
		return "", errors.New("registry authentication scope or credential mode is invalid")
	}
	dockerAuth, err := json.Marshal(struct {
		Username      string `json:"username,omitempty"`
		Password      string `json:"password,omitempty"`
		ServerAddress string `json:"serveraddress"`
		IdentityToken string `json:"identitytoken,omitempty"`
		RegistryToken string `json:"registrytoken,omitempty"`
	}{
		Username: auth.Username, Password: auth.Password, ServerAddress: auth.Registry,
		IdentityToken: auth.IdentityToken, RegistryToken: auth.RegistryToken,
	})
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(dockerAuth), nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func boundedRegistrySecret(value string) bool {
	return len(value) <= 16<<10 && utf8.ValidString(value)
}

// ValidRegistryAuthority accepts one canonical host[:port], without a scheme,
// path, user information, query, fragment, or surrounding whitespace.
func ValidRegistryAuthority(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) || strings.TrimSpace(value) != value {
		return false
	}
	parsed, err := url.Parse("https://" + value)
	return err == nil && parsed.Host == value && parsed.Hostname() != "" && parsed.User == nil &&
		parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == ""
}

func imageReferenceUsesRegistry(imageReference, registry string) bool {
	if !imageDigest.MatchString(imageReference) || !ValidRegistryAuthority(registry) {
		return false
	}
	repository, _, found := strings.Cut(imageReference, "@")
	return found && strings.HasPrefix(repository, registry+"/")
}

func validImagePullTimeout(value time.Duration) bool {
	return value >= time.Second && value <= 30*time.Minute
}
