package main

import (
	"encoding/json"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// decodeSchema builds the schema, asserts it is valid JSON, and returns it decoded
// into a generic map for structural assertions.
func decodeSchema(t *testing.T) map[string]any {
	t.Helper()
	raw, err := configSchemaJSON()
	if err != nil {
		t.Fatalf("configSchemaJSON: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("emitted schema is not valid JSON: %v\n%s", err, raw)
	}
	return schema
}

// TestConfigSchemaTopLevelShape pins the schema's root shape: the draft 2020-12
// $schema id, an object type, a titled document, a non-empty properties map, and
// additionalProperties:false (the mirror of loadConfigFile's DisallowUnknownFields).
func TestConfigSchemaTopLevelShape(t *testing.T) {
	schema := decodeSchema(t)

	if got := schema["$schema"]; got != "https://json-schema.org/draft/2020-12/schema" {
		t.Errorf("$schema = %v, want the draft 2020-12 id", got)
	}
	if got := schema["type"]; got != "object" {
		t.Errorf("type = %v, want object", got)
	}
	if got, _ := schema["title"].(string); !strings.Contains(strings.ToLower(got), "steward") {
		t.Errorf("title = %q, want it to name Steward's config", got)
	}
	// additionalProperties must be the JSON literal false, not merely absent.
	if got, ok := schema["additionalProperties"].(bool); !ok || got {
		t.Errorf("additionalProperties = %v, want false (mirrors DisallowUnknownFields)", schema["additionalProperties"])
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok || len(props) == 0 {
		t.Fatalf("properties = %v, want a non-empty object", schema["properties"])
	}
}

// TestConfigSchemaCoversEveryFileConfigField is the reflection-fidelity test: it
// proves the schema is generated FROM fileConfig rather than being a second
// hand-maintained list that could silently drift. Every json tag on fileConfig
// must appear as a property key, and the properties must not carry an extra key
// that fileConfig does not define.
func TestConfigSchemaCoversEveryFileConfigField(t *testing.T) {
	schema := decodeSchema(t)
	props, _ := schema["properties"].(map[string]any)

	want := map[string]bool{}
	ft := reflect.TypeOf(fileConfig{})
	for i := 0; i < ft.NumField(); i++ {
		tag := ft.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}
		want[name] = true
		if _, ok := props[name]; !ok {
			t.Errorf("fileConfig field with json tag %q has no schema property", name)
		}
	}
	for name := range props {
		if !want[name] {
			t.Errorf("schema property %q does not correspond to any fileConfig field", name)
		}
	}
}

// TestConfigSchemaFieldTypes pins the Go-type → JSON-Schema-type mapping the
// generator derives by reflection, for a representative field of each kind.
func TestConfigSchemaFieldTypes(t *testing.T) {
	schema := decodeSchema(t)
	props, _ := schema["properties"].(map[string]any)

	cases := map[string]string{
		"addr":                     "string",
		"max_instances":            "integer",
		"disable_inbound_listener": "boolean",
		"uplink_poll_interval":     "string", // a Go duration string, not a JSON-native type
	}
	for name, wantType := range cases {
		prop, ok := props[name].(map[string]any)
		if !ok {
			t.Errorf("property %q missing or not an object", name)
			continue
		}
		if got := prop["type"]; got != wantType {
			t.Errorf("property %q type = %v, want %q", name, got, wantType)
		}
	}
}

// TestConfigSchemaMaxInstancesPositive pins constraint 2: max_instances is an
// integer with exclusiveMinimum:0, the direct mirror of prepareRuntime's
// `maxInstances <= 0` rejection.
func TestConfigSchemaMaxInstancesPositive(t *testing.T) {
	schema := decodeSchema(t)
	props, _ := schema["properties"].(map[string]any)
	prop, ok := props["max_instances"].(map[string]any)
	if !ok {
		t.Fatal("max_instances property missing")
	}
	if got := prop["type"]; got != "integer" {
		t.Errorf("max_instances type = %v, want integer", got)
	}
	// JSON numbers decode to float64; exclusiveMinimum:0 means "strictly > 0".
	if got, ok := prop["exclusiveMinimum"].(float64); !ok || got != 0 {
		t.Errorf("max_instances exclusiveMinimum = %v, want 0", prop["exclusiveMinimum"])
	}
}

// TestConfigSchemaUplinkDependencyIsOneDirectional pins constraint 3 and its most
// important property: the uplink_url ⇒ uplink_credential_file dependency is
// encoded in ONE direction only, matching prepareRuntime (which has no symmetric
// check — a lone credential file is accepted today). A symmetric encoding would be
// a stricter rule than the real validator enforces.
func TestConfigSchemaUplinkDependencyIsOneDirectional(t *testing.T) {
	schema := decodeSchema(t)
	dep, ok := schema["dependentRequired"].(map[string]any)
	if !ok {
		t.Fatalf("dependentRequired missing or not an object: %v", schema["dependentRequired"])
	}

	// The one direction that must exist: uplink_url requires uplink_credential_file.
	reqs, ok := dep["uplink_url"].([]any)
	if !ok {
		t.Fatalf("dependentRequired[uplink_url] missing or not an array: %v", dep["uplink_url"])
	}
	found := false
	for _, r := range reqs {
		if r == "uplink_credential_file" {
			found = true
		}
	}
	if !found {
		t.Errorf("dependentRequired[uplink_url] = %v, want it to contain uplink_credential_file", reqs)
	}

	// The reverse direction must NOT exist: a lone uplink_credential_file is
	// accepted by prepareRuntime, so encoding uplink_credential_file ⇒ uplink_url
	// would drift stricter than the real validator.
	if _, exists := dep["uplink_credential_file"]; exists {
		t.Errorf("dependentRequired must NOT be symmetric: found a uplink_credential_file entry %v; prepareRuntime accepts a lone credential file", dep["uplink_credential_file"])
	}
}

// TestConfigSchemaDisableInboundRequiresUplink pins constraint 4: the
// value-conditional rule (disable_inbound_listener:true ⇒ uplink_url required)
// uses an if/then with const:true, since dependentRequired cannot express a
// value-conditional constraint. It mirrors prepareRuntime's
// `disableInbound && uplinkURL == ""` check, which fires only on the true value.
func TestConfigSchemaDisableInboundRequiresUplink(t *testing.T) {
	schema := decodeSchema(t)

	ifClause, ok := schema["if"].(map[string]any)
	if !ok {
		t.Fatalf("if clause missing or not an object: %v", schema["if"])
	}
	ifProps, _ := ifClause["properties"].(map[string]any)
	dib, _ := ifProps["disable_inbound_listener"].(map[string]any)
	if dib == nil || dib["const"] != true {
		t.Errorf("if.properties.disable_inbound_listener = %v, want {const:true} (value-conditional, not mere key presence)", ifProps["disable_inbound_listener"])
	}
	// The if must also require the key be present, so it fires on true, not on absence.
	if !containsString(ifClause["required"], "disable_inbound_listener") {
		t.Errorf("if.required = %v, want it to include disable_inbound_listener", ifClause["required"])
	}

	thenClause, ok := schema["then"].(map[string]any)
	if !ok {
		t.Fatalf("then clause missing or not an object: %v", schema["then"])
	}
	if !containsString(thenClause["required"], "uplink_url") {
		t.Errorf("then.required = %v, want it to require uplink_url", thenClause["required"])
	}
}

// TestConfigSchemaLogLevelEnum pins constraint 6: log_level is an enum of exactly
// the canonical lowercase set, matching the docs. The disclosed simplification
// (the real parser also accepts other casing/whitespace) lives in the property's
// description.
func TestConfigSchemaLogLevelEnum(t *testing.T) {
	schema := decodeSchema(t)
	props, _ := schema["properties"].(map[string]any)
	prop, ok := props["log_level"].(map[string]any)
	if !ok {
		t.Fatal("log_level property missing")
	}
	enum, ok := prop["enum"].([]any)
	if !ok {
		t.Fatalf("log_level enum missing or not an array: %v", prop["enum"])
	}
	want := []string{"debug", "info", "warn", "error"}
	if len(enum) != len(want) {
		t.Fatalf("log_level enum = %v, want %v", enum, want)
	}
	for i, w := range want {
		if enum[i] != w {
			t.Errorf("log_level enum[%d] = %v, want %q", i, enum[i], w)
		}
	}
	if desc, _ := prop["description"].(string); !strings.Contains(desc, "casing") {
		t.Errorf("log_level description should disclose the casing simplification, got %q", desc)
	}
}

func containsString(v any, want string) bool {
	arr, ok := v.([]any)
	if !ok {
		return false
	}
	for _, e := range arr {
		if e == want {
			return true
		}
	}
	return false
}

// TestSchemaRejectsWhatCheckConfigRejects is the core cross-check the task asks
// for: without a third-party JSON-Schema validator (this repo is stdlib-only), it
// proves the schema and the real -check-config validator enforce the SAME rule for
// two concrete invalid fixtures — (a) the real binary rejects the fixture exactly
// as prepareRuntime does today, and (b) the schema's own structure rejects the
// same fixture. That pins "the schema rejects what -check-config rejects" without
// hand-rolling a general schema evaluator.
func TestSchemaRejectsWhatCheckConfigRejects(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped in -short")
	}
	bin := buildSteward(t)
	schema := decodeSchema(t)
	props, _ := schema["properties"].(map[string]any)

	t.Run("uplink_url without uplink_credential_file (constraint 3)", func(t *testing.T) {
		// (a) The real validator rejects it, naming the missing pairing.
		cfg := writeConfigFile(t, `{"uplink_url":"https://x.example"}`)
		assertFailsWith(t, exec.Command(bin, "-check-config", "-config", cfg), "-uplink-credential-file")

		// (b) The schema's dependentRequired encodes exactly that missing-key rule:
		// uplink_url is present in the fixture, uplink_credential_file is not, and
		// the schema requires the latter whenever the former is present.
		dep, _ := schema["dependentRequired"].(map[string]any)
		if !containsString(dep["uplink_url"], "uplink_credential_file") {
			t.Errorf("schema dependentRequired[uplink_url] does not require uplink_credential_file: %v", dep["uplink_url"])
		}
	})

	t.Run("non-positive max_instances (constraint 2)", func(t *testing.T) {
		// (a) The real validator rejects a zero max_instances.
		cfg := writeConfigFile(t, `{"max_instances":0}`)
		assertFailsWith(t, exec.Command(bin, "-check-config", "-config", cfg), "-max-instances", "positive")

		// (b) The schema types max_instances as an integer with exclusiveMinimum:0,
		// so the same fixture value (0) is out of range — a bare fact about 0
		// relative to the decoded constraint, no general evaluator needed.
		prop, _ := props["max_instances"].(map[string]any)
		min, ok := prop["exclusiveMinimum"].(float64)
		if !ok {
			t.Fatalf("max_instances has no numeric exclusiveMinimum: %v", prop["exclusiveMinimum"])
		}
		const fixtureValue = 0.0
		if !(fixtureValue <= min) {
			t.Errorf("fixture max_instances=%v is not rejected by exclusiveMinimum=%v", fixtureValue, min)
		}
	})
}

// TestSchemaFlagPrintsSchemaAndExitsZero pins the -schema action flag against the
// real binary: it prints valid JSON with the expected top-level shape, exits 0,
// and — like -version — never starts the server or reads a config file.
func TestSchemaFlagPrintsSchemaAndExitsZero(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a binary; skipped in -short")
	}
	bin := buildSteward(t)

	cmd := exec.Command(bin, "-schema")
	cmd.Env = stewardEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("-schema must exit 0, got %v\n%s", err, out)
	}

	var schema map[string]any
	if err := json.Unmarshal(out, &schema); err != nil {
		t.Fatalf("-schema output is not valid JSON: %v\n%s", err, out)
	}
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Errorf("-schema output missing the draft 2020-12 $schema id:\n%s", out)
	}
	if schema["type"] != "object" {
		t.Errorf("-schema output type = %v, want object", schema["type"])
	}
	if props, ok := schema["properties"].(map[string]any); !ok || len(props) == 0 {
		t.Errorf("-schema output has no properties:\n%s", out)
	}
	if schema["additionalProperties"] != false {
		t.Errorf("-schema output additionalProperties = %v, want false", schema["additionalProperties"])
	}
	// It must short-circuit before any listener binds, exactly like -version.
	if strings.Contains(string(out), "steward listening") {
		t.Errorf("-schema must not start the HTTP server:\n%s", out)
	}
}
