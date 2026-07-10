package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// configFieldDescriptions holds the human-readable JSON Schema `description` for
// each -config file key, keyed by the same snake_case JSON tag configSchema reads
// off fileConfig. Descriptions are the one part of the schema reflection cannot
// derive — Go exposes a struct field's type at runtime but not its doc comment —
// so they live here, colocated with the generator and tied to fileConfig by that
// shared key. Everything mechanical (the property names, their types, which keys
// are required) is derived from fileConfig itself so it cannot drift; only this
// prose is maintained by hand. A field present in fileConfig but absent here still
// appears in the schema (typed, just undescribed), so a forgotten entry degrades
// gracefully rather than dropping the property.
var configFieldDescriptions = map[string]string{
	"addr":                     "host:port the inbound HTTP listener binds, e.g. \"127.0.0.1:8080\" or \":8080\". Only validated (and bound) when the inbound listener is enabled.",
	"max_instances":            "maximum number of tracked instances before Provision returns 503; must be a positive integer. A live SIGHUP re-read of this file hot-reloads this value (only).",
	"state_file":               "path to a JSON file for durable instance state; omit for in-memory only (state is lost on restart).",
	"uplink_url":               "control-plane base URL for the outbound uplink (an absolute http(s) URL); omit to disable the uplink (inbound REST only). When set, uplink_credential_file is required.",
	"uplink_credential_file":   "path to the node's uplink credential JSON; required when uplink_url is set.",
	"uplink_poll_interval":     "base cadence for uplink polling as a Go duration string (time.ParseDuration format, e.g. \"30s\", \"1m30s\"); jitter is applied on top and it is clamped to a 5-minute ceiling.",
	"disable_inbound_listener": "when true, bind no inbound HTTP listener at all; requires uplink_url so the node is still reachable via the outbound uplink.",
	"log_level":                "log verbosity: one of debug, info, warn, error. The real validator additionally accepts other letter casing and surrounding whitespace; this schema documents the canonical lowercase form.",
}

// configSchemaJSON returns the pretty-printed JSON Schema (draft 2020-12) for the
// -config file, generated from the fileConfig struct. It is what the -schema
// action flag prints. It returns an error only if configSchema cannot map a
// fileConfig field's Go type or json.MarshalIndent fails — both dev-time
// invariants for today's fixed struct, surfaced loudly rather than emitting a
// silently-incomplete schema.
func configSchemaJSON() ([]byte, error) {
	schema, err := configSchema()
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(schema, "", "  ")
}

// configSchema builds the JSON Schema (draft 2020-12) document describing a valid
// -config file. The property list, each property's type, and required-ness are
// derived by reflecting over fileConfig, so a field added to that struct is
// picked up here automatically without a hand-edit — the reflection-fidelity test
// pins that promise. Only the free-text descriptions (which reflection cannot
// reach) and the value constraints (which encode prepareRuntime's validation
// rules) are spelled out below.
//
// The encoded constraints mirror the real startup validators exactly — no
// stricter, no looser — so a config the schema accepts is one -check-config would
// accept and vice versa:
//
//   - additionalProperties:false mirrors loadConfigFile's DisallowUnknownFields:
//     an unknown key is a fail-closed startup error today, so the schema rejects
//     it too.
//   - max_instances exclusiveMinimum:0 mirrors prepareRuntime's `maxInstances <= 0`
//     rejection (positive integer required).
//   - dependentRequired{uplink_url: [uplink_credential_file]} mirrors the
//     ONE-DIRECTIONAL `uplinkURL != "" && uplinkCredentialFile == ""` check.
//     prepareRuntime has NO symmetric check (a credential file with no uplink_url
//     is accepted today, the file simply unused), so this is encoded in one
//     direction only — encoding the reverse would be a stricter rule than the real
//     validator enforces.
//   - the if/then requiring uplink_url when disable_inbound_listener is true
//     mirrors the `disableInbound && uplinkURL == ""` check. It is value-
//     conditional (only `true` requires it; `false` does not), which
//     dependentRequired cannot express (it fires on key presence regardless of
//     value), so an if/then with `const: true` is used instead. It composes with
//     the dependentRequired above via the schema root's implicit AND, so
//     disable_inbound_listener:true transitively also requires
//     uplink_credential_file without hand-encoding that step.
//
// log_level uses a lowercase enum as the documented canonical form even though
// the real parser also accepts other casing and surrounding whitespace: JSON
// Schema's pattern keyword (ECMA-262) has no portable inline case-insensitivity
// flag, so a fully-faithful encoding is not cleanly expressible; the lowercase
// enum matches every example in the docs, and log_level's description discloses
// the simplification. uplink_poll_interval is typed string (a Go duration string,
// not a JSON-native type); a regex-perfect duration pattern is out of scope and
// its description names the format instead.
func configSchema() (map[string]any, error) {
	properties := map[string]any{}

	t := reflect.TypeOf(fileConfig{})
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		name := jsonTagName(field)
		if name == "" {
			continue // no json tag (or json:"-"): not a config key.
		}

		schemaType, err := jsonSchemaType(field.Type)
		if err != nil {
			return nil, fmt.Errorf("config field %s (json %q): %w", field.Name, name, err)
		}
		prop := map[string]any{"type": schemaType}
		if desc, ok := configFieldDescriptions[name]; ok {
			prop["description"] = desc
		}

		// Per-key value constraints that mirror the real startup validators.
		switch name {
		case "max_instances":
			// prepareRuntime rejects maxInstances <= 0; exclusiveMinimum:0 is the
			// direct schema equivalent (any value strictly greater than 0).
			prop["exclusiveMinimum"] = 0
		case "log_level":
			prop["enum"] = []string{"debug", "info", "warn", "error"}
		}

		properties[name] = prop
	}

	return map[string]any{
		"$schema":              "https://json-schema.org/draft/2020-12/schema",
		"title":                "Steward config file",
		"type":                 "object",
		"additionalProperties": false,
		"properties":           properties,
		// One-directional only: uplink_url present ⇒ uplink_credential_file
		// required. There is deliberately NO uplink_credential_file ⇒ uplink_url
		// entry, matching prepareRuntime, which accepts a lone credential file.
		"dependentRequired": map[string]any{
			"uplink_url": []string{"uplink_credential_file"},
		},
		// Value-conditional: disable_inbound_listener:true ⇒ uplink_url required.
		"if": map[string]any{
			"properties": map[string]any{
				"disable_inbound_listener": map[string]any{"const": true},
			},
			"required": []string{"disable_inbound_listener"},
		},
		"then": map[string]any{
			"required": []string{"uplink_url"},
		},
	}, nil
}

// jsonTagName returns the JSON property name for a struct field: the part of its
// `json` tag before any options comma. It returns "" for a field with no json tag
// or an explicit json:"-", which are not config keys.
func jsonTagName(field reflect.StructField) string {
	tag, ok := field.Tag.Lookup("json")
	if !ok {
		return ""
	}
	name, _, _ := strings.Cut(tag, ",")
	if name == "-" {
		return ""
	}
	return name
}

// jsonSchemaType maps a fileConfig field's Go type to its JSON Schema `type`.
// Every fileConfig field is a pointer (so an absent key is distinguishable from a
// present zero value), so the pointer is unwrapped first. It errors on any Go type
// with no mapping, so a future fileConfig field of an unexpected type fails the
// -schema command loudly rather than producing a schema that silently omits or
// mistypes it.
func jsonSchemaType(t reflect.Type) (string, error) {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.String:
		return "string", nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return "integer", nil
	case reflect.Bool:
		return "boolean", nil
	default:
		return "", fmt.Errorf("no JSON Schema type mapping for Go type %s", t)
	}
}
