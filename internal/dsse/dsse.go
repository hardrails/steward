// Package dsse implements the small, dependency-free subset of DSSE that
// Steward uses for offline admission artifacts. It deliberately signs exact
// payload bytes: callers must not rely on JSON canonicalization.
package dsse

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

const (
	DefaultMaxEnvelopeBytes = 1 << 20
	MaxPayloadBytes         = 512 << 10
)

var (
	ErrMalformedEnvelope  = errors.New("malformed DSSE envelope")
	ErrNoTrustedSignature = errors.New("DSSE envelope has no trusted valid signature")
	rawMessageType        = reflect.TypeOf(json.RawMessage{})
)

// Envelope is the JSON DSSE envelope. Payload is standard base64 encoded.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// PAE returns the DSSE pre-authentication encoding for payloadType and payload.
func PAE(payloadType string, payload []byte) []byte {
	return []byte("DSSEv1 " + strconv.Itoa(len(payloadType)) + " " + payloadType + " " + strconv.Itoa(len(payload)) + " " + string(payload))
}

func Sign(payloadType string, payload []byte, keyID string, privateKey ed25519.PrivateKey) (Envelope, error) {
	if strings.TrimSpace(payloadType) == "" || len(payloadType) > 256 || strings.ContainsRune(payloadType, '\x00') {
		return Envelope{}, fmt.Errorf("%w: invalid payload type", ErrMalformedEnvelope)
	}
	if strings.TrimSpace(keyID) == "" || len(keyID) > 256 || strings.ContainsRune(keyID, '\x00') {
		return Envelope{}, fmt.Errorf("%w: invalid key ID", ErrMalformedEnvelope)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return Envelope{}, fmt.Errorf("%w: invalid private key", ErrMalformedEnvelope)
	}
	if len(payload) > MaxPayloadBytes {
		return Envelope{}, fmt.Errorf("%w: payload exceeds limit", ErrMalformedEnvelope)
	}
	signature := ed25519.Sign(privateKey, PAE(payloadType, payload))
	return Envelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []Signature{{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(signature)}},
	}, nil
}

// AddSignature returns a detached envelope with one additional Ed25519
// signature over the unchanged DSSE payload. Signatures are sorted by key ID so
// a complete multi-party artifact has one canonical ordering.
func AddSignature(envelope Envelope, keyID string, privateKey ed25519.PrivateKey) (Envelope, error) {
	if err := validateEnvelope(envelope); err != nil {
		return Envelope{}, err
	}
	if strings.TrimSpace(keyID) == "" || len(keyID) > 256 || strings.ContainsRune(keyID, '\x00') ||
		len(privateKey) != ed25519.PrivateKeySize {
		return Envelope{}, fmt.Errorf("%w: invalid signing identity", ErrMalformedEnvelope)
	}
	if len(envelope.Signatures) >= 16 {
		return Envelope{}, fmt.Errorf("%w: invalid signature count", ErrMalformedEnvelope)
	}
	for _, signature := range envelope.Signatures {
		if signature.KeyID == keyID {
			return Envelope{}, fmt.Errorf("%w: duplicate signature key ID", ErrMalformedEnvelope)
		}
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != envelope.Payload {
		return Envelope{}, fmt.Errorf("%w: invalid payload encoding", ErrMalformedEnvelope)
	}
	result := Envelope{
		PayloadType: envelope.PayloadType,
		Payload:     envelope.Payload,
		Signatures:  append([]Signature(nil), envelope.Signatures...),
	}
	signature := ed25519.Sign(privateKey, PAE(result.PayloadType, payload))
	result.Signatures = append(result.Signatures, Signature{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(signature)})
	slices.SortFunc(result.Signatures, func(left, right Signature) int { return strings.Compare(left.KeyID, right.KeyID) })
	return result, nil
}

func Marshal(envelope Envelope) ([]byte, error) {
	if err := validateEnvelope(envelope); err != nil {
		return nil, err
	}
	return json.Marshal(envelope)
}

// Parse strictly decodes a bounded DSSE envelope. It rejects unknown fields,
// duplicate JSON object members (at any nesting level), and duplicate key IDs.
func Parse(raw []byte) (Envelope, error) {
	var envelope Envelope
	if err := DecodeStrictInto(raw, DefaultMaxEnvelopeBytes, &envelope); err != nil {
		return Envelope{}, fmt.Errorf("%w: %v", ErrMalformedEnvelope, err)
	}
	if err := validateEnvelope(envelope); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

// Verify checks an envelope against trusted public keys and returns the exact
// payload bytes plus the key ID that supplied the valid signature.
func Verify(raw []byte, expectedPayloadType string, trusted map[string]ed25519.PublicKey) ([]byte, string, error) {
	envelope, err := Parse(raw)
	if err != nil {
		return nil, "", err
	}
	if envelope.PayloadType != expectedPayloadType {
		return nil, "", fmt.Errorf("%w: expected payload type %q, got %q", ErrMalformedEnvelope, expectedPayloadType, envelope.PayloadType)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || len(payload) > MaxPayloadBytes {
		return nil, "", fmt.Errorf("%w: invalid payload encoding", ErrMalformedEnvelope)
	}
	message := PAE(envelope.PayloadType, payload)
	for _, signature := range envelope.Signatures {
		key, ok := trusted[signature.KeyID]
		if !ok || len(key) != ed25519.PublicKeySize {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(signature.Sig)
		if err == nil && len(sig) == ed25519.SignatureSize && ed25519.Verify(key, message, sig) {
			return payload, signature.KeyID, nil
		}
	}
	return nil, "", ErrNoTrustedSignature
}

// VerifyAll requires every supplied signature to name a distinct trusted key
// and authenticate the exact payload. It returns key IDs in their canonical
// envelope order. Callers enforce their own threshold and authority scope.
func VerifyAll(raw []byte, expectedPayloadType string, trusted map[string]ed25519.PublicKey) ([]byte, []string, error) {
	envelope, err := Parse(raw)
	if err != nil {
		return nil, nil, err
	}
	if envelope.PayloadType != expectedPayloadType {
		return nil, nil, fmt.Errorf("%w: expected payload type %q, got %q", ErrMalformedEnvelope, expectedPayloadType, envelope.PayloadType)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || len(payload) > MaxPayloadBytes || base64.StdEncoding.EncodeToString(payload) != envelope.Payload {
		return nil, nil, fmt.Errorf("%w: invalid payload encoding", ErrMalformedEnvelope)
	}
	message := PAE(envelope.PayloadType, payload)
	keyIDs := make([]string, 0, len(envelope.Signatures))
	for index, signature := range envelope.Signatures {
		if index > 0 && envelope.Signatures[index-1].KeyID >= signature.KeyID {
			return nil, nil, fmt.Errorf("%w: signatures are not in canonical key ID order", ErrMalformedEnvelope)
		}
		key, ok := trusted[signature.KeyID]
		sig, decodeErr := base64.StdEncoding.DecodeString(signature.Sig)
		if !ok || len(key) != ed25519.PublicKeySize || decodeErr != nil || len(sig) != ed25519.SignatureSize ||
			base64.StdEncoding.EncodeToString(sig) != signature.Sig || !ed25519.Verify(key, message, sig) {
			return nil, nil, ErrNoTrustedSignature
		}
		keyIDs = append(keyIDs, signature.KeyID)
	}
	return payload, keyIDs, nil
}

// Digest identifies the exact serialized admission artifact, not its decoded
// meaning. This makes a signed intent unambiguous even if transport whitespace
// or signature ordering changes.
func Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + fmt.Sprintf("%x", sum[:])
}

func validateEnvelope(envelope Envelope) error {
	if strings.TrimSpace(envelope.PayloadType) == "" || len(envelope.PayloadType) > 256 || strings.ContainsRune(envelope.PayloadType, '\x00') {
		return fmt.Errorf("%w: invalid payload type", ErrMalformedEnvelope)
	}
	if len(envelope.Payload) == 0 || len(envelope.Payload) > base64.StdEncoding.EncodedLen(MaxPayloadBytes) {
		return fmt.Errorf("%w: invalid payload length", ErrMalformedEnvelope)
	}
	if len(envelope.Signatures) == 0 || len(envelope.Signatures) > 16 {
		return fmt.Errorf("%w: invalid signature count", ErrMalformedEnvelope)
	}
	seen := make(map[string]struct{}, len(envelope.Signatures))
	for _, signature := range envelope.Signatures {
		if strings.TrimSpace(signature.KeyID) == "" || len(signature.KeyID) > 256 || strings.ContainsRune(signature.KeyID, '\x00') {
			return fmt.Errorf("%w: invalid signature key ID", ErrMalformedEnvelope)
		}
		if _, ok := seen[signature.KeyID]; ok {
			return fmt.Errorf("%w: duplicate signature key ID", ErrMalformedEnvelope)
		}
		seen[signature.KeyID] = struct{}{}
		if len(signature.Sig) == 0 || len(signature.Sig) > base64.StdEncoding.EncodedLen(ed25519.SignatureSize) {
			return fmt.Errorf("%w: invalid signature", ErrMalformedEnvelope)
		}
	}
	return nil
}

// DecodeStrictInto decodes JSON only when it is bounded, exactly matches the
// supplied struct's JSON field names, and contains no duplicate object keys.
// The standard encoding/json decoder is intentionally not used alone because it
// accepts duplicate members and case-insensitive field names.
func DecodeStrictInto(raw []byte, maxBytes int, destination any) error {
	if maxBytes <= 0 || len(raw) == 0 || len(raw) > maxBytes {
		return errors.New("JSON input is empty or exceeds its limit")
	}
	value := reflect.ValueOf(destination)
	if value.Kind() != reflect.Pointer || value.IsNil() || value.Elem().Kind() != reflect.Struct {
		return errors.New("strict JSON destination must be a non-nil pointer to struct")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := validateJSONValue(decoder, value.Elem().Type(), 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON input contains trailing value")
		}
		return err
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := ensureEOF(decoder); err != nil {
		return err
	}
	return nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("JSON input contains trailing value")
	}
	return err
}

func validateJSONValue(decoder *json.Decoder, expected reflect.Type, depth int) error {
	if depth > 32 {
		return errors.New("JSON nesting exceeds limit")
	}
	allowNull := expected.Kind() == reflect.Pointer || expected.Kind() == reflect.Slice || expected.Kind() == reflect.Map
	for expected.Kind() == reflect.Pointer {
		expected = expected.Elem()
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		if allowNull {
			return nil
		}
		return fmt.Errorf("null is not valid for %s", expected)
	}
	if expected == rawMessageType {
		return validateArbitraryJSON(decoder, token, depth)
	}
	switch expected.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return fmt.Errorf("expected object for %s", expected)
		}
		fields := jsonFields(expected)
		seen := make(map[string]struct{}, len(fields))
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			field, ok := fields[key]
			if !ok {
				return fmt.Errorf("unknown JSON field %q", key)
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := validateJSONValue(decoder, field.Type, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated object")
		}
		return nil
	case reflect.Slice, reflect.Array:
		if token != json.Delim('[') {
			return fmt.Errorf("expected array for %s", expected)
		}
		for decoder.More() {
			if err := validateJSONValue(decoder, expected.Elem(), depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated array")
		}
		return nil
	case reflect.Map:
		if expected.Key().Kind() != reflect.String || token != json.Delim('{') {
			return fmt.Errorf("expected string-keyed object for %s", expected)
		}
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := validateJSONValue(decoder, expected.Elem(), depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated object")
		}
		return nil
	case reflect.String:
		if _, ok := token.(string); !ok {
			return fmt.Errorf("expected string for %s", expected)
		}
	case reflect.Bool:
		if _, ok := token.(bool); !ok {
			return fmt.Errorf("expected boolean for %s", expected)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if _, ok := token.(json.Number); !ok {
			return fmt.Errorf("expected integer for %s", expected)
		}
	default:
		return fmt.Errorf("unsupported strict JSON type %s", expected)
	}
	return nil
}

// validateArbitraryJSON is used only for json.RawMessage fields inside an
// otherwise exact typed envelope. It preserves extension payloads while still
// rejecting duplicate object keys and excessive nesting.
func validateArbitraryJSON(decoder *json.Decoder, token json.Token, depth int) error {
	if depth > 32 {
		return errors.New("JSON nesting exceeds limit")
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		switch token.(type) {
		case nil, string, bool, json.Number:
			return nil
		default:
			return errors.New("unsupported JSON token")
		}
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := validateArbitraryJSON(decoder, value, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated object")
		}
		return nil
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := validateArbitraryJSON(decoder, value, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated array")
		}
		return nil
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func jsonFields(t reflect.Type) map[string]reflect.StructField {
	fields := make(map[string]reflect.StructField)
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.PkgPath != "" {
			continue
		}
		tag := strings.Split(field.Tag.Get("json"), ",")[0]
		if tag == "-" {
			continue
		}
		if tag == "" {
			tag = field.Name
		}
		fields[tag] = field
	}
	return fields
}
