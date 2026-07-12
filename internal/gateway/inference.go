package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

const maxInferenceJSONDepth = 32
const maxInferenceTopLevelMembers = 1024

// inspectInferenceModel reads the request exactly once through a hard byte
// ceiling, then inspects only the top-level model member. Token inspection is
// deliberate: decoding into a map would silently accept duplicate model keys
// and let the gateway and upstream disagree about which value is authoritative.
func inspectInferenceModel(w http.ResponseWriter, request *http.Request) ([]byte, string, error) {
	if request.ContentLength > maxProxyBody {
		return nil, "", errors.New("inference request exceeds the byte limit")
	}
	request.Body = http.MaxBytesReader(w, request.Body, maxProxyBody)
	raw, err := io.ReadAll(request.Body)
	closeErr := request.Body.Close()
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, "", errors.New("inference request exceeds the byte limit")
		}
		return nil, "", errors.New("inference request body could not be read")
	}
	if closeErr != nil {
		return nil, "", errors.New("inference request body could not be closed")
	}
	model, err := topLevelModel(raw)
	if err != nil {
		return nil, "", fmt.Errorf("inference request JSON is invalid: %w", err)
	}
	return raw, model, nil
}

func topLevelModel(raw []byte) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return "", errors.New("top-level object required")
	}
	model := ""
	seenModel := false
	seenKeys := make(map[string]struct{})
	for decoder.More() {
		if len(seenKeys) >= maxInferenceTopLevelMembers {
			return "", errors.New("too many top-level members")
		}
		keyToken, err := decoder.Token()
		if err != nil {
			return "", err
		}
		key, ok := keyToken.(string)
		if !ok {
			return "", errors.New("object member name is invalid")
		}
		if _, duplicate := seenKeys[key]; duplicate {
			return "", fmt.Errorf("duplicate top-level member %q", key)
		}
		seenKeys[key] = struct{}{}
		value, err := decoder.Token()
		if err != nil {
			return "", err
		}
		if key == "model" {
			seenModel = true
			var stringValue bool
			model, stringValue = value.(string)
			if !stringValue {
				return "", errors.New("top-level model must be a string")
			}
			continue
		}
		if err := skipJSONValue(decoder, value); err != nil {
			return "", err
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return "", errors.New("top-level object is incomplete")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return "", errors.New("trailing JSON value")
		}
		return "", err
	}
	if !seenModel {
		return "", errors.New("top-level model is required")
	}
	return model, nil
}

func skipJSONValue(decoder *json.Decoder, first json.Token) error {
	delimiter, composite := first.(json.Delim)
	if !composite {
		return nil
	}
	if delimiter != '{' && delimiter != '[' {
		return errors.New("JSON value has an unexpected closing delimiter")
	}
	depth := 1
	for depth > 0 {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			continue
		}
		switch delimiter {
		case '{', '[':
			depth++
			if depth > maxInferenceJSONDepth {
				return errors.New("JSON nesting exceeds limit")
			}
		case '}', ']':
			depth--
		}
	}
	return nil
}
