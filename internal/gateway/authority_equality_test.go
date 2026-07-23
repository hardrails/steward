package gateway

import (
	"bytes"
	"net/http"
	"testing"
)

func TestGrantActionAuthorityEqualityIncludesConnectorScope(t *testing.T) {
	left := GrantActionAuthority{
		KeyID: "action-key", PublicKey: "public", ConnectorIDs: []string{"browser", "search"},
	}
	if !grantActionAuthoritiesEqual(left, left) {
		t.Fatal("identical action authorities were not equal")
	}
	right := left
	right.ConnectorIDs = []string{"browser"}
	if grantActionAuthoritiesEqual(left, right) {
		t.Fatal("different connector scopes were equal")
	}
}

func TestControlTaskResponseWriterRejectsOversizedAgentOutput(t *testing.T) {
	writer := newControlTaskResponseWriter()
	if _, err := writer.Write(bytes.Repeat([]byte("x"), maxControlTaskProxyResponse+1)); err == nil {
		t.Fatal("oversized task response was accepted")
	}
	if !writer.overflow || writer.status != http.StatusOK || writer.body.Len() != 0 {
		t.Fatalf("oversized task response state = %+v", writer)
	}
}
