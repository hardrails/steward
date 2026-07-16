package imageimport

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

func TestExecuteRejectsIncompleteOrUnboundedRequestBeforeEffects(t *testing.T) {
	valid := Request{
		ArchivePath:     "/tmp/image.tar",
		CapsuleEnvelope: []byte("{}"),
		PolicyEnvelope:  []byte("{}"),
		SiteRoots:       map[string]ed25519.PublicKey{"site-root": make(ed25519.PublicKey, ed25519.PublicKeySize)},
		Now:             time.Unix(1, 0).UTC(),
		DockerSocket:    "/var/run/docker.sock",
		Timeout:         time.Minute,
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name    string
		context context.Context
		mutate  func(*Request)
		want    string
	}{
		{name: "nil context", context: nil, want: "context is required"},
		{name: "canceled context", context: canceled, want: "context canceled"},
		{name: "missing archive", context: context.Background(), mutate: func(request *Request) {
			request.ArchivePath = ""
		}, want: "incomplete or unbounded"},
		{name: "zero time", context: context.Background(), mutate: func(request *Request) {
			request.Now = time.Time{}
		}, want: "incomplete or unbounded"},
		{name: "unbounded timeout", context: context.Background(), mutate: func(request *Request) {
			request.Timeout = MaxTimeout + time.Second
		}, want: "incomplete or unbounded"},
		{name: "invalid site root", context: context.Background(), mutate: func(request *Request) {
			request.SiteRoots = map[string]ed25519.PublicKey{"site-root": {1}}
		}, want: "site-root trust is invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			if test.mutate != nil {
				test.mutate(&request)
			}
			if _, err := Execute(test.context, request); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Execute() error = %v, want %q", err, test.want)
			}
		})
	}
}
