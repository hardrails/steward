package controlplane

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strconv"
	"strings"
	"testing"
)

func TestConsoleServesOnlyEmbeddedSameOriginAssets(t *testing.T) {
	distribution, err := fs.Sub(consoleDistribution, "console/dist")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(distribution, "assets")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		path        string
		contentType string
		asset       string
	}{
		{"/console", "text/html; charset=utf-8", "index.html"},
		{"/console/", "text/html; charset=utf-8", "index.html"},
		{"/console/icon.svg", "image/svg+xml", "icon.svg"},
		{"/console/THIRD_PARTY_NOTICES.txt", "text/plain; charset=utf-8", "THIRD_PARTY_NOTICES.txt"},
	}
	for _, entry := range entries {
		contentType := "text/javascript; charset=utf-8"
		if path.Ext(entry.Name()) == ".css" {
			contentType = "text/css; charset=utf-8"
		}
		tests = append(tests, struct {
			path        string
			contentType string
			asset       string
		}{"/console/assets/" + entry.Name(), contentType, "assets/" + entry.Name()})
	}
	server := &Server{}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			body, err := fs.ReadFile(distribution, test.asset)
			if err != nil {
				t.Fatal(err)
			}
			if len(body) > maxConsoleAssetBytes {
				t.Fatalf("embedded console asset %q is %d bytes; limit is %d", test.asset, len(body), maxConsoleAssetBytes)
			}
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			response := httptest.NewRecorder()
			server.console(response, request)
			if response.Code != http.StatusOK || response.Header().Get("Content-Type") != test.contentType ||
				response.Header().Get("Content-Length") != strconv.Itoa(len(body)) ||
				response.Body.String() != string(body) {
				t.Fatalf("status=%d headers=%v body-bytes=%d", response.Code, response.Header(), response.Body.Len())
			}
			assertConsoleHeaders(t, response.Header())
		})
	}

	indexBytes, err := fs.ReadFile(distribution, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	index := string(indexBytes)
	for _, required := range []string{`href="/console/icon.svg"`, `type="module"`, `/console/assets/`} {
		if !strings.Contains(index, required) {
			t.Fatalf("console index missing local asset %q", required)
		}
	}
	for _, forbidden := range []string{"http://", "https://", "<style", "<script>"} {
		if strings.Contains(index, forbidden) {
			t.Fatalf("console index contains forbidden external or inline source %q", forbidden)
		}
	}
}

func TestConsoleHeadErrorsAndSecurityBoundary(t *testing.T) {
	server := &Server{}
	index, err := fs.ReadFile(consoleDistribution, "console/dist/index.html")
	if err != nil {
		t.Fatal(err)
	}

	head := httptest.NewRecorder()
	server.console(head, httptest.NewRequest(http.MethodHead, "/console", nil))
	if head.Code != http.StatusOK || head.Body.Len() != 0 ||
		head.Header().Get("Content-Length") != strconv.Itoa(len(index)) {
		t.Fatalf("HEAD status=%d headers=%v body=%q", head.Code, head.Header(), head.Body.String())
	}
	assertConsoleHeaders(t, head.Header())

	for _, test := range []struct {
		method string
		target string
		status int
	}{
		{http.MethodPost, "/console", http.StatusMethodNotAllowed},
		{http.MethodGet, "/console?token=must-not-be-accepted", http.StatusBadRequest},
		{http.MethodGet, "/console/unknown", http.StatusNotFound},
		{http.MethodGet, "/console/assets/", http.StatusNotFound},
		{http.MethodGet, "/console/assets/missing.js", http.StatusNotFound},
		{http.MethodGet, "/console/assets/missing.css", http.StatusNotFound},
		{http.MethodGet, "/console/assets/../index.html", http.StatusNotFound},
		{http.MethodGet, "/console/assets/%2e%2e%2findex.html", http.StatusNotFound},
		{http.MethodGet, "/console/package.json", http.StatusNotFound},
		{http.MethodGet, "/console/src/App.jsx", http.StatusNotFound},
		{http.MethodGet, "/console/assets/control-room.js.map", http.StatusNotFound},
	} {
		response := httptest.NewRecorder()
		server.console(response, httptest.NewRequest(test.method, test.target, nil))
		if response.Code != test.status ||
			!strings.Contains(response.Body.String(), `"error":`) ||
			!strings.Contains(response.Body.String(), `"message":`) {
			t.Fatalf("%s %s status=%d headers=%v body=%q", test.method, test.target, response.Code, response.Header(), response.Body.String())
		}
		assertConsoleHeaders(t, response.Header())
	}
}

func TestConsoleSourceRestrictsSignedCommandMutationAndUnsafeBrowserCapabilities(t *testing.T) {
	var source strings.Builder
	for _, name := range []string{"console/src/App.jsx", "console/src/command-courier.js", "console/src/session.js", "console/src/main.jsx"} {
		content, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		source.Write(content)
	}
	script := source.String()
	for _, forbidden := range []string{
		"local" + "Storage",
		"session" + "Storage",
		"document." + "cookie",
		"inner" + "HTML",
		"outer" + "HTML",
		"insertAdjacent" + "HTML",
		"dangerouslySet" + "InnerHTML",
		"eval" + "(",
		"new " + "Function",
		"window." + "open",
		`method: "PUT"`,
		`method: "PATCH"`,
		`method: "DELETE"`,
		"/v1/enrollments",
		"/v1/operators",
		"crypto.subtle.sign",
		"crypto.subtle.generateKey",
		"crypto.subtle.importKey",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("console JavaScript contains forbidden persistence or code sink %q", forbidden)
		}
	}
	if count := strings.Count(script, `method: "POST"`); count != 1 {
		t.Fatalf("console JavaScript contains %d explicit POST call sites, want exactly one", count)
	}
	for _, required := range []string{
		`headers.set("Authorization", "Bearer " + (options.credential || credentialRef.current))`,
		`credentials: "omit"`,
		`redirect: "error"`,
		`referrerPolicy: "no-referrer"`,
		`url.origin !== window.location.origin`,
		`credentialRef.current = ""`,
		`inputRef.current.value = ""`,
		`page.next_after`,
		`More nodes exist.`,
		`tenantPage.next_after`,
		`Load 500 more`,
		`OBSERVE HERE. AUTHORIZE WITH YOUR KEYS.`,
		`method !== "GET" && !commandSubmission`,
		`reenteredCredential !== credentialRef.current`,
		`command_dsse_base64: preview.envelopeBase64`,
		`crypto.subtle.digest("SHA-256", bytes)`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("console JavaScript missing boundary %q", required)
		}
	}
}

func assertConsoleHeaders(t *testing.T, header http.Header) {
	t.Helper()
	expected := map[string]string{
		"Cache-Control":                "no-store",
		"Content-Security-Policy":      consoleContentSecurityPolicy,
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Referrer-Policy":              "no-referrer",
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"X-Robots-Tag":                 "noindex, nofollow, noarchive",
	}
	for name, value := range expected {
		if header.Get(name) != value {
			t.Fatalf("%s=%q want %q", name, header.Get(name), value)
		}
	}
	if header.Get("Permissions-Policy") == "" || strings.Contains(header.Get("Permissions-Policy"), "*") {
		t.Fatalf("Permissions-Policy=%q", header.Get("Permissions-Policy"))
	}
	if header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("console unexpectedly enables CORS: %v", header)
	}
}
