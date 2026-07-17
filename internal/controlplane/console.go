package controlplane

import (
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"path"
	"strconv"
	"strings"
)

// The console is embedded into steward-control so an air-gapped installation
// never needs a CDN, JavaScript package registry, or separate web server.
//
// The committed dist directory is the audited Vite production output. Node
// and npm are needed to rebuild it, but not to build or run Steward.
//
//go:embed console/dist
var consoleDistribution embed.FS

const (
	consoleContentSecurityPolicy = "default-src 'none'; base-uri 'none'; child-src 'none'; connect-src 'self'; font-src 'none'; form-action 'none'; frame-ancestors 'none'; frame-src 'none'; img-src 'self'; manifest-src 'none'; media-src 'none'; object-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self'; style-src-attr 'none'; worker-src 'none'"
	maxConsoleAssetBytes         = 1 << 20
)

func (server *Server) console(writer http.ResponseWriter, request *http.Request) {
	setConsoleSecurityHeaders(writer.Header())
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		methodNotAllowed(writer, http.MethodGet, http.MethodHead)
		return
	}
	if !noQuery(writer, request) {
		return
	}

	asset, contentType, ok := consoleAsset(request.URL.Path)
	if !ok {
		writeError(writer, http.StatusNotFound, "not_found", "the requested console asset does not exist")
		return
	}
	body, err := fs.ReadFile(consoleDistribution, asset)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeError(writer, http.StatusNotFound, "not_found", "the requested console asset does not exist")
			return
		}
		server.logger.Error("embedded console asset missing", "asset", asset, "error", err)
		writeError(writer, http.StatusInternalServerError, "internal_error", "the embedded console asset is unavailable")
		return
	}
	if len(body) > maxConsoleAssetBytes {
		server.logger.Error("embedded console asset exceeds response limit", "asset", asset, "bytes", len(body))
		writeError(writer, http.StatusInternalServerError, "internal_error", "the embedded console asset is unavailable")
		return
	}

	writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
	writer.Header().Set("Content-Type", contentType)
	writer.WriteHeader(http.StatusOK)
	if request.Method == http.MethodGet {
		_, _ = writer.Write(body)
	}
}

func consoleAsset(requestPath string) (string, string, bool) {
	switch requestPath {
	case "/console", "/console/":
		return "console/dist/index.html", "text/html; charset=utf-8", true
	case "/console/icon.svg":
		return "console/dist/icon.svg", "image/svg+xml", true
	case "/console/THIRD_PARTY_NOTICES.txt":
		return "console/dist/THIRD_PARTY_NOTICES.txt", "text/plain; charset=utf-8", true
	}
	const prefix = "/console/assets/"
	if !strings.HasPrefix(requestPath, prefix) {
		return "", "", false
	}
	name := strings.TrimPrefix(requestPath, prefix)
	if name == "" || len(name) > 128 || path.Base(name) != name || !safeConsoleAssetName(name) {
		return "", "", false
	}
	switch path.Ext(name) {
	case ".css":
		return "console/dist/assets/" + name, "text/css; charset=utf-8", true
	case ".js":
		return "console/dist/assets/" + name, "text/javascript; charset=utf-8", true
	default:
		return "", "", false
	}
}

func safeConsoleAssetName(name string) bool {
	for _, character := range name {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return name != "." && name != ".." && !strings.HasPrefix(name, ".")
}

func setConsoleSecurityHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Security-Policy", consoleContentSecurityPolicy)
	header.Set("Cross-Origin-Opener-Policy", "same-origin")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
	header.Set("Permissions-Policy", "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), publickey-credentials-get=(), screen-wake-lock=(), usb=()")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("X-Robots-Tag", "noindex, nofollow, noarchive")
}
