package controlplane

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// NewHostGate binds the control-plane HTTP authority to the address that the
// kernel assigned to the listener. A loopback HTTP listener accepts only that
// literal IP and port. A TLS listener accepts exact DNS and IP SANs from the
// leaf certificate at that listener port; port 443 may be omitted.
//
// The gate must wrap the whole control-plane handler. That keeps an attacker
// from using DNS rebinding or an ambiguous Host value to reach either the API
// or the embedded operator console through a browser origin the operator did
// not intend to trust.
func NewHostGate(listenerAddress string, tlsConfig *tls.Config, next http.Handler) (http.Handler, error) {
	if next == nil {
		return nil, errors.New("control Host gate requires an HTTP handler")
	}
	listenerHost, listenerPort, err := net.SplitHostPort(listenerAddress)
	if err != nil {
		return nil, fmt.Errorf("control Host gate listener address: %w", err)
	}
	port, err := canonicalPort(listenerPort)
	if err != nil {
		return nil, fmt.Errorf("control Host gate listener port: %w", err)
	}

	policy := hostPolicy{allowed: make(map[string]struct{}), port: port}
	if tlsConfig == nil {
		ip := net.ParseIP(listenerHost)
		if ip == nil || !ip.IsLoopback() || listenerHost != ip.String() {
			return nil, errors.New("control Host gate requires a canonical literal loopback address when TLS is disabled")
		}
		policy.allowed[ip.String()] = struct{}{}
	} else {
		allowed, err := exactCertificateHosts(tlsConfig)
		if err != nil {
			return nil, err
		}
		policy.allowed = allowed
		policy.allowPortOmission = port == "443"
	}

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !policy.allows(request.Host) {
			writeError(
				writer,
				http.StatusBadRequest,
				"invalid_request",
				"request Host does not match this control endpoint",
			)
			return
		}
		next.ServeHTTP(writer, request)
	}), nil
}

type hostPolicy struct {
	allowed           map[string]struct{}
	port              string
	allowPortOmission bool
}

func (policy hostPolicy) allows(authority string) bool {
	host, port, hasPort, err := parseRequestAuthority(authority)
	if err != nil {
		return false
	}
	if _, ok := policy.allowed[host]; !ok {
		return false
	}
	if hasPort {
		return port == policy.port
	}
	return policy.allowPortOmission
}

func exactCertificateHosts(config *tls.Config) (map[string]struct{}, error) {
	if config == nil || len(config.Certificates) != 1 || len(config.Certificates[0].Certificate) == 0 {
		return nil, errors.New("control TLS Host policy requires exactly one leaf certificate")
	}
	leaf, err := x509.ParseCertificate(config.Certificates[0].Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse control TLS leaf certificate for Host policy: %w", err)
	}

	allowed := make(map[string]struct{}, len(leaf.DNSNames)+len(leaf.IPAddresses))
	wildcardSeen := false
	for _, dnsName := range leaf.DNSNames {
		if strings.Contains(dnsName, "*") {
			wildcardSeen = true
			continue
		}
		canonical, err := canonicalDNSName(dnsName)
		if err != nil {
			return nil, fmt.Errorf("control TLS certificate has an invalid exact DNS SAN %q: %w", dnsName, err)
		}
		allowed[canonical] = struct{}{}
	}
	for _, candidate := range leaf.IPAddresses {
		if candidate == nil || candidate.IsUnspecified() {
			return nil, errors.New("control TLS certificate has an invalid IP SAN")
		}
		canonical := candidate.String()
		if net.ParseIP(canonical) == nil {
			return nil, errors.New("control TLS certificate has an invalid IP SAN")
		}
		allowed[canonical] = struct{}{}
	}
	if len(allowed) == 0 {
		if wildcardSeen {
			return nil, errors.New("control TLS certificate Host policy contains only wildcard SANs; configure at least one exact DNS or IP SAN")
		}
		return nil, errors.New("control TLS certificate Host policy requires at least one exact DNS or IP SAN")
	}
	return allowed, nil
}

func parseRequestAuthority(authority string) (string, string, bool, error) {
	if authority == "" || len(authority) > 512 || strings.TrimSpace(authority) != authority {
		return "", "", false, errors.New("request Host is empty or not canonical")
	}
	for _, character := range authority {
		if character <= 0x20 || character >= 0x7f {
			return "", "", false, errors.New("request Host contains a forbidden character")
		}
	}
	if strings.ContainsAny(authority, `/\\?#@,%`) {
		return "", "", false, errors.New("request Host contains a forbidden delimiter")
	}

	host := authority
	port := ""
	hasPort := false
	if strings.HasPrefix(authority, "[") {
		closing := strings.IndexByte(authority, ']')
		if closing <= 1 || strings.Contains(authority[closing+1:], "]") {
			return "", "", false, errors.New("request Host has invalid IP brackets")
		}
		host = authority[1:closing]
		remainder := authority[closing+1:]
		if remainder != "" {
			if !strings.HasPrefix(remainder, ":") || len(remainder) == 1 {
				return "", "", false, errors.New("request Host has an invalid port")
			}
			port = remainder[1:]
			hasPort = true
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() != nil || host != ip.String() {
			return "", "", false, errors.New("request Host has a non-canonical IPv6 literal")
		}
		host = ip.String()
	} else {
		switch strings.Count(authority, ":") {
		case 0:
		case 1:
			var err error
			host, port, err = net.SplitHostPort(authority)
			if err != nil {
				return "", "", false, errors.New("request Host has an invalid port")
			}
			hasPort = true
		default:
			return "", "", false, errors.New("request Host has an unbracketed IPv6 literal")
		}
		if ip := net.ParseIP(host); ip != nil {
			if ip.To4() == nil || host != ip.String() {
				return "", "", false, errors.New("request Host has a non-canonical IP literal")
			}
			host = ip.String()
		} else {
			var err error
			host, err = canonicalDNSName(host)
			if err != nil {
				return "", "", false, errors.New("request Host has an invalid DNS name")
			}
		}
	}
	if hasPort {
		canonical, err := canonicalPort(port)
		if err != nil {
			return "", "", false, errors.New("request Host has an invalid port")
		}
		port = canonical
	}
	return host, port, hasPort, nil
}

func canonicalDNSName(name string) (string, error) {
	if name == "" || len(name) > 253 || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return "", errors.New("DNS name is empty, too long, or has an empty edge label")
	}
	if net.ParseIP(name) != nil {
		return "", errors.New("IP addresses must use an IP SAN")
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("DNS name has an invalid label")
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' ||
				character >= 'A' && character <= 'Z' ||
				character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return "", errors.New("DNS name has a non-ASCII or invalid character")
		}
	}
	return strings.ToLower(name), nil
}

func canonicalPort(raw string) (string, error) {
	port, err := strconv.Atoi(raw)
	if err != nil || port <= 0 || port > 65535 || strconv.Itoa(port) != raw {
		return "", errors.New("port must be a canonical integer between 1 and 65535")
	}
	return raw, nil
}
