package clustersubstrate

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	OperationInit       = "init"
	OperationJoinServer = "join-server"
	OperationJoinWorker = "join-worker"
)

type PlanRequest struct {
	Operation   string
	ClusterName string
	NodeName    string
	ServerURL   string
	TokenFile   string
	Arch        string
	AirGap      bool
	Start       bool
}

type Plan struct {
	SchemaVersion string    `json:"schema_version"`
	Provider      string    `json:"provider"`
	Version       string    `json:"version"`
	Operation     string    `json:"operation"`
	Service       string    `json:"service"`
	ClusterName   string    `json:"cluster_name"`
	NodeName      string    `json:"node_name"`
	ServerURL     string    `json:"server_url,omitempty"`
	TokenFile     string    `json:"token_file,omitempty"`
	Architecture  string    `json:"architecture"`
	AirGap        bool      `json:"air_gap"`
	Start         bool      `json:"start"`
	Bundle        Artifact  `json:"bundle"`
	Images        *Artifact `json:"images,omitempty"`
	Config        string    `json:"config"`
	Baseline      string    `json:"baseline,omitempty"`
	Trust         []string  `json:"trusted_components"`
	Warnings      []string  `json:"warnings"`
	NextSteps     []string  `json:"next_steps"`
}

var dnsLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
var dnsNamePattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?$`)

func BuildPlan(request PlanRequest) (Plan, error) {
	lock, err := CurrentLock()
	if err != nil {
		return Plan{}, err
	}
	if request.Operation != OperationInit && request.Operation != OperationJoinServer && request.Operation != OperationJoinWorker {
		return Plan{}, errors.New("cluster operation must be init, join-server, or join-worker")
	}
	if !dnsLabelPattern.MatchString(request.ClusterName) {
		return Plan{}, errors.New("cluster name must be a lowercase DNS label")
	}
	if len(request.NodeName) > 253 || !dnsNamePattern.MatchString(request.NodeName) ||
		strings.Contains(request.NodeName, "..") {
		return Plan{}, errors.New("node name must be a lowercase DNS name")
	}
	if request.Arch != "amd64" && request.Arch != "arm64" {
		return Plan{}, errors.New("cluster architecture must be amd64 or arm64")
	}
	if request.Operation == OperationInit {
		if request.ServerURL != "" || request.TokenFile != "" {
			return Plan{}, errors.New("cluster init does not accept a server URL or join-token file")
		}
	} else {
		if err := validateServerURL(request.ServerURL); err != nil {
			return Plan{}, err
		}
		if err := validateTokenFile(request.TokenFile); err != nil {
			return Plan{}, err
		}
	}
	bundle, _ := lock.Artifact(request.Arch, "bundle")
	var images *Artifact
	if request.AirGap {
		value, _ := lock.Artifact(request.Arch, "images")
		images = &value
	}
	config := renderConfig(request)
	plan := Plan{
		SchemaVersion: "steward.cluster-plan.v1",
		Provider:      Provider, Version: lock.Version, Operation: request.Operation,
		Service: serviceFor(request.Operation), ClusterName: request.ClusterName,
		NodeName: request.NodeName, ServerURL: request.ServerURL, TokenFile: request.TokenFile,
		Architecture: request.Arch, AirGap: request.AirGap, Start: request.Start,
		Bundle: bundle, Images: images, Config: config,
		Trust: []string{
			"RKE2 server nodes and datastore",
			"Kubernetes control-plane credentials and certificate authorities",
			"Linux kernel, containerd, gVisor, and cluster networking",
		},
		Warnings: []string{
			"RKE2 is part of the trusted computing base for this cluster profile.",
			"Cluster installation does not move Steward agents from the qualified Docker and gVisor Executor.",
		},
	}
	if request.Operation != OperationJoinWorker {
		plan.Baseline = BaselineManifest
	}
	if request.Start {
		plan.NextSteps = []string{"wait for the RKE2 service to become active", "run the cluster doctor"}
	} else {
		plan.NextSteps = []string{"review the staged configuration", "start " + plan.Service + " when the host is ready"}
	}
	return plan, nil
}

func serviceFor(operation string) string {
	if operation == OperationJoinWorker {
		return "rke2-agent"
	}
	return "rke2-server"
}

func validateServerURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.Path != "" {
		return errors.New("cluster server must be an https:// host:9345 origin with no path, query, fragment, or user information")
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	if err != nil || host == "" || port != "9345" {
		return errors.New("cluster server must use the RKE2 registration port 9345")
	}
	if strings.ContainsAny(host, " \t\r\n") {
		return errors.New("cluster server host is invalid")
	}
	return nil
}

func validateTokenFile(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("cluster join-token file must be a clean absolute path")
	}
	if strings.ContainsAny(path, "\r\n\t") {
		return errors.New("cluster join-token file is invalid")
	}
	return nil
}

func renderConfig(request PlanRequest) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "node-name: %q\n", request.NodeName)
	fmt.Fprintln(&builder, "node-label:")
	fmt.Fprintf(&builder, "  - %q\n", "steward.io/cluster="+request.ClusterName)
	fmt.Fprintln(&builder, "profile: cis")
	if request.Operation != OperationInit {
		fmt.Fprintf(&builder, "server: %q\n", request.ServerURL)
		fmt.Fprintf(&builder, "token-file: %q\n", request.TokenFile)
	}
	if request.Operation != OperationJoinWorker {
		fmt.Fprintln(&builder, "write-kubeconfig-mode: \"0600\"")
		fmt.Fprintln(&builder, "secrets-encryption: true")
		fmt.Fprintln(&builder, "cni: canal")
		fmt.Fprintln(&builder, "disable:")
		fmt.Fprintln(&builder, "  - rke2-ingress-nginx")
		fmt.Fprintln(&builder, "  - rke2-traefik")
		fmt.Fprintln(&builder, "etcd-snapshot-schedule-cron: \"0 */6 * * *\"")
		fmt.Fprintln(&builder, "etcd-snapshot-retention: 12")
	}
	return builder.String()
}

const BaselineManifest = `apiVersion: v1
kind: Namespace
metadata:
  name: steward-system
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
---
apiVersion: v1
kind: Namespace
metadata:
  name: steward-agents
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
---
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: runsc
handler: runsc
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: steward-system
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: steward-agents
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
`
