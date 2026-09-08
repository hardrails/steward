package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hardrails/steward/internal/dsse"
)

func serveTaskIssuer(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("task serve-issuer", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	config := taskIssuerConfig{}
	flags.StringVar(&config.Admission, "admission", "", "operator-approved Executor admission")
	flags.StringVar(&config.Intent, "intent", "", "operator-approved instance intent")
	flags.StringVar(&config.Trust, "trust", "", "authenticated service-trust inventory")
	flags.StringVar(&config.Key, "key", "", "station-only task private key")
	flags.StringVar(&config.KeyID, "key-id", "", "admitted task authority identity")
	flags.StringVar(&config.Store, "store", "", "existing station-only 0700 issuance directory")
	flags.DurationVar(&config.Validity, "valid-for", 5*time.Minute, "finite task permit validity")
	flags.IntVar(&config.Capacity, "capacity", 1024, "retained task limit, at most 4096")
	operations := flags.String("operations", "", "comma-separated allowed service operation identities")
	socket := flags.String("socket", "", "private Unix socket; no TCP listener")
	clientGID := flags.Int("client-gid", -1, "dedicated group allowed to request signatures from a separate UID")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*socket) {
		return errors.New("task serve-issuer requires an absolute private socket path and no positional arguments")
	}
	if *clientGID < 1 || uint64(*clientGID) >= uint64(^uint32(0)) {
		return errors.New("task serve-issuer requires an explicit non-root client group ID")
	}
	config.Operations = strings.Split(*operations, ",")
	issuer, err := openTaskIssuer(config)
	if err != nil {
		return err
	}
	defer issuer.Close()
	listener, err := listenTaskIssuer(*socket, *clientGID)
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if _, err = fmt.Fprintln(stdout, "Task signing station listening on its private Unix socket."); err != nil {
		return err
	}
	return runTaskIssuerServer(ctx, listener, issuer)
}

func listenTaskIssuer(socket string, clientGID int) (net.Listener, error) {
	if clientGID < 1 || uint64(clientGID) >= uint64(^uint32(0)) {
		return nil, errors.New("task issuer requires an explicit non-root client group ID")
	}
	parent, err := os.Lstat(filepath.Dir(socket))
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0o710 ||
		parent.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) ||
		parent.Sys().(*syscall.Stat_t).Gid != uint32(clientGID) {
		return nil, errors.New("task issuer socket requires a signer-owned 0710 parent directory with the configured client group")
	}
	if existing, statErr := os.Lstat(socket); statErr == nil {
		if existing.Mode()&os.ModeSocket == 0 || existing.Mode().Perm() != 0o660 ||
			existing.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) ||
			existing.Sys().(*syscall.Stat_t).Gid != uint32(clientGID) {
			return nil, errors.New("task issuer socket path is occupied by an unsafe artifact")
		}
		connection, dialErr := net.DialTimeout("unix", socket, time.Second)
		if dialErr == nil {
			_ = connection.Close()
			return nil, errors.New("task issuer socket already has a listener")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, errors.New("task issuer socket liveness is uncertain")
		}
		current, currentErr := os.Lstat(socket)
		if currentErr != nil || !os.SameFile(existing, current) {
			return nil, errors.New("task issuer socket changed during recovery")
		}
		if err = os.Remove(socket); err != nil {
			return nil, err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, statErr
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return nil, err
	}
	// Only the signer can mutate the directory. Grant the dedicated client group
	// socket access, never access to the 0700 store or private key snapshots.
	if err = os.Chown(socket, -1, clientGID); err != nil {
		_ = listener.Close()
		return nil, err
	}
	if err = os.Chmod(socket, 0o660); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func runTaskIssuerServer(ctx context.Context, listener net.Listener, issuer *taskIssuer) error {
	server := &http.Server{
		Handler: http.HandlerFunc(issuer.serveHTTP), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192,
	}
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(listener) }()
	select {
	case err := <-finished:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return err
		}
		if err := <-finished; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

func (issuer *taskIssuer) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	defer func() {
		if recover() != nil {
			writeTaskIssuerError(writer, 500, "internal_error", "Signing failed unexpectedly. Reconcile the original task before retrying.")
		}
	}()
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if request.RequestURI != "/v1/tasks" {
		writeTaskIssuerError(writer, 404, "not_found", "Task signing route is unavailable.")
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeTaskIssuerError(writer, 405, "method_not_allowed", "Task signing requires POST.")
		return
	}
	if request.Header.Get("Origin") != "" || request.Header.Get("Content-Type") != "application/json" {
		writeTaskIssuerError(writer, 400, "invalid_request", "Use the private host signing client with JSON.")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxTaskBundleBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		writeTaskIssuerError(writer, 413, "request_too_large", "Task signing request exceeds its bound or is unreadable.")
		return
	}
	var intent taskIssuerRequest
	if err = dsse.DecodeStrictInto(body, maxTaskBundleBytes, &intent); err != nil {
		writeTaskIssuerError(writer, 400, "invalid_request", "Task signing fields are invalid.")
		return
	}
	bundle, err := issuer.issue(intent)
	if err != nil {
		if errors.Is(err, errTaskIssuerPreparation) {
			writeTaskIssuerError(writer, 500, "preparation_failed", "Repair the station's private staging storage and pinned authority. Keep the original task identity and reconcile before retrying.")
			return
		}
		status, code := 422, "issuance_rejected"
		if errors.Is(err, errTaskIssuerConflict) {
			status, code = 409, "issuance_conflict"
		} else if errors.Is(err, errTaskIssuerCapacity) {
			status, code = 503, "capacity_exhausted"
		} else if errors.Is(err, errTaskIssuerBusy) {
			status, code = 503, "signer_busy"
		} else if errors.Is(err, errTaskIssuerStorage) {
			status, code = 500, "storage_unconfirmed"
		}
		writeTaskIssuerError(writer, status, code, "No replacement authority was issued. Reconcile the original task and signing station.")
		return
	}
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(bundle)
}

func writeTaskIssuerError(writer http.ResponseWriter, status int, code, message string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]string{"error": code, "message": message})
}
