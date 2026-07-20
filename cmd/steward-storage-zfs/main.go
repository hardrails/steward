// Command steward-storage-zfs owns the narrow privileged OpenZFS and Docker
// named-volume surface used by Steward's local persistent-state backend.
package main

import (
	"context"
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

	"github.com/hardrails/steward/internal/buildinfo"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/securefile"
	"github.com/hardrails/steward/internal/storagebackend"
	"github.com/hardrails/steward/internal/zfsstorage"
)

const (
	configSchema  = "steward.storage-zfs.config.v1"
	maxConfigSize = 64 << 10
	maxTokenSize  = 4096
)

type config struct {
	Schema       string `json:"schema"`
	Socket       string `json:"socket"`
	TokenFile    string `json:"token_file"`
	DatasetRoot  string `json:"dataset_root"`
	MountRoot    string `json:"mount_root"`
	DockerSocket string `json:"docker_socket"`
	ZFSBinary    string `json:"zfs_binary"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("steward-storage-zfs", flag.ContinueOnError)
	flags.SetOutput(stderr)
	version := flags.Bool("version", false, "print the Steward ZFS storage worker version and exit")
	checkConfig := flags.Bool("check-config", false, "validate configuration and token files, then exit")
	configPath := flags.String("config", "/etc/steward/storage-zfs.json", "strict ZFS storage worker configuration")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	if *version {
		fmt.Fprintln(stdout, "steward-storage-zfs "+buildinfo.Resolve())
		return 0
	}
	loaded, token, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "steward-storage-zfs: load configuration:", err)
		return 2
	}
	backend, err := openBackend(loaded)
	if err != nil {
		fmt.Fprintln(stderr, "steward-storage-zfs: validate configuration:", err)
		return 2
	}
	if *checkConfig {
		if _, err := storagebackend.NewHandler(backend, token); err != nil {
			fmt.Fprintln(stderr, "steward-storage-zfs: validate token:", err)
			return 2
		}
		fmt.Fprintln(stdout, "ZFS storage worker configuration valid")
		return 0
	}
	lock, err := acquireLock(loaded.Socket + ".lock")
	if err != nil {
		fmt.Fprintln(stderr, "steward-storage-zfs: acquire lifetime lock:", err)
		return 1
	}
	defer lock.Close()
	if err := backend.Initialize(ctx); err != nil {
		fmt.Fprintln(stderr, "steward-storage-zfs: initialize backend:", err)
		return 1
	}
	handler, err := storagebackend.NewHandler(backend, token)
	if err != nil {
		fmt.Fprintln(stderr, "steward-storage-zfs: create handler:", err)
		return 2
	}
	listener, err := listenUnix(loaded.Socket)
	if err != nil {
		fmt.Fprintln(stderr, "steward-storage-zfs: listen:", err)
		return 1
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(loaded.Socket)
	}()
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 10 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	select {
	case err := <-result:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(stderr, "steward-storage-zfs: serve:", err)
			return 1
		}
		return 0
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			fmt.Fprintln(stderr, "steward-storage-zfs: shutdown:", err)
			return 1
		}
		err := <-result
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(stderr, "steward-storage-zfs: serve:", err)
			return 1
		}
		return 0
	}
}

func loadConfig(path string) (config, string, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return config{}, "", errors.New("configuration path must be a clean absolute file")
	}
	raw, err := securefile.Read(path, maxConfigSize, securefile.TrustFile)
	if err != nil {
		return config{}, "", err
	}
	var loaded config
	if err := dsse.DecodeStrictInto(raw, maxConfigSize, &loaded); err != nil {
		return config{}, "", fmt.Errorf("decode strict configuration: %w", err)
	}
	if err := loaded.validate(); err != nil {
		return config{}, "", err
	}
	tokenRaw, err := securefile.Read(loaded.TokenFile, maxTokenSize, securefile.OwnerOnly)
	if err != nil {
		return config{}, "", fmt.Errorf("read token: %w", err)
	}
	token := strings.TrimSuffix(string(tokenRaw), "\n")
	if strings.HasSuffix(token, "\r") {
		token = strings.TrimSuffix(token, "\r")
	}
	return loaded, token, nil
}

func (loaded config) validate() error {
	if loaded.Schema != configSchema {
		return errors.New("configuration schema is unsupported")
	}
	for name, path := range map[string]string{
		"socket": loaded.Socket, "token_file": loaded.TokenFile, "mount_root": loaded.MountRoot,
		"docker_socket": loaded.DockerSocket, "zfs_binary": loaded.ZFSBinary,
	} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
			return fmt.Errorf("%s must be a clean absolute path", name)
		}
	}
	if loaded.Socket == loaded.DockerSocket || loaded.Socket == loaded.TokenFile {
		return errors.New("worker socket must not alias the Docker socket or token file")
	}
	return nil
}

func openBackend(loaded config) (*zfsstorage.Backend, error) {
	runner := zfsstorage.ExecRunner{Path: loaded.ZFSBinary}
	if err := runner.Validate(); err != nil {
		return nil, err
	}
	binder, err := zfsstorage.NewDockerBinder(loaded.DockerSocket)
	if err != nil {
		return nil, err
	}
	return zfsstorage.New(zfsstorage.Config{
		DatasetRoot: loaded.DatasetRoot, MountRoot: loaded.MountRoot, Runner: runner, Binder: binder,
	})
}

func acquireLock(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, errors.New("lifetime lock must be an owner-only regular file")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func listenUnix(path string) (net.Listener, error) {
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o002 != 0 {
		return nil, errors.New("socket parent must be an existing non-world-writable directory")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("refusing to replace a non-socket at the configured socket path")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return listener, nil
}
