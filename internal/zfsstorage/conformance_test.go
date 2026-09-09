package zfsstorage

import (
	"bytes"
	"compress/flate"
	"context"
	"errors"
	"io"
	"syscall"
	"testing"
)

type byteProbeFile struct {
	write   func([]byte) (int, error)
	syncErr error
}

func (file byteProbeFile) Write(block []byte) (int, error) { return file.write(block) }
func (file byteProbeFile) Sync() error                     { return file.syncErr }

func TestByteQuotaProbeUsesFreshIncompressibleData(t *testing.T) {
	var previous []byte
	writes := 0
	file := byteProbeFile{write: func(block []byte) (int, error) {
		writes++
		var compressed bytes.Buffer
		writer, err := flate.NewWriter(&compressed, flate.BestSpeed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(block); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if compressed.Len() < len(block)*95/100 {
			t.Fatal("quota probe data compresses instead of allocating storage")
		}
		if bytes.Equal(previous, block) {
			t.Fatal("quota probe reused data eligible for deduplication")
		}
		previous = bytes.Clone(block)
		if writes == 2 {
			return 0, syscall.EDQUOT
		}
		return len(block), nil
	}}
	if err := verifyByteQuota(context.Background(), file, conformanceByteLimit); err != nil {
		t.Fatal(err)
	}
	if writes != 2 {
		t.Fatalf("writes = %d", writes)
	}
}

func TestByteQuotaProbeRequiresKernelQuotaError(t *testing.T) {
	for _, test := range []struct {
		name                    string
		writeErr, syncErr, want error
		short                   bool
	}{
		{name: "write quota", writeErr: syscall.EDQUOT},
		{name: "write full", writeErr: syscall.ENOSPC},
		{name: "sync quota", syncErr: syscall.EDQUOT},
		{name: "write IO", writeErr: syscall.EIO, want: syscall.EIO},
		{name: "sync IO", syncErr: syscall.EIO, want: syscall.EIO},
		{name: "short write", short: true, want: io.ErrShortWrite},
	} {
		t.Run(test.name, func(t *testing.T) {
			file := byteProbeFile{syncErr: test.syncErr, write: func(block []byte) (int, error) {
				if test.writeErr != nil {
					return 0, test.writeErr
				}
				if test.short {
					return len(block) - 1, nil
				}
				return len(block), nil
			}}
			if err := verifyByteQuota(context.Background(), file, conformanceByteLimit); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
	writes := 0
	file := byteProbeFile{write: func(block []byte) (int, error) { writes++; return len(block), nil }}
	if err := verifyByteQuota(context.Background(), file, conformanceByteLimit); err == nil {
		t.Fatal("accepted a filesystem that never enforces quota")
	}
	if writes != 12 {
		t.Fatalf("unbounded probe writes: %d", writes)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifyByteQuota(ctx, file, conformanceByteLimit); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error = %v", err)
	}
	if writes != 12 {
		t.Fatal("cancelled probe wrote data")
	}
}
