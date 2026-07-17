//go:build !darwin && !linux

package main

import "errors"

func lockCLIContextConfig(string) (func() error, error) {
	return nil, errors.New("CLI context locking is supported only on Linux and macOS")
}
