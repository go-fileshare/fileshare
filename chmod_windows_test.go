//go:build windows

package main

import "testing"

// On Windows a read-only file is an attribute, not a mode, and openImageFile's
// fallback is exercised by the missing-file case instead.
func chmodReadOnly(path string) error { return nil }

var _ = testing.Short
