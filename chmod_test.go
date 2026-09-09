//go:build !windows

package main

import "os"

// chmodReadOnly makes a file unwritable. Windows does not express this with a
// mode bit, so the test that uses it is not run there.
func chmodReadOnly(path string) error { return os.Chmod(path, 0o400) }
