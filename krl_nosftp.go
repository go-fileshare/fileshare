// SPDX-License-Identifier: BSD-3-Clause

//go:build nosftp

package main

import "io"

// Without SFTP no SSH certificate arrives, and there is nothing to revoke.
func openSSHKRL(*oidcBlock, io.Writer) (*revocationList, error) { return nil, nil }
