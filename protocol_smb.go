// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosmb

package main

func init() {
	register(&protocol{
		name:          "smb",
		authenticates: true,
		serve:         serveSMB,
		// 4445, not 445: the registered port needs privilege on every operating
		// system, and a default that requires root is a default nobody can
		// use. `serve "smb" { addr = "0.0.0.0:445" }` says so when it is meant.
		defaultPort: 4445,
	})
}
