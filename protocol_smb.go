// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosmb

package main

func init() {
	register(&protocol{
		name:          "smb",
		authenticates: true,
		serve:         serveSMB,
		defaultPort:   445,
	})
}
