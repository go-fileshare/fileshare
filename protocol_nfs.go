// SPDX-License-Identifier: BSD-3-Clause

//go:build !nonfs

package main

func init() {
	register(&protocol{
		name:          "nfs",
		authenticates: false,
		why: "NFSv3 has no authentication at all: AUTH_UNIX is a claim the client makes " +
			"about itself and the wire cannot disagree with it",
		serve:       serveNFS,
		defaultPort: 2049,
	})
}
