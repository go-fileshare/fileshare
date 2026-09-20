// SPDX-License-Identifier: BSD-3-Clause

//go:build !nonfs

package main

func init() {
	register(&protocol{
		name:          "nfs",
		authenticates: false,
		why: "NFSv3 on its own has no authentication: AUTH_UNIX is a claim the client makes " +
			"about itself and the wire cannot disagree with it. A kerberos block lifts this: " +
			"sec=krb5 carries a principal a ticket proves",
		serve:       serveNFS,
		defaultPort: 2049,
	})
}
