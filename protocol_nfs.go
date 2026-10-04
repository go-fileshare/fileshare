// SPDX-License-Identifier: BSD-3-Clause

//go:build !nonfs

package main

func init() {
	register(&protocol{
		name:          "nfs",
		authenticates: false,
		why: "NFSv3 on its own has no authentication: AUTH_UNIX is a claim the client makes " +
			"about itself and the wire cannot disagree with it. A kerberos block lifts this: " +
			"sec=krb5 carries a principal a ticket proves; so does identity = \"certificate\" " +
			"on the nfs serve block: RPC-over-TLS with a client certificate naming the person",
		serve:       serveNFS,
		defaultPort: 2049,
	})
}
