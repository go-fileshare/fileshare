// SPDX-License-Identifier: BSD-3-Clause

//go:build !nos3

package main

func init() {
	register(&protocol{
		name:          "s3",
		authenticates: true,
		serve:         serveS3,
		// 9000 is not registered with IANA for this; it is what MinIO uses
		// and therefore what every client, script and container example
		// already points at. A person who does not say deserves to land where
		// their tools look.
		defaultPort: 9000,
	})
}
