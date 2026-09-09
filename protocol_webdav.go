// SPDX-License-Identifier: BSD-3-Clause

//go:build !nowebdav

package main

func init() {
	register(&protocol{
		name:          "webdav",
		authenticates: true,
		serve:         serveWebDAV,
		defaultPort:   8080,
	})
}
