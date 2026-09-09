// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosftp

package main

func init() {
	register(&protocol{
		name:          "sftp",
		authenticates: true,
		serve:         serveSFTP,
		// 2222, not 22: the registered port belongs to the machine's own SSH
		// daemon, and taking it would lock somebody out of their server.
		defaultPort: 2222,
	})
}
