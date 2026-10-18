// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package main

import "github.com/go-fileshare/fileshare/internal/launch"

func runWorker(dir string, readOnly bool, uid, gid uint64, groups string) error {
	e, err := launch.ParseExpect(uid, gid, groups)
	if err != nil {
		return err
	}
	return launch.Worker(e, dir, readOnly)
}
