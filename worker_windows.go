// SPDX-License-Identifier: BSD-3-Clause

//go:build !unix

package main

import "errors"

func runWorker(string, bool, uint64, uint64, string) error {
	return errors.New("a worker serves a share as a person, by setuid: there is none on this system")
}
