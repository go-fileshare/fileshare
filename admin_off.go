// SPDX-License-Identifier: BSD-3-Clause

//go:build nogrpc

package main

import (
	"context"
	"errors"
)

// Built with -tags nogrpc: no admin API, and a configuration that asks for
// one is refused rather than served without it.

func checkAdminListen(*adminBlock) error {
	return errors.New("this binary was built with -tags nogrpc, which leaves the admin API out")
}

func startAdmin(context.Context, *server, *config) (func(), error) {
	return nil, errors.New("this binary was built with -tags nogrpc")
}
