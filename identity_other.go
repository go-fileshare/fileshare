// SPDX-License-Identifier: BSD-3-Clause

//go:build !unix

package main

import (
	"errors"
	"io"

	"github.com/spf13/cobra"
)

var errNoSetuid = errors.New("shares served as their people need a Unix system: a worker is started with a uid and a gid")

func serveWithLauncher(*config, []string, io.Writer) error { return errNoSetuid }

func newFrontCmd(*options) *cobra.Command {
	return &cobra.Command{
		Use:    "serve-front",
		Hidden: true,
		RunE:   func(*cobra.Command, []string) error { return errNoSetuid },
	}
}
