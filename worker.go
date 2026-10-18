// SPDX-License-Identifier: BSD-3-Clause

package main

import "github.com/spf13/cobra"

// newWorkerCmd is the role a person's worker plays: the launcher starts this
// binary as `fileshare worker`, already running as the person
// (docs/identity.md). It is hidden: nobody runs it by hand, and run by hand it
// refuses -- it finds no socket on descriptor 3.
func newWorkerCmd() *cobra.Command {
	var dir, groups string
	var uid, gid uint64
	var readOnly bool
	cmd := &cobra.Command{
		Use:           "worker",
		Short:         "Serve one share as one person, for the launcher (internal)",
		Hidden:        true,
		Args:          noArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWorker(dir, readOnly, uid, gid, groups)
		},
	}
	f := cmd.Flags()
	f.StringVar(&dir, "directory", "", "the share's directory")
	f.BoolVar(&readOnly, "read-only", false, "serve it read-only")
	f.Uint64Var(&uid, "uid", 0, "the uid this process must find itself running as")
	f.Uint64Var(&gid, "gid", 0, "the gid this process must find itself running as")
	f.StringVar(&groups, "groups", "", "the supplementary gids it must have, comma-separated")
	return cmd
}
