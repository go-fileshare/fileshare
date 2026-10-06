// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !nogrpc && !noprovisioner

package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/go-fileshare/fileshare/internal/provision"
)

func runProvisioner(cmd *cobra.Command, o *options) error {
	if err := provisionerArgs(o); err != nil {
		return err
	}
	cfg, err := provision.LoadConfig(o.files)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return provision.Run(ctx, cfg, cmd.ErrOrStderr())
}

// provisionerArgs refuses the one-image flags: they describe a share, and the
// provisioner serves none.
func provisionerArgs(o *options) error {
	if len(o.files) == 0 {
		return errors.New("the provisioner needs its configuration: fileshare provisioner -c <file>")
	}
	if o.image != "" || o.user != "" || o.pwFile != "" || o.share != "" {
		return errors.New("--image, --user, --password-file and --share describe a share; the provisioner serves none")
	}
	return nil
}
