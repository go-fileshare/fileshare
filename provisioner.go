// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"github.com/spf13/cobra"
)

// The provisioner is the second role of this binary: the privileged half that
// creates the storage a volume is served from. See docs/volumes.md, and
// internal/provision for the role itself.

const provisionerLong = `provisioner creates the storage behind volume shares -- a ZFS dataset, a
btrfs subvolume, an XFS or ext4 directory under a project quota -- and does
nothing else. It is the privileged half of fileshare: it needs CAP_SYS_ADMIN,
and the server, which parses five network protocols for strangers, holds none.

    fileshare provisioner -c /etc/fileshare-provisioner.hcl

It reads its OWN configuration, a provisioner block naming the socket, the
one uid it answers (fileshare's), the group the volumes belong to, and the
parents volumes may be created under. It listens on a unix socket only, and
answers a closed set of verbs: anything else closes the connection.

Linux only.`

func newProvisionerCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:           "provisioner",
		Short:         "Create the storage behind volume shares: the privileged half (Linux)",
		Long:          provisionerLong,
		Args:          noArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProvisioner(cmd, o)
		},
	}
}
