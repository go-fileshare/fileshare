// SPDX-License-Identifier: BSD-3-Clause

// Package provision is `fileshare provisioner`: the privileged half of
// fileshare, which creates the storage a volume share is served from -- a ZFS
// dataset, a btrfs subvolume, an XFS or ext4 directory under a project quota
// -- and nothing else. See docs/volumes.md for the design, and
// proto/fileshare/provision/v1/provision.proto for the protocol.
//
// fileshare itself parses five network protocols for strangers and holds no
// privilege. Creating storage needs CAP_SYS_ADMIN (quotactl, the btrfs quota
// ioctls, /dev/zfs, mount(2)), so that part is this separate process, behind a
// unix socket, answering one uid, with a closed set of verbs and requests that
// never carry a path.
//
// It builds on Linux and macOS -- the second only so that its tests run on a
// developer's Mac with fake backends; the command refuses to start anywhere
// but Linux. Elsewhere the package is empty.
package provision
