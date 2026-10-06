# Volumes: shares on storage fileshare provisions

**Status: design, for review. Nothing here is implemented yet.**

fileshare serves what already exists: a disk image, a device, a directory. This
adds storage it **creates** — a ZFS dataset, a btrfs subvolume, an XFS or ext4
directory under a project quota — sized, owned and tracked, and served as a
share, all driven through the admin gRPC API.

Creating that storage needs `CAP_SYS_ADMIN` (quotactl, the btrfs quota ioctls,
`/dev/zfs`, mount(2)), and fileshare itself needs none: it parses five network
protocols for strangers. So the privileged part is a separate process with a
small, closed protocol, and the server stays unprivileged.

## Two roles of one binary

```
                         admin gRPC (unix socket 0600 + peer uid, or mTLS)
  operator ─────────────────────────────────────────────▶  fileshare serve
                                                             (unprivileged)
                                                                  │
                     provision gRPC (unix socket, SO_PEERCRED = fileshare's uid)
                                                                  ▼
                                                    fileshare provisioner
                                                    (CAP_SYS_ADMIN, nothing else)
                                                                  │
                                    go-fsctl: zfs · btrfs · projquota (ioctls, no CLI)
```

- `fileshare provisioner` runs under its own systemd unit with
  `CapabilityBoundingSet=CAP_SYS_ADMIN` (plus `CAP_CHOWN`/`CAP_FOWNER` to set a
  volume root's owner), a `SystemCallFilter`, `NoNewPrivileges`. It may **not**
  use `ProtectSystem=`/`ReadWritePaths=` (they disconnect mount propagation, and
  it mounts ZFS datasets) nor Landlock (a Landlock-restricted thread cannot
  mount).
- `fileshare serve` runs as an ordinary user, and may use all of those.

Why one binary rather than a separate daemon: one version to deploy, one
protocol definition, no skew between the two halves. The storage logic itself
lives in go-fsctl, where anything else can use it.

## The provisioner's protocol

`proto/fileshare/provision/v1/provision.proto`, on a unix socket only (as CSI
does: "Only UNIX Domain Sockets MAY be used as endpoints").

```proto
service ProvisionService {
  rpc GetCapabilities(GetCapabilitiesRequest) returns (GetCapabilitiesResponse); // parents, kinds, free space, limits
  rpc CreateVolume(CreateVolumeRequest)   returns (CreateVolumeResponse);
  rpc ResizeVolume(ResizeVolumeRequest)   returns (ResizeVolumeResponse);
  rpc SnapshotVolume(SnapshotVolumeRequest) returns (SnapshotVolumeResponse);  // zfs, btrfs; UNIMPLEMENTED on xfs/ext4
  rpc DeleteVolume(DeleteVolumeRequest)   returns (DeleteVolumeResponse);
  rpc ListVolumes(ListVolumesRequest)     returns (ListVolumesResponse);
}

message CreateVolumeRequest {
  string parent      = 1;  // an id from the provisioner's OWN configuration, never a path
  string name        = 2;  // ^[a-z0-9][a-z0-9_-]{0,62}$
  uint64 quota_bytes = 3;  // 0 is refused: an unbounded volume is a configuration mistake
}
message Volume {
  string parent = 1; string name = 2;
  Kind   kind   = 3;            // ZFS, BTRFS, XFS, EXT4
  string path   = 4;            // <parent root>/<name>, for fileshare to serve
  uint64 quota_bytes = 5; uint64 used_bytes = 6;
  google.protobuf.Timestamp created = 7;
}
```

Rules, each taken from somewhere it is already practice:

| rule | from |
|---|---|
| A request never carries a path: a `parent` id from the provisioner's own configuration, and a `name` matched by a strict grammar. | Proxmox's volume-name regexes; TrueNAS refusing system parents |
| Create and Delete are idempotent by name. The same name with different parameters is `ALREADY_EXISTS`; deleting what is not there is `OK`. | CSI CreateVolume / DeleteVolume |
| Every object it creates carries an ownership mark (a ZFS user property `fileshare:volume=<parent>/<name>`, a btrfs subvolume under its own directory, an XFS/ext4 project id from a configured range), checked before any resize, snapshot or delete. It never touches what it did not create. | TrueNAS, the confused-deputy threat |
| Delete refuses a volume with snapshots, or not empty, unless the request says `destroy_data = true`; every delete is logged before it happens. | TrueNAS pool.dataset.delete |
| `RESOURCE_EXHAUSTED` when the parent has no room, `OUT_OF_RANGE` above the configured per-volume maximum. | CSI error vocabulary |
| The peer's uid (SO_PEERCRED, in a TransportCredentials of our own: grpc-go's `credentials/local` does not report it) must be the configured `client_uid`, or every call is `PERMISSION_DENIED`. | unix(7), OpenSSH privsep |
| Anything else — an unknown method, a malformed message — closes the connection. | OpenSSH privsep's `fatal_f("unpermitted request %d")` |

## Where a volume lives, and who owns it

One rule for all kinds: **a volume is `<parent root>/<name>`**.

- **ZFS**: dataset `<parent dataset>/<name>`, created in ONE ioctl with
  `refquota` (the share's visible size; `quota` would also count snapshots),
  `mountpoint=legacy` (so nothing mounts it behind the provisioner's back) and
  the ownership property; then mounted at `<root>/<name>`. Legacy mounts do not
  survive a reboot, so the provisioner remounts the volumes it owns at start.
- **btrfs**: subvolume `<root>/<name>` on a filesystem with quotas enabled,
  limited by its level-0 qgroup (`max_rfer`). Caveat from btrfs's own docs:
  qgroups slow commits as snapshots multiply.
- **XFS / ext4**: directory `<root>/<name>` with a project id (with
  inheritance) from the configured range and a hard block limit. The mount
  needs `prjquota` (and ext4 the `project,quota` features). `df` inside it then
  shows the quota as the size.

The volume root is owned by `root:<fileshare's group>`, mode `2770`. fileshare
writes into it through the group and never owns it — because the OWNER of a
directory may change or clear its project id without any privilege, and so step
out of an XFS/ext4 quota (fs/file_attr.c, `vfs_fileattr_set`).

## What fileshare adds

Configuration:

```hcl
admin {
  listen       = "unix:///run/fileshare/admin.sock"
  state_file   = "/var/lib/fileshare/shares.json"
  source_roots = ["/srv/fileshare/volumes"]
  provisioner  = "unix:///run/fileshare/provisioner.sock"   # new
}
```

and the provisioner's own file:

```hcl
provisioner {
  listen      = "unix:///run/fileshare/provisioner.sock"
  client_uid  = 990                       # fileshare's
  group       = "fileshare"
  max_volume  = "10T"

  parent "tank"  { zfs = "tank/fileshare",  root = "/srv/fileshare/volumes/tank" }
  parent "fast"  { btrfs = "/srv/fileshare/volumes/fast" }
  parent "plain" { xfs = "/srv/fileshare/volumes/plain", project_ids = "100000-199999" }
}
```

Admin API (`fileshare.admin.v1`), relayed to the provisioner:

- `ListParents`, `CreateVolume`, `ResizeVolume`, `SnapshotVolume`,
  `DeleteVolume`, `ListVolumes`;
- `CreateShareRequest` gains `volume { parent, name }` as a source, beside
  `image` and `directory`. fileshare asks the provisioner for the volume's path,
  checks that it lies under `source_roots`, that it is a directory, and that
  statfs reports the expected filesystem (for ZFS, that it is a mount of that
  dataset) before serving it;
- `DeleteVolume` is refused while a share uses the volume; `DeleteShare` never
  deletes a volume.

And, while there: the admin socket starts checking its peer's uid against a
configured list, where today only its 0600 mode stands in the way.

## Phases

1. go-fsctl: zfs create-with-properties and mount; btrfs quota rescan and the
   subvolume → qgroup helper; a new `go-fsctl/projquota` for XFS and ext4
   project quotas; first tags on those repositories.
2. The provisioner role and its protocol, tested as root in CI on a loop-backed
   pool, btrfs and XFS.
3. The admin API, `volume` sources, the admin socket's peer check, the docs.
4. Ceph, later (CephFS quotas through `ceph.quota.max_bytes` are pure Go;
   RBD through krbd needs the key in the kernel keyring, never in the sysfs
   string).

## Sources

CSI spec (container-storage-interface/spec, spec.md); TopoLVM design (a small
privileged LVM daemon behind a unix socket); OpenSSH privsep (Provos, monitor.c);
TrueNAS middleware `pool_/dataset.py`; Proxmox `PVE/Storage/Plugin.pm`; unix(7),
quotactl(2), Q_XSETQLIM(2const), ioctl_xfs_fsgetxattr(2), mount(2),
systemd.exec(5); Linux `fs/file_attr.c`, `fs/quota/quota.c`, `fs/xfs/xfs_super.c`,
`fs/ext4/ioctl.c`, `include/uapi/linux/{fs,quota,dqblk_xfs,btrfs}.h`; OpenZFS
`zfsprops.7`, `libzfs_mount*.c`, `zpl_super.c`; btrfs-progs
`ch-quota-intro.rst`.
