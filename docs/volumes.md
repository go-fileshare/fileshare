# Volumes: shares on storage fileshare provisions

**Status: the provisioner role is implemented (#59); phase 3 implemented — the admin API's volume calls, `volume` sources and the admin socket's peer check (see "As built (phase 3)" below).**

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

- **ZFS**: dataset `<parent dataset>/<name>`, created in one ioctl with
  `refquota` (the share's visible size; `quota` would also count snapshots),
  `mountpoint=legacy` and the ownership property
  (go-fsctl/zfs `CreateFilesystemWithProps`); then mounted at `<root>/<name>`.
  - ⛔ One ioctl is not one transaction: `zfs_ioc_create` creates the dataset,
    then applies the properties (module/zfs/zfs_ioctl.c), so it exists untagged
    for a moment, and a rejected property makes the kernel destroy it again. No
    mount happens in between — the kernel never mounts on create — so nothing
    is served unquota'd; the provisioner treats a dataset under its parent with
    no ownership mark as not its own.
  - Nothing mounts a `mountpoint=legacy` dataset behind the provisioner's back:
    automatic mounting is userspace's (`zfs create`, `zfs mount -a` at boot,
    `zpool import`), and all of them skip legacy datasets. Legacy mounts do not
    survive a reboot either, so the provisioner remounts the volumes it owns at
    start.
  - ⛔ User properties are inherited: a child of a tagged dataset reports the
    same `fileshare:volume` value. Ownership is the property's SOURCE being the
    dataset itself, not its value (go-fsctl/zfs `UserProp` returns both).
- **btrfs**: subvolume `<root>/<name>` on a filesystem with quotas enabled,
  limited by its level-0 qgroup (`max_rfer`). Caveat from btrfs's own docs:
  qgroups slow commits as snapshots multiply.
- **XFS / ext4**: directory `<root>/<name>` with a project id (with
  inheritance) from the configured range and a hard block limit
  (go-fsctl/projquota). The mount needs `prjquota` (and ext4 the
  `project,quota` features and the `quota_v2` module). `df` inside it then
  shows the quota as the size (the soft limit if one is set). Measured in
  go-fsctl/projquota's CI on real XFS and ext4 mounts:
  - ⛔ **On ext4, anything with `CAP_SYS_RESOURCE` is not limited at all**
    (fs/quota/dquot.c `ignore_hardlimit`): root wrote 16 MiB into an 8 MiB
    quota. XFS has no such exemption. So `fileshare serve` must hold neither
    root nor `CAP_SYS_RESOURCE`, and refuses to start serving volumes if it
    does.
  - A full project is `ENOSPC` on XFS and `EDQUOT` on ext4: fileshare reports
    both as "the share is full".
  - Reading a project's usage needs `CAP_SYS_ADMIN` too, so used space comes
    from the provisioner, never from fileshare.
  - XFS ignores a hard limit below the soft one and makes project 0's limits
    every project's default; the library refuses both.

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
  provisioner  = "unix:///run/fileshare-provisioner/provisioner.sock"   # new
}
```

and the provisioner's own file:

```hcl
provisioner {
  listen      = "unix:///run/fileshare-provisioner/provisioner.sock"   # its OWN directory: it refuses one others can write
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

## As built (#59): what the sketch above left out or got wrong

- **Its own socket directory.** fileshare must not be able to write where the
  provisioner's socket lives (the provisioner refuses a socket directory
  others can write): `/run/fileshare-provisioner/`, not `/run/fileshare/`.
- **Malformed requests.** grpc-go decodes a message before any interceptor
  runs, so an UnknownServiceHandler alone cannot close the connection of a
  peer that sends garbage. The provisioner refuses in three places: a
  `grpc.InTapHandle` (before routing or decoding: unknown method → connection
  closed, other uid → PERMISSION_DENIED), a strict codec that refuses bytes
  that do not decode and messages carrying unknown fields, and a stats handler
  that closes the connection of a call the codec refused. Refusing unknown
  fields means `serve` and the provisioner run the same version: upgrade the
  provisioner first.
- **Snapshots** carry a `snapshot` name; there is no DeleteSnapshot or
  ListSnapshots: a volume's snapshots go with it (`destroy_data`), and
  `Volume` lists their names. `GetVolume` exists.
- **RESOURCE_EXHAUSTED** is: the requested quota (or a resize's growth)
  exceeds the parent's free space now (no overcommit at creation, nothing
  tracked afterwards); an exhausted project-id range; a kernel ENOSPC/EDQUOT.
  Shrinking below what is used is FAILED_PRECONDITION on every kind (btrfs and
  XFS would accept it).
- **Idempotency**: "the same parameters" is the quota.
- **Ownership marks, as built**: ZFS — the `fileshare:volume` property's
  SOURCE is the dataset itself, with the expected value; btrfs — the
  subvolume id and uuid recorded in the provisioner's state file, checked
  against the subvolume's root inode (a subvolume under its directory proves
  nothing: root can make one there); XFS/ext4 — the project id inside the
  parent's range AND equal to the recorded one. Every creation is recorded
  pending first, so a retry finishes it and a delete removes it.
- **btrfs**: deleting a subvolume leaves its qgroup behind (removed best
  effort); a subvolume nested inside a volume escapes the volume's qgroup and
  blocks deletion (ENOTEMPTY).
- **ZFS**: only ZFS volumes are mounted nosuid,nodev (btrfs and XFS volumes
  have their filesystem's flags); a tagged dataset whose state record was lost
  is taken back by the next Create or Delete, not remounted at start.
- **`client_uid = 0`** is refused by the provisioner itself.
- **Tree removal** (XFS/ext4 delete) never follows a link and stops at another
  filesystem by st_dev — which a bind mount of the SAME filesystem does not
  change: a bind mount inside a volume would be walked.
- **systemd**: the example unit's `SystemCallFilter` names `quotactl
  quotactl_fd` explicitly; the unit is not exercised in CI, and whether
  namespacing options other than ProtectSystem/ReadWritePaths (PrivateTmp…)
  also break ZFS mount propagation is unverified.

Measured in #59's root CI job, writing as an unprivileged uid into a 32 MiB
volume: zfs 33554432 bytes then EDQUOT, btrfs 33521664 EDQUOT, xfs 33554432
ENOSPC, ext4 32505856 EDQUOT (the first run's ZFS fill wrote 64 MiB: a
repeating pattern that lz4 compressed away — the test now writes random bytes).

## As built (phase 3): what the sketch above left out or got wrong

- **`provisioner_uid`** (default 0) is the uid the provisioner's socket must
  answer as, checked by the client at every connection
  (`peercred.RequireServer`): a socket somebody else bound gets nothing.
- **Status codes** are relayed as the provisioner gives them, with two
  exceptions of fileshare's own: no `provisioner` configured is
  FAILED_PRECONDITION, and so is a PERMISSION_DENIED from the provisioner —
  passed through, it would tell an allowed admin caller that *they* may not,
  when it is fileshare's uid the provisioner refused (a deployment mistake).
  A provisioner that does not answer is UNAVAILABLE.
- **"Which shares use a volume"** is the shares made from it AND any share —
  of the configuration files too, served, disabled or unavailable — whose
  source lies inside its path. DeleteVolume refuses either, and takes the
  manager's lock across the question and the provisioner's answer, so no
  share can be made from the volume in between.
- **Checks before serving** go further than the sketch: btrfs, the path must
  be a subvolume's root (inode 256) — a plain directory under the parent has
  no qgroup; XFS/ext4, the directory must carry a non-zero project id with
  PROJINHERIT (FS_IOC_FSGETXATTR, unprivileged) — a directory outside every
  project is served unbounded; and the path must be clean before it is
  resolved. ZFS: "a mount of that dataset" is checked as "a mount point of a
  ZFS filesystem" (st_dev differs from the parent's, f_type is ZFS): the
  provisioner's Volume does not say which dataset, so which one is mounted
  there is not verified.
- **A volume share that fails at a start is not a failed start.** Every other
  share whose source cannot be opened stops the server (it always did); a
  volume share whose volume is gone, fails a check, or whose provisioner does
  not answer within 10 s is kept, not served, and reported — at the start,
  in `check`, and in `Share.unavailable`. EnableShare retries it, also on a
  share that is enabled and unavailable.
- **The root / CAP_SYS_RESOURCE refusal applies to every kind**, not only
  ext4: it is one rule for the process, read from the effective uid and
  `/proc/self/status` CapEff bit 24; a status that cannot be read is judged
  exempt. It refuses serving, not the volume calls: creating storage as root
  is harmless, writing into it as root is not.
- **"Full"**: ENOSPC and EDQUOT are both rewritten, for every directory share
  (not only volumes), to one error reading "no space left on device", which
  WebDAV maps to 507 and NFS to NFS3ERR_NOSPC; SFTP v3 has no code for it
  (SSH_FX_FAILURE, with that text). ⛔ SMB cannot be fixed here:
  go-filesystems/smb maps by sentinel only and answers STATUS_ACCESS_DENIED;
  STATUS_DISK_FULL needs a change there. NFS3ERR_DQUOT would be more exact
  for EDQUOT; go-filesystems/nfs never sends it.
- **`allowed_uids`** can only narrow what the socket's 0600 mode allows (its
  owner and root): the sketch's "checking its peer's uid against a configured
  list" cannot let anybody else in. It is refused over TCP (the client
  certificate is the check) and where internal/peercred cannot read a peer
  (not Linux or macOS).
- **The share's size** is what statfs says inside the volume: the quota for
  ZFS (refquota), XFS and ext4 (project statfs); the whole filesystem for
  btrfs, whose statfs ignores qgroups.

Measured in the end-to-end CI job (the provisioner job's last steps):
`fileshare serve` as nobody, filling a 32 MiB volume of each kind over WebDAV
and over SFTP.

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
