# fileshare

**Share a disk image over SMB, NFS and WebDAV — one configuration, one binary,
pure Go.**

```sh
go install github.com/go-fileshare/fileshare@latest
fileshare --config /etc/fileshare.d
```

```
smb    on 0.0.0.0:445  — photos and scratch
webdav on 0.0.0.0:8080 — photos and scratch
nfs    on 0.0.0.0:2049 — scratch
       photos is not served over nfs: it is restricted to alice and bob, and
       NFSv3 has no authentication at all: AUTH_UNIX is a claim the client
       makes about itself and the wire cannot disagree with it
```

A person wants to **share an image**. Which protocol carries it is a property
of the client at the other end: macOS and Windows reach for SMB, a Linux fleet
already has NFS, a browser or a phone has HTTP. Running three servers, each
with its own configuration file and its own idea of who `alice` is, is a way to
get two of them subtly wrong.

The filesystem inside the image is worked out rather than declared —
[`go-filesystems/detect`](https://github.com/go-filesystems/detect) reads the
magic and hands back the driver that owns it: fat32, exfat, ext4, ntfs,
iso9660, squashfs or hfsplus.

## What a protocol can promise

The protocols do not agree about the one thing access control needs: whether
the server can tell **who** is asking.

| | |
|---|---|
| **SMB** | NTLMv2. The password never crosses the wire, and the share tells a reader they are one — in the access mask, before they try. |
| **WebDAV** | HTTP Basic, over whatever TLS the transport gives it. A share a person may not use answers 404, not 403: it is not confirmed to exist. |
| **NFSv3** | **Nothing.** `AUTH_UNIX` is a claim — the client says "uid 501" and the wire cannot disagree. There is no encryption either. |

So **a share that names who may use it is not exported over NFS**. Not a
warning, not an option: a configuration saying "photos belongs to alice" and a
protocol handing photos to whoever connects cannot both be honoured, and
quietly widening access is the worse of the two failures. The refusal is
printed at startup and in `check`, with the reason.

## The configuration

```hcl
name = "ATTIC"

user "alice" { password_file = "/etc/fileshare/alice.pw" }
user "bob"   { password_file = "/etc/fileshare/bob.pw" }

share "photos" {
  image   = "/srv/photos.img"
  allow   = ["alice", "bob"]   # only these two may connect
  writers = ["alice"]          # bob gets it read-only
}

share "scratch" {
  image = "/srv/scratch.img"   # anyone who authenticates, read-write
}

serve "smb"    { addr = "0.0.0.0:445" }
serve "webdav" { addr = "0.0.0.0:8080" }
serve "nfs"    { addr = "0.0.0.0:2049" }
```

A directory of small files is one configuration: `--config /etc/fileshare.d`
merges them, so a user in one file and a share in another belong together. A
name in `allow` or `writers` that belongs to no `user` block is refused at
startup — `allow = ["alise"]` would otherwise lock Alice out of her own share
and start happily. A `serve` block with no `addr` lands on the registered port
for that protocol, on loopback.

## `check`, before you restart something people are using

```
$ fileshare check /etc/fileshare.d
ATTIC

SHARE    IMAGE               FILESYSTEM  WHO MAY CONNECT           WHO MAY WRITE   SMB  WEBDAV  NFS
photos   /srv/photos.img     fat32       alice and bob             alice           yes  yes     NO
scratch  /srv/scratch.img    ext4        anyone who authenticates  anyone …        yes  yes     yes

photos is not served over nfs: it is restricted to alice and bob, and NFSv3 has
no authentication at all: AUTH_UNIX is a claim the client makes about itself and
the wire cannot disagree with it

USER   PASSWORD FROM
alice  /etc/fileshare/alice.pw
bob    /etc/fileshare/bob.pw

this configuration can be served
```

Every image is opened **read-only** and closed again, so this is safe to run
against a live server's images. It prints where a password comes from and never
what is in it.

## Building only what you want

Each protocol is behind a build tag, and a tag leaves it out **entirely**: no
listener, no parser, no dependency, no code.

```sh
go install -tags nonfs,nowebdav github.com/go-fileshare/fileshare@latest   # SMB only
go build   -tags nosmb,nonfs .                                            # WebDAV only
```

| build | size |
|---|---|
| everything | 14.8 MB |
| `-tags nonfs` | 14.5 MB |
| `-tags nonfs,nowebdav` (SMB only) | 10.3 MB |
| `-tags nosmb,nowebdav` (NFS only) | 10.3 MB |

A configuration naming a protocol this binary was built without is told *that*,
rather than "there is no such protocol" — the difference between a typo and a
build tag.

**Why not subprocess plugins.** It was measured rather than argued:
`hashicorp/go-plugin` brings gRPC and protobuf, which cost **13.2 MB on their
own** — more than this entire binary with all three protocols and every driver
in it. A plugin host would be twice the size before loading anything, and each
plugin binary would carry gRPC again.

For attack surface, a tag is also the stronger tool for anything you do not
run: code that was never compiled cannot be reached, sandboxed or not. What
tags do *not* give is isolation between the protocols you **do** run — today
they share an address space and the same open images — nor a way to add a
protocol without recompiling. Both are real, and both are arguments for a
process boundary rather than for a smaller binary — and the next step for them
is one process per protocol using this same binary, not a plugin framework.
[docs/plugins.md](docs/plugins.md) has the measurements and the design
question that decides it: who owns the image.

## One image, several protocols, one lock

Every server in this family serialises the driver itself, because
[`go-filesystems/interface`](https://github.com/go-filesystems/interface)
promises nothing about concurrent path-based calls — and each of them holds
**its own** lock, knowing nothing about the others. Serving one image over
three protocols at once would therefore have no common lock anywhere, so the
image is wrapped once here and the same wrapper is handed to all of them.

Measured, so as not to overstate it: eight goroutines writing through an
unwrapped fat32 driver under `-race` produce no race today. This is insurance
on a contract, not a reproduction of a defect — ext4 and ntfs are not fat32,
and a driver update is not a thing this program should have to re-audit.

The wrapper carries the optional capabilities through rather than hiding them:
a driver that answers `Opener` gets a locked `File` back, and one whose `File`
answers `WritableFile` keeps its positional writes. The difference between
those and the whole-file fallback was measured at ~70× elsewhere in the family,
so a wrapper that erased them would be a performance defect disguised as
safety.

## Verified

- **macOS** mounts a share over SMB while `curl` is writing to the same image
  over WebDAV, and reads back what WebDAV wrote. Bob's WebDAV write to a share
  he may only read is `403`; a wrong password is `401`.
- **go-smb2** (a client this project did not write) drives twenty concurrent
  reads through SMB while twenty run through WebDAV, under `-race`, in CI.
- The access rules are checked **through every protocol** rather than in the
  configuration alone: alice writes and bob does not, over SMB and over WebDAV,
  and NFS is not offered the share at all.

## Not yet

SFTP — the fourth protocol this was designed for. `go-filesystems/sftp` serves
one Filesystem per daemon and authenticates with keys only, so a per-user view
needs a change there first, and it will be an `sftp` line in the table above
when it lands. S3 likewise: it needs a `go-filesystems/s3` to exist.

## Licence

BSD-3-Clause.
