# fileshare

[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-fileshare/fileshare/actions/workflows/ci.yml/badge.svg)](https://github.com/go-fileshare/fileshare/actions/workflows/ci.yml)
[![cgo](https://img.shields.io/badge/cgo-none-0079A8?style=flat-square)](https://github.com/go-fileshare/fileshare)

**Share a disk image over SMB, NFS, WebDAV and SFTP — one configuration, one
binary, pure Go.**

```sh
go install github.com/go-fileshare/fileshare@latest

fileshare --image disk.img --user alice --password-file pw   # one image, now
fileshare --config /etc/fileshare.d                          # several, with users
```

The password comes from a **file**, never a flag: an argument is visible in the
process list to every user on the machine.

```
smb    on 0.0.0.0:445  — photos and scratch
webdav on 0.0.0.0:8080 — photos and scratch
sftp   on 0.0.0.0:2222 — photos and scratch
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
magic and hands back the driver that owns it: **fat32, exfat, ext4, ntfs, ufs,
iso9660, squashfs or hfsplus**.

That is every driver of the one shape — `OpenReader(io.ReaderAt, int64)`, a
filesystem at offset zero.

**apfs, btrfs, xfs and zfs cannot be recognised that way**: each opens a *disk*
image and picks a **partition**, so there is no magic at offset zero to find.
A share says which:

```hcl
share "photos" {
  image      = "/srv/disk.img"
  filesystem = "xfs"
  partition  = 2       # or leave it out: -1, the first data partition
}
```

### A partition, for any filesystem

A disk image holding FAT32, ext4 or exFAT has a partition table in front of it
as often as one holding XFS does — and detection reads offset zero, where a
partitioned image has the *table*. So the partition is chosen first, and the
driver is handed a view of it:

```hcl
share "photos" {
  image           = "/srv/disk.img"
  partition_label = "photos"          # what lsblk calls PARTLABEL
}
```

Three ways to name one, and **only one may be given** — two that disagree would
serve whichever the code tried first:

| | |
|---|---|
| `partition = 2` | counting from 1, the way partitioning tools print them |
| `partition_label = "photos"` | the GPT partition name |
| `partition_uuid = "…"` | the GPT unique GUID — Linux's `PARTUUID` |

⛔ **An index moves.** A disk repartitioned, a tool that writes entries in
another order, an image restored with one partition fewer — and `partition = 2`
names something else, silently, because a filesystem is still found there. A
label or a UUID names the partition itself, which is why fstabs stopped using
indexes years ago. The index is here for MBR images, which have neither.

A share that chose a partition is **read-only**, and says so at startup: the
driver's offsets are the partition's while the file underneath is the whole
disk, so a write would land at that offset from the start of the *image* — on
the partition table, as often as not.

⛔ **Naming a filesystem turns detection off for that share.** That is the
point — and it is the risk, so the image is opened as *that* or refused. A
FAT32 image told it is XFS does not become an XFS share; it fails to start,
saying what it was asked to open it as.

`filesystem` is accepted for the sniffable ones too, and then the two are
compared: a share that says `ext4` over a FAT32 image is refused with *the
share says ext4 and the image holds fat32*. That is how a site refuses a
misdetection rather than discovering one later. `check` marks a named driver
with an asterisk, because that row was not recognised — it was asserted.

## What a protocol can promise

The protocols do not agree about the one thing access control needs: whether
the server can tell **who** is asking.

| | |
|---|---|
| **SMB** | NTLMv2. The password never crosses the wire, and the share tells a reader they are one — in the access mask, before they try. |
| **WebDAV** | HTTP Basic, over whatever TLS the transport gives it. A share a person may not use answers 404, not 403: it is not confirmed to exist. |
| **SFTP** | A **public key**, or an **SSH certificate** from an authority you trust: the server never holds the secret, and with a certificate a person's access is issued and expires elsewhere. No password: a client that prompts for one is doing the thing keys exist to avoid. |
| **OIDC** (over WebDAV) | A **bearer token** an identity provider signed. Verified by [go-authn/oidc](https://github.com/go-authn/oidc): signature, issuer, audience, expiry. No other protocol here has anywhere to put one. |
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

group "family" { members = ["alice", "bob"] }

share "photos" {
  image   = "/srv/photos.img"
  allow   = ["@family"]        # a group, or a person, in either list
  writers = ["alice"]          # bob gets it read-only
}

share "scratch" {
  image = "/srv/scratch.img"   # anyone who authenticates, read-write
}

serve "smb"    { addr = "0.0.0.0:445" }
serve "webdav" { addr = "0.0.0.0:8080" }
serve "sftp"   { addr = "0.0.0.0:2222" }
serve "nfs"    { addr = "0.0.0.0:2049" }
```

## SFTP: keys, or certificates

Every client already has it — `sftp` ships with OpenSSH, the Finder and GNOME
mount it, editors speak it — and it is the one protocol here whose shape does
not fit: a person logs in and lands in **one** filesystem, not a list of
shares. So the shares become the top-level directories of a tree built for
whoever just authenticated:

```
$ sftp -i ~/.ssh/id_ed25519 -P 2222 alice@attic
sftp> ls
photos  scratch
sftp> cd photos
sftp> get holiday.jpg
```

A share alice may not use is not a directory alice can see, and a share she may
only read refuses her writes **in the tree**, before a driver that would have
allowed them. A rename across two shares is refused: it would be a copy and a
delete over two images, and that is not what rename promises anywhere.

```hcl
host_key_file        = "/etc/fileshare/ssh_host_ed25519_key"
trusted_user_ca_file = "/etc/fileshare/ca.pub"   # optional

user "alice" {
  authorized_keys_file = "/etc/fileshare/alice.pub"
}

user "carol" {}   # nothing here: her certificate is her credential
```

With `trusted_user_ca_file`, a certificate signed by that authority and naming
the user among its principals is enough — so a person's access is **issued and
expires elsewhere**, and no file here is edited when somebody joins or leaves.
The signature, the validity window and the principals are checked by
`x/crypto/ssh`'s `CertChecker`; verified against OpenSSH's own client, which
also refuses the same key once its certificate is moved aside.

Without `host_key_file` a fresh identity is generated at every start, and the
server says so: every client that has seen it before will warn about a changed
key, which is the client doing its job.

A directory of small files is one configuration: `--config /etc/fileshare.d`
merges them, so a user in one file and a share in another belong together. A
name in `allow` or `writers` that belongs to no `user` block is refused at
startup — `allow = ["alise"]` would otherwise lock Alice out of her own share
and start happily. A `serve` block with no `addr` lands on the registered port
for that protocol, on loopback.

## A token, over the one protocol that can carry one

```hcl
oidc {
  issuer   = "https://login.example.org"
  audience = "fileshare"
}
```

A browser has a token and no password. So WebDAV accepts `Authorization:
Bearer`, and the challenge it sends offers **both** — a client picks the one it
can answer.

⛔ **Only WebDAV.** SMB authenticates with NTLMv2, SFTP with a key or a
certificate, NFS with nothing at all: none of them has anywhere to put an
Authorization header. That is a fact about the protocols, not a limit of this
program, and a configuration naming a provider without serving WebDAV is
refused rather than started.

⛔ **A token says who the provider thinks somebody is. It does not say this
server has a share for them.** A valid token for a name no source here knows is
refused — the safe reading of *I do not know you* is not *you are allowed*. A
site where the provider **is** the directory says so:

```hcl
oidc {
  issuer    = "https://login.example.org"
  audience  = "fileshare"
  trust_all = true      # everybody that provider vouches for, not just these people
}
```

There is no login flow here: no redirect, no client secret, no cookies. This is
the resource server.

## Where the people come from

A `user` block is the whole directory for a household. A site whose people are
already in a database or in LDAP should not copy them into a second place that
goes stale, so a `users` block reads them where they are:

```hcl
users "sql" {
  driver   = "postgres"                 # or sqlite, or mysql
  dsn_file = "/etc/fileshare/dsn"       # a DSN holds a password: it lives in a file
  users    = "select login, nt_hash, ssh_keys from staff"
  groups   = "select team, member from team_members"
}

users "ldap" {
  url                = "ldaps://ldap.example.org"
  base_dn            = "ou=people,dc=example,dc=org"
  bind_dn            = "cn=reader,dc=example,dc=org"
  bind_password_file = "/etc/fileshare/bind.pw"
}
```

The **queries are yours**, because a site's people are already in that site's
shape; a schema invented here would mean copying them into a second one. The
LDAP side reads what a Samba-aware directory already publishes —
`sambaNTPassword`, `sshPublicKey`, `memberUid` — and every name is
configurable.

Sources are asked **in the order they are written**, and the first one that
knows a name owns it. The `user` and `group` blocks come first, so a service
account written down locally is not overridden by somebody with the same name
in LDAP. Groups are the exception: a group's members are the **union** of every
source, because a team can have people in a file and in a database.

A group is written `@name` wherever a person could be:

```hcl
share "photos" {
  allow   = ["@engineers", "alice"]
  writers = ["@owners"]
}
```

Expansion happens **once, at startup**. A membership that changes in LDAP is
picked up by a restart — said plainly, because asking the directory on every
connection is a different design and this is not it.

### What a source can prove, and what each protocol needs

This is the part a site discovers otherwise at a mount, so `check` says it
first:

| the source has | SMB | WebDAV | SFTP |
|---|---|---|---|
| a password (file, or a cleartext column) | yes | yes | — |
| an NT hash (`sambaNTPassword`, `nt_hash`) | yes | — | — |
| only a bind, or a bcrypt column | **no** | yes | — |
| public keys, or a trusted CA | — | — | yes |

**NTLMv2 needs the password or its MD4, and nothing else will do.** A client
never sends a password to an SMB server — it sends a proof computed from it —
so a directory that only *checks* passwords cannot answer SMB, however good the
check is. That is a property of the protocol, not a limitation of this program,
and no amount of configuration changes it. WebDAV asks only "is this the right
password", which a bind answers.

A person a directory names but proves nothing for is legitimate — a listing
with the secrets elsewhere — and `check` says so in one line rather than
leaving them to find out.

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

USER   FROM                    AUTHENTICATES WITH                 SMB  WEBDAV  SFTP
alice  the configuration file  a password from /etc/…/alice.pw    yes  yes     yes
bob    the configuration file  a password from /etc/…/bob.pw      yes  yes     -
dora   ldaps://ldap.example.org  a password check and an NT hash  yes  yes     -
eli    ldaps://ldap.example.org  a password check                 -    yes     -

this configuration can be served
```

Every image is opened **read-only** and closed again, so this is safe to run
against a live server's images. It prints where a credential comes from and
never what is in it — and the per-person columns are why
[`Identity.Can`](https://github.com/go-authn/directory) exists: eli is in the
same group as dora and SMB still cannot serve him, because LDAP holds his
password and gives it to nobody.

## Building only what you want

Each protocol is behind a build tag, and a tag leaves it out **entirely**: no
listener, no parser, no dependency, no code.

```sh
go install -tags nonfs,nowebdav,nosftp github.com/go-fileshare/fileshare@latest   # SMB only
go build   -tags nosmb,nonfs,nosftp .                                            # WebDAV only
```

Where the **people** come from is behind tags of its own: `nosql` leaves out
the three database drivers, `noldap` the LDAP client.

| build | size |
|---|---|
| everything | 28.6 MB |
| `-tags noldap` | 28.3 MB |
| `-tags nosftp` | 27.9 MB |
| `-tags nonfs,nowebdav,nosftp` (SMB only) | 26.4 MB |
| `-tags nopartitioned` (no apfs, btrfs, xfs, zfs) | 29.5 MB |
| `-tags nosql` | 16.9 MB |
| `-tags nosql,noldap` | 16.6 MB |
| `-tags nosql,noldap,nonfs,nowebdav,nosftp` | 11.9 MB |

`nosql` is by a distance the biggest lever: PostgreSQL, MySQL and SQLite
together weigh **11.7 MB**, more than every protocol in this program put
together. A site whose users are in the file wants it. The drivers are imported
by this command and not by the library that uses them, which is what makes the
choice a build tag rather than a fork.

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

## One process per protocol

```sh
fileshare --config /etc/fileshare.d --isolate
```

```
smb    on 0.0.0.0:445  — process 19810, serving public, photos and scratch
webdav on 0.0.0.0:8080 — process 19811, serving public and photos
nfs    on 0.0.0.0:2049 — process 19812, serving public
```

The parent binds the listeners and then execs **itself** once per protocol,
handing each child only the shares that protocol may serve. Checked with
`lsof`, not by reading the code:

```
smb     (pid 19810) has open: scratch.img photos.img
webdav  (pid 19811) has open: photos.img
nfs     (pid 19812) has open: photos.img
```

The writable image is open in **exactly one process**, and the WebDAV child
never opens it at all. That is what build tags cannot give: a panic or an
exhausted heap in one protocol takes down one protocol, each child can be
confined by whatever the operating system offers, and a bug in one parser
cannot reach an image that process never opened.

On Unix the parent passes the bound listener to the child, so **a privileged
port works with unprivileged children** — the parent binds 445, the child
never needs the privilege. Windows has no `ExtraFiles`, so there the child
binds the address itself; the isolation is the same, the privileged-port
half is not.

**The rule that makes it honest.** A child opens the image itself, so an image
served *writable* by two protocols would be two drivers over one file with no
lock between them — exactly what the shared lock below prevents inside one
process. That is refused, and the refusal says how to fix it:

```
scratch is writable over smb and webdav, and one process per protocol means
that many drivers writing one file with no lock between them. Say
`protocols = ["smb"]` on the share, or make it read_only, or do not isolate.
```

`protocols = [...]` on a share says which of them carry it — useful on its own,
not only under `--isolate`: a share declared SMB-only is a share the WebDAV
process is never told about. A `serve` block that would end up carrying nothing
is refused too, before any image is opened, naming the shares that were kept
from it and why.

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

**S3** — the fifth protocol, and the one that would make an image reachable
from anything that speaks object storage. It needs a `go-filesystems/s3` to
exist first: SigV4 is stdlib arithmetic, and the union tree in `unionfs.go` is
already the shape a bucket list wants.

## Licence

BSD-3-Clause.
