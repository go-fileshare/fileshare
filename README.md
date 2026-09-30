# fileshare

[![Go Reference](https://pkg.go.dev/badge/github.com/go-fileshare/fileshare.svg)](https://pkg.go.dev/github.com/go-fileshare/fileshare)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-fileshare/fileshare/actions/workflows/ci.yml/badge.svg)](https://github.com/go-fileshare/fileshare/actions/workflows/ci.yml)
[![cgo](https://img.shields.io/badge/cgo-none-0079A8?style=flat-square)](https://github.com/go-fileshare/fileshare)

**Share a disk image — or a directory — over SMB, NFS, WebDAV, SFTP and S3 —
one configuration, one binary, pure Go.**

Documentation: **<https://go-fileshare.github.io/docs/>**

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
       NFSv3 on its own has no authentication: AUTH_UNIX is a claim the client
       makes about itself and the wire cannot disagree with it. A kerberos
       block lifts this: sec=krb5 carries a principal a ticket proves
```

That last refusal is the one that used to be permanent. A `kerberos` block
makes NFS able to tell people apart, and `photos` is then served over it like
anywhere else — to `alice` and `bob`, and to nobody else:

```hcl
kerberos {
  realm  = "EXAMPLE.ORG"
  keytab = "/etc/fileshare/krb5.keytab"
}
```

The realm is compared, not just the name before the `@`: two realms can each
have an `alice`, and only one of them is yours.

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
| **S3** | **SigV4**, header or presigned. The secret proves itself by computing an HMAC and never crosses the wire — so, like NTLMv2, the directory must HOLD the password rather than merely check it. A share is a bucket. |
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

tls {
  cert_file = "/etc/fileshare/tls/fullchain.pem"
  key_file  = "/etc/fileshare/tls/key.pem"
}

serve "smb"    { addr = "0.0.0.0:445" }
serve "webdav" {
  addr = "0.0.0.0:443"
  tls  = true
}
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

### People the identity provider vouches for, over SFTP

```hcl
oidc {
  issuer           = "https://login.example.org"
  audience         = "fileshare"
  ssh_ca_file      = "/etc/fileshare/bridge-ca.pub"   # go-authn/bridge's ssh_ca
  opkssh_client_id = "opkssh"                         # OpenPubkey logins
  opkssh_max_age   = "24h"                            # 12h, 24h, 48h, 1week
}
```

- **A certificate the provider's SSH CA signed** -- `bridge ssh-cert` writes
  one after a login through the federation. Its principal is the person, its
  `groups@go-authn.org` extension their groups, so `oidc:groups:` rules
  apply. It is *not* `trusted_user_ca_file`, whose certificates are about
  local accounts: a local authority's certificate claiming the provider's
  groups is read as the local account it names.
- **An OpenPubkey certificate**, as `opkssh login` writes: signed by the
  user's own key, with an ID token that commits to that key. It is checked as
  `opkssh verify` checks it -- the [openpubkey](https://github.com/openpubkey/openpubkey)
  verifier (the provider's signature against its published keys, the nonce
  commitment, the client ID, the age), then the certificate's key against the
  token's -- and the SSH user name must be the token's username, because there
  is no auth_id file here to map one to the other:
  `sftp alice@univ-example.fr@files.example.org`.

⛔ **A certificate is checked at login, and revoking the person does not
revoke it.** Disabling somebody in go-authn/bridge revokes their tokens and
deletes their application passwords -- which a directory reload applies here,
closing their SMB, WebDAV and S3 sessions -- but a certificate already issued
still opens SFTP until it expires, and an SFTP session already open stays
open: these people are not in the directory, so no reload concerns them. The
window is the certificate's lifetime: bridge's `ssh_ca { validity }` (12h by
default, at most 168h, and never past the IdP session's end) and
`opkssh_max_age` here. Keep it as short as the clients' re-login allows --
`bridge token` and opkssh fetch a new one without asking the person.

#### Revoking a certificate

```hcl
oidc {
  # ...
  ssh_ca_file     = "/etc/fileshare/bridge-ca.pub"
  ssh_krl_url     = "https://bridge.example.org/ssh/krl"   # or ssh_krl_file
  ssh_krl_max_age = "1h"                                   # default; ssh_krl_refresh = "1m"
}
```

go-authn/bridge publishes the SSH certificates it has revoked — a person
disabled, an IdP disabled — as an OpenSSH **KRL** (`PROTOCOL.krl`, the list
`sshd`'s `RevokedKeys` reads), and fileshare keeps a copy of it, read with
[go-authn/krl](https://github.com/go-authn/krl). A revoked certificate is
refused at login, and **a session it already opened stops being served**: SSH
checks a certificate once, so every operation of a federated SFTP session asks
the KRL again, open files included.

⛔ **It fails closed.** While the KRL cannot be fetched, or its last good copy is
older than `ssh_krl_max_age`, the provider's certificates are refused: a
revocation check that lets everything through when the list is unreachable is
the one an attacker who can block the list defeats. The list must then be
served as reliably as the logins it governs; `fileshare_revocation_list_age_seconds`
is the metric to alert on before `max_age` is reached. The KRL is fetched over
https only (`ssh_krl_ca_file` pins its authorities); it is not signed, because
nothing checks a KRL's signature -- OpenSSH 9.6 and 10.3 read a signed one and
skip the signature (measured by go-authn/krl against both).

OpenPubkey (opkssh) certificates are not in any KRL — nothing issued them but
the person's own key — and are bounded by `opkssh_max_age`.

#### Which institutions, and which groups

```hcl
oidc {
  # ...
  domains = ["univ-a.fr", "univ-b.fr"]   # nobody else from the federation gets in
}

share "projet-x" {
  image   = "/srv/projet-x.img"
  allow   = ["oidc:groups:urn:mace:univ-a.fr:projet-x", "oidc:domain:univ-b.fr"]
  writers = ["oidc:groups:urn:mace:univ-a.fr:projet-x"]
}
```

`domains` is checked at authentication, over SFTP and WebDAV alike: a name
must be `<something>@<one of them>`, compared whole (`evilunivb.fr` is not
`univb.fr`). `oidc:domain:` is the same test for one share. The domain can be
trusted as far as the provider: go-authn/bridge drops an eppn or subject-id
whose scope the IdP's federation metadata does not grant it.

**Groups** are what the institution's IdP releases, turned into the `groups`
claim by go-authn/bridge's `claims { groups = [...] }`: `eduPersonEntitlement`
by default (a lab's or a VO's groups, as eduTEAMS or an institution's group
manager publishes them), or `eduPersonScopedAffiliation` (`staff@univ-a.fr`,
`student@univ-b.fr`). They travel in the token over WebDAV and in the
certificate's `groups@go-authn.org` extension over SFTP. To see them:

```sh
ssh-keygen -L -f ~/.ssh/id_ed25519-cert.pub     # the Extensions section
```

and this server says, at every federated SFTP login,
`sftp: alice@univ-a.fr, vouched for by the provider, in groups [...]`.

⛔ Somebody the provider vouches for is still a stranger here unless a rule
names them or `trust_all` says the provider is the directory -- the same test a
token passes over WebDAV. A provider certificate with no principal, valid for
*anybody* by the format's own definition, is refused.

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

⛔ **A bearer token: only WebDAV.** SMB authenticates with NTLMv2, SFTP with a
key or a certificate, NFS with nothing at all, and **S3 with a SigV4
signature** — an HMAC computed over the request, with no field a bearer token
fits in. None of them has anywhere to put an Authorization header. That is a
fact about the protocols, not a limit of this program.

**The provider's word over SFTP** arrives in a certificate instead, in two
shapes (see below): one its SSH CA signed, or an opkssh one. A configuration
naming a provider and serving neither WebDAV nor such an SFTP is refused rather
than started.

The usual way to reach S3 with an OIDC token is **STS
`AssumeRoleWithWebIdentity`**, which exchanges the token for temporary
credentials the client then signs with. That is a different thing from
accepting a bearer token, and it is not implemented here — said plainly
because it is the first thing somebody arriving from MinIO will look for.

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

### People the provider names, not this file

A federation -- RENATER through [go-authn/bridge](https://github.com/go-authn/bridge),
say -- knows who is in a project, and a share can ask IT rather than copy the
list:

```hcl
share "photos" {
  image   = "/srv/photos.img"
  allow   = ["oidc:groups:urn:mace:univ-example.fr:photos", "oidc:user:bob@univ-example.fr", "alice"]
  writers = ["oidc:groups:urn:mace:univ-example.fr:photos"]
}
```

`oidc:groups:<value>` is somebody whose token's groups claim holds the value;
`oidc:user:<name>` is somebody the token names. The spelling is opkssh's, so
that one vocabulary says who reaches a shell and who reaches a share. Somebody
a rule names is known to this server as far as tokens go -- the open shares
too -- and somebody no rule names is still a stranger.

⛔ **A rule is about the provider's people only.** `oidc:user:bob` is the bob
the provider vouches for; a local account called bob, with a password, is
somebody else and matches no rule. A rule with no `oidc` block, a malformed
one, or one that may write without being allowed to connect is refused at
startup.

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

| the source has | SMB | S3 | WebDAV | SFTP |
|---|---|---|---|---|
| a password (file, or a cleartext column) | yes | yes | yes | — |
| an NT hash (`sambaNTPassword`, `nt_hash`) | yes | **no** | — | — |
| only a bind, or a bcrypt column | **no** | **no** | yes | — |
| public keys, or a trusted CA | — | — | — | yes |

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
| everything | 31.2 MB |
| `-tags noldap` | 30.9 MB |
| `-tags nosftp` | 30.6 MB |
| `-tags noopenpubkey` (no opkssh logins over SFTP) | about 2 MB less |
| `-tags nos3` | 31.1 MB |
| `-tags nonfs,nowebdav,nosftp,nos3` (SMB only) | 28.1 MB |
| `-tags nopartitioned` (no apfs, btrfs, xfs, zfs) | 29.2 MB |
| `-tags nosql` | 20.2 MB |
| `-tags nosql,noldap` | 19.8 MB |
| `-tags nosql,noldap,nonfs,nowebdav,nosftp,nos3` | 16.2 MB |

The admin API brought gRPC and protobuf in, and they are behind `nogrpc`
(linux/amd64, measured 2026-09-29, when the rows above had grown to 34.1 MB for
everything):

| build | size |
|---|---|
| everything, with the admin API | 46.1 MB |
| `-tags nogrpc` | 34.4 MB |
| `-tags nosql,noldap,nogrpc` | 22.5 MB |

gRPC costs **11.7 MB** — the measurement below, taken again, now that it is
here for a reason of its own. A configuration with an `admin` block, in a
`nogrpc` build, is refused rather than served without one.

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

## A device, not only an image

```hcl
share "photos" {
  image = "/dev/sda"        # a device node, not a file
}
```

**No privilege is involved.** Nothing here mounts anything -- the
[`go-filesystems`](https://github.com/go-filesystems) drivers read ext4, xfs and
the rest in user space -- so there is no `mount(2)` and therefore no
`CAP_SYS_ADMIN`. Opening a device is an ordinary `open(2)`, governed by the
permissions on the node:

| | owner | mode | enough |
|---|---|---|---|
| Linux `/dev/sda` | `root:disk` | 0660 | membership of `disk` |
| macOS `/dev/disk0` | `root:operator` | 0640 | membership of `operator`, plus Full Disk Access |

A refusal says which group, rather than `permission denied` -- the answer is
never `sudo`. Port 445 is the one privileged act left, and `--isolate` already
handles it: the parent binds the listener, the child that speaks SMB never
needs the privilege.

⛔ **A device share is read-only.** The same reasoning as a share that chose a
partition. Writing to a live disk is not a decision to make on your behalf.

⛔⛔ **The device is opened exclusively, and that is about correctness, not
caution.** If the kernel has a filesystem mounted from it, the filesystem's
page cache holds newer metadata than the device does -- so a raw reader sees a
directory block from before an update beside an inode block from after it, a
state that never existed on disk at any one moment. `O_EXCL` on a block device
is the kernel's own primitive for "nobody else, a mount included"; it is what
`mkfs` and `fsck` use. A device in use is refused, by name, with the reason.

Two things were measured rather than assumed, and both were surprises:

- `Stat().Size()` is **0** for a device, so the length is asked of the device
  itself. Seeking to the end answers on Linux and returns **0 with no error**
  on macOS, which is why Darwin uses `DKIOCGETBLOCKCOUNT` instead.
- A **raw** node (`/dev/rdiskN`, or `O_DIRECT` on Linux) refuses an unaligned
  read, and reading a two-byte field at offset 11 is what parsing a FAT BPB
  *is*. Reads to a device are rounded out to whole blocks; without that,
  `/dev/rdisk4` reported `unknown filesystem` -- the `EINVAL` swallowed by a
  detector that found no magic number.

## A directory, not only an image

A share may serve a directory of the host — a container's volume, say —
instead of an image:

```hcl
share "photos" {
  directory = "/data/photos"
  allow     = ["@family"]
}
```

It is [go-filesystems/osfs](https://github.com/go-filesystems/osfs), which
reaches the tree through an `os.Root`: `..` that climbs out, and a symbolic link
leading out, are refused by the kernel-backed root, not by a string test. A
client may *create* a link to `/etc`; nothing will follow it. A FIFO planted in
the tree is refused rather than left to hang the server.

A directory is **not** put behind the one lock images share (see below): an
image driver owns one file and promises nothing about two calls at once, while
a host tree is the kernel's. `filesystem` and `partition` are for an image, and
a directory share naming one is refused.

## The admin API

```hcl
admin {
  listen       = "unix:///run/fileshare/admin.sock"   # made 0600
  state_file   = "/var/lib/fileshare/shares.json"
  source_roots = ["/srv/images", "/data"]
}
```

A gRPC service, [`fileshare.admin.v1.AdminService`](proto/fileshare/admin/v1/admin.proto):
create, update and delete shares, **disable** and **enable** them, **grant** a
user, a `@group`, an `oidc:groups:` value or an `oidc:user:` name read or write
access, and **revoke** it; list the shares, the users (with the protocols their
credentials can answer) and the groups, and **reload the directory** now. Every
change answers with what serving
it did — the generation now served and how many connections were closed.
`grpc.health.v1` answers on the same listener.

- **Disabling is Samba's `available = no`**: the share stays defined and every
  attempt to connect fails; its open connections are closed and its image or
  directory is let go of, so the file can be replaced while it is offline.
  Unlike every other change it applies to a share of the configuration too —
  taking a share offline is an operation, not a definition — and it survives a
  restart; `fileshare check` lists what is offline.

- **Over TCP it is mutual TLS or nothing**: `tls_cert_file`, `tls_key_file` and
  `client_ca_file` together, loopback included — any local user can reach
  loopback, and this API decides who reads whose files. The listener is
  [grpc-transports/control](https://github.com/grpc-transports/control). Each
  change is logged with who made it: the client certificate's CN, or the
  socket peer's uid.
- **It manages the shares it created.** A share written in the configuration is
  listed and cannot be changed through the API: a share defined in two places
  is a question nobody wants to answer. The API's shares live in `state_file`,
  written atomically, and are served again at the next start.
- **A source must lie under `source_roots`**, resolved — links followed, `..`
  taken out — and it is the resolved path that is kept. Without `source_roots`
  the API cannot create shares: the process can read `/dev` and `/etc`, and
  nobody meant to hand those to a caller.
- **Every share has at least one grant.** A share with none is open to anyone
  who authenticates; the file may say that on purpose, an API call should not
  say it by omission. So `CreateShare` needs a grant and revoking the last one
  is refused.
- **A change is checked like a configuration, opened, written down, then
  served** — and a change the server cannot honour (an image that will not
  open, a name nobody in the directory has) is refused with what was served and
  what was written left as they were.
- ⛔ **A change restarts the protocol servers, and closes their connections.**
  SMB checks who may connect once per tree connect and SFTP builds a person's
  tree once per login, so a session that outlived a revocation would keep the
  access just taken away. The ports stay bound, so a client connecting during a
  change waits instead of being refused; images whose share did not change keep
  their driver, never opened a second time.

The Go code under `proto/` is generated and committed, so `go install` needs no
`protoc`; after changing the `.proto`, regenerate it with the versions CI pins
(protoc 34.1, protoc-gen-go v1.36.12, protoc-gen-go-grpc v1.6.2):

```sh
protoc -I proto --go_out=. --go_opt=module=github.com/go-fileshare/fileshare \
  --go-grpc_out=. --go-grpc_opt=module=github.com/go-fileshare/fileshare \
  proto/fileshare/admin/v1/admin.proto
```

`--isolate` does not go with an `admin` block yet: there is no one process a
change could be applied to.

## Health and metrics

```hcl
metrics { listen = "127.0.0.1:9100" }   # or unix:///run/fileshare/metrics.sock
```

`/healthz` (the process answers), `/readyz` (every protocol is bound and a
generation is serving — 503, and why, while starting, applying a change or
stopping) and `/metrics` in Prometheus text format, served by
[go-net-health/endpoint](https://github.com/go-net-health/endpoint) on a
listener of its own, never a public port.

`fileshare_shares{origin}`, `fileshare_generation`,
`fileshare_connections_accepted_total{protocol}`,
`fileshare_connections_open{protocol}`, `fileshare_admin_changes_total{result}`,
`fileshare_admin_requests_total{method,code}`, `fileshare_directory_people`,
`fileshare_directory_reloads_total{result}`, the Go runtime, build info.
⛔ **No metric names a share or a person**: WebDAV answers 404 for a share
somebody may not use, so that it is not confirmed to exist, and a scrape must
not confirm it either.

## Reading the directory again

```hcl
reload = "5m"   # and on SIGHUP, and on the admin API's ReloadDirectory
```

The people come from directories other things change — go-authn/bridge
writes an application password into a table, and deletes the row when the
person is disabled. A reload reads them again, and what it does depends on
what changed:

- **only additions** — somebody new, who changes no share's lists (a new
  application password, a person the shares reach through `oidc:` rules or
  none at all): added in place, SMB's running server included, and **no
  connection is touched**. Somebody new who joins a group a share names *does*
  change that share, and goes through a new generation like any other change
  to it: SMB fixes a share's lists when it starts;
- **anything taken away** — somebody gone, a credential changed, a share whose
  expanded lists changed: a new generation, and the old one's connections
  closed, so a removal reaches the sessions already open;
- **a directory that cannot be read** — nothing changes. An outage must not
  empty a file server.

⛔ A share written for `@engineers` whose last engineer has left is served to
**nobody**, not to everybody: an empty `allow` means "anyone who
authenticates", so what decides whether a share is open is what was
*written*, not what it expands to now. Such a share is not offered over SMB at
all, whose empty `AllowUsers` would read as everyone.

It is the `users` blocks — SQL, LDAP — that are read again; the `user` blocks
of the configuration file are the configuration, read at the start.

## TLS, and certificates from ACME

WebDAV and S3 are served over HTTPS, and NFS over RPC-with-TLS (RFC 9289),
with `tls = true` on their serve block and one `tls` block saying where the
certificate comes from — files, reloaded when they change:

```hcl
tls {
  cert_file = "/etc/fileshare/tls/fullchain.pem"
  key_file  = "/etc/fileshare/tls/key.pem"
}

serve "webdav" {
  addr = "0.0.0.0:443"
  tls  = true
}
```

— or an ACME CA, through [go-authn/servercert](https://github.com/go-authn/servercert).
Let's Encrypt by default; a CA that knows you through external account
binding, such as GÉANT TCS through HARICA:

```hcl
tls {
  acme {
    directory_url     = "https://acme-v02.harica.gr/acme/<uuid>/directory"   # the Server URL cm.harica.gr shows
    domains           = ["files.example.org"]
    cache_dir         = "/var/lib/fileshare/acme"
    eab_key_id        = "…"
    eab_hmac_key_file = "/etc/fileshare/tls/eab.key"   # a secret: a file, never the config
  }
}
```

What decides whether ACME can work is how the CA checks the name:

| challenge | the CA connects to | so |
|---|---|---|
| tls-alpn-01 (RFC 8737) | port **443** | a TLS protocol must be served on 443 |
| http-01 (RFC 8555 §8.3) | port **80** | `http_challenge = "0.0.0.0:80"` answers it |
| none | nothing | a CA account with the domain **pre-validated** asks for no challenge: HARICA's enterprise EAB accounts for GÉANT TCS — so a server nobody outside can reach still gets its certificate |

A certificate is asked for at the first TLS connection that names the host
(SNI); a client connecting by IP address gets none.

⛔ **WebDAV with passwords is no longer served in the clear** on an address
other machines can reach. HTTP Basic is the password on every request and a
bearer token is as good as one, so such a configuration is refused, not
warned about. Serve it with `tls = true`, or — when TLS is terminated in front
of it, by a proxy — say so with `plaintext = true`. Loopback addresses, and a
server with nobody to authenticate, are unaffected. `fileshare check` says, per
protocol, what is encrypted and what is in the clear on purpose.

**NFS over TLS proves the machine, not the person.** `client_ca_file` makes a
client present a certificate from that authority — which host is mounting —
and RFC 9289 leaves user authentication as it was: the uid inside is still the
one AUTH_SYS claims. So a share that names who may use it is still refused over
NFS without a `kerberos` block. TLS is offered, not required: a client that
never asks for it is still served the open shares. SMB and SFTP do not take
`tls`: SMB 3 encrypts with its own keys, and SFTP is SSH.

## NFS, with identities from certificates

```hcl
serve "nfs" {
  tls            = true
  client_ca_file = "/etc/fileshare/bridge-x509-ca.pem"
  identity       = "certificate"
  crl_url        = "https://bridge.example.org/x509/crl"   # or crl_file; required
}
```

After an identity provider login, go-authn/bridge issues a short-lived X.509
client certificate naming the person the way FreeBSD's `rpc.tlsservd -u` reads
it — the SubjectAltName otherName `1.3.6.1.4.1.2238.1.1.1`, a UTF8String
`user@domain` ([draft-cel-nfsv4-rpc-tls-othername](https://www.ietf.org/archive/id/draft-cel-nfsv4-rpc-tls-othername-04.html)
describes it; its OIDs are not assigned yet) — and their groups as
`tag:go-authn.github.io,2026:group:…` URIs (RFC 4151). With `identity =
"certificate"`, a share that names people is served over NFS without kerberos:
every call on it must arrive over TLS, with a certificate that is **not in the
CRL** (fetched and kept failing closed, like the KRL above — a CRL past its
NextUpdate counts as unknown), that names exactly one person, somebody this
server admits the way it admits a token, and whom the share allows.

⛔ **What it cannot promise, and why RFC 9289 alone refuses to**: the server sees
a *connection's* certificate, and a Linux client attaches one to a **mount**
(`tlshd`, the keyring serial on `mount -o xprtsec=mtls,...`). Every user of that
mount acts as the person the certificate names. On a workstation one person
uses, that is exactly them; on a machine several people log into, it is whoever
mounted — use `sec=krb5` there. The certificate's lifetime bounds a revocation
only if the CRL is not reachable; with it, the next call after the CRL changes
is refused.

Measured with a real Linux client (kernel 6.17, ktls-utils 0.9, in
go-filesystems/nfs's CI):

- **MOUNT's MNT arrives in the clear**, whatever `xprtsec=` says: the kernel's
  mount client has no TLS. It is answered, and every NFS call made without TLS
  is then refused, so a person the share does not allow sees *access denied* at
  the first access rather than at `mount`. Nothing of a share crosses in the
  clear.
- `tlshd` checks this server's certificate against the **system** trust store
  only (it ignores `x509.truststore`), and wants the client's certificate and
  key owned by root, the key mode 600 — otherwise it fails with *gnutls: Error
  in the certificate (-43)*, naming neither.

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

## S3: a share is a bucket

```hcl
serve "s3" { addr = "0.0.0.0:9000" }
```

The fifth protocol, and the one that makes an image reachable from anything
that speaks object storage — a backup tool, a data pipeline, `rclone`, a
browser’s `fetch()`. Nothing mounts.

```
GET /                      the shares this person may use, as buckets
GET /photos?list-type=2    the files in that share, as keys
GET /photos/holiday.jpg    the file itself, Range and all
```

It is served over the **same per-user tree SFTP uses**, so a share alice may
not use is not a bucket alice can see — and the access rules are applied in
one place rather than copied into a second protocol.

**An access key is a user, and the secret key is their password.** SigV4
proves possession by computing an HMAC, so the directory must hold the
password: the same column as NTLMv2, and `check` prints it. An identity
holding only an NT hash serves SMB and **not** S3 — MD4 is not a secret an
HMAC can be built from.

⛔ The secret never leaves the directory. `Identity.Derive` runs the key
schedule over the password and hands back only the result, which is why there
is no `Password()` accessor anywhere in this program.

The object API itself is [`go-filesystems/s3`](https://github.com/go-filesystems/s3):
`ListBuckets`, `ListObjectsV2` with prefix and delimiter, `HeadObject`,
`GetObject` with `Range`. Costs **0.1 MB** — SigV4 is stdlib crypto.

## Not yet

**Writes over S3.** `PUT` and `DELETE` answer 403. The library can write, but
a share a person may only read has to refuse them at the same place SFTP
does, and that is not wired yet — refusing is better than a half-written
object. **Multipart upload** is refused by name, so a client falls back to a
single `PUT` rather than failing at the end of a 5 GB one.

## Licence

BSD-3-Clause.
