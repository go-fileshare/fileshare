# Serving each person under their own system identity: design

Status: **design, 2026-10-12, decisions completed 2026-10-18; the launcher is the parent process (privilege separation), 2026-10-18. Phase 1 (SFTP and WebDAV) is built, 2026-10-18**: see "What phase 1 built" at the end, which says where the code differs from what is written here first.

## What is asked

Once a person has authenticated, the process that reads and writes their
files runs **as them**: their uid, their primary gid, their supplementary
groups. The kernel then applies the permissions of the tree, and what they
create belongs to them. Today one fileshare process serves everybody under
one service account; fileshare decides who may do what, and the files it
creates belong to that account.

## Decisions

Taken by the project owner on 2026-10-12:

| | |
|---|---|
| **Platforms** | Unix: Linux, FreeBSD, OpenBSD and macOS. Windows later, by another mechanism (a logon token and `CreateProcessAsUser`). |
| **Shares** | **Directory shares only.** Inside a disk image, permissions are applied by fileshare's own driver, not by the kernel, so a system identity changes nothing there. |
| **Where uid and groups come from** | Three sources: fileshare's configuration, the LDAP directory (`posixAccount`: `uidNumber`, `gidNumber`; `posixGroup`: `memberUid`, RFC 2307), and `/etc/passwd` with `/etc/group`. |
| **A person with no uid** | **Refused** on the shares that require it. There is no shared fallback account. |

Taken by the project owner on 2026-10-18:

| | |
|---|---|
| **Who starts a worker** | **A separate privileged launcher.** The front that parses the protocols holds **no** privilege, and `CAP_SETUID` never sits in the process that talks to strangers. |
| **NFSv3 `AUTH_UNIX`** | It **never** selects a worker. Under `AUTH_UNIX` the uid is the client's own claim (RFC 5531 §14: it "SHOULD NOT be used for services that permit clients to modify data"). Over NFS, a share requiring identity is served only under Kerberos. |
| **Which uids are refused** | **Configurable**: `min_uid` and `min_gid` (default 1000 for both), plus a `deny_uids` list. **uid 0 is refused whatever the configuration**, because a worker running as root is the one thing this design exists to prevent. That is the only rule that is not a setting. |

## The design: a worker per person, behind the protocols

The front still speaks the protocols and authenticates, as today, and holds no
privilege. For a directory share marked `identity = "system"`, it no longer
opens the tree itself. Instead it asks the **launcher** for that person's
**worker**: a process that runs as the person and opens the tree under their
identity. The front then forwards each filesystem operation to it. There is
one worker per person and share, shared by all of that person's connections
and protocols, and it stops after a period with nothing to do.

```
fileshare serve (as root)  =  the LAUNCHER: binds the listeners, reads the configuration,
   │                          speaks to nobody on the network
   │ starts the front as the service account, with the listeners
   │ and one end of a socketpair (ExtraFiles)
   ▼
front (no privilege) ◄── client: SMB/WebDAV/SFTP/S3/NFS; authenticates
   │ 1. over the socketpair: "a worker for alice, share photos"
   ▼
launcher: resolves alice ITSELF, checks min_uid, starts the worker,
   │      hands the front the worker's socket (SCM_RIGHTS)
   ▼
front ◄──filesystem operations──► worker as alice (uid 1001, gid 100, groups 100,27)
                                     │  os.Root over /data/photos
                                     ▼
                                   kernel: permissions, ownership
```

## The launcher

This is OpenSSH's privilege separation: a privileged **monitor** whose only
peer is the unprivileged child it started (bibliography §1a), and the shape
`--isolate` already has, where the parent binds the listeners and re-executes
itself, passing them down with `ExtraFiles`.

- **The launcher is the parent process.** `fileshare serve`, started as root,
  becomes the launcher. It binds the listeners, so a privileged port needs no
  privilege in the front. Then it starts the front as the configured service
  account (`SysProcAttr.Credential`, groups cleared), handing it the listeners
  and **one end of a socketpair**. The launcher never parses a network
  protocol.
- **No name, so no stranger.** The socketpair exists only in the two
  processes. Nothing else can connect to it, so there is no socket path to
  protect and no peer to identify. Identifying the peer would have needed
  `SO_PEERCRED`, `LOCAL_PEERCRED`, `SO_PEERCRED` (OpenBSD) and `LOCAL_PEEREID`
  (NetBSD), one per system. golang.org/x/sys exposes only the first two
  cleanly, and OpenBSD does not let a program make the raw system call itself.
- **A closed set of verbs**: one, start a worker. A worker stops when the
  front closes its socket; the launcher keeps nothing to stop it with.
- **A request never carries a uid or a path.** It names a **person** and a
  **share** from the configuration. The launcher resolves the person to a uid,
  a gid and groups **itself** (see "Resolving a person to a uid"), applies
  `min_uid`, `min_gid` and `deny_uids`, and refuses uid 0. The tree comes from
  the share's `directory`.

  So a front that has been taken over can, at worst, ask for a worker for a
  person who exists and whose uid is allowed, on a share that exists. It
  cannot ask for root, for a system account below `min_uid`, or for an
  arbitrary directory. That is the limit of what separating the launcher buys:
  the front still decides *who* has authenticated, and the launcher cannot
  check that for it.
- **The worker's socket is handed to the front** over the socketpair, with
  `SCM_RIGHTS`. The launcher keeps no open file of the worker's.
- **If the front exits, the launcher exits with it**, with the front's
  status, and a service manager restarts the pair. The workers exit too:
  their sockets were the front's. If the launcher dies, the front gets no
  new workers. It fails those requests; it never serves them as itself.

## The worker

- It is the same binary, started as `fileshare worker`, with
  `SysProcAttr.Credential{Uid, Gid, Groups}`.
  - `Groups` is always set, possibly empty: an empty list clears root's
    groups. `NoSetGroups` is never set, because it keeps root's.
  - `Setsid` puts the worker in its own session.
- **Before it serves anything, it checks that the drop happened.**
  - `setuid(0)` must fail.
  - `getgroups` must be exactly the expected list.
  - On Linux it also sets `PR_SET_NO_NEW_PRIVS`, and `PR_SET_DUMPABLE` stays
    off (the kernel resets it when the uid changes).
- **It inherits nothing it should not have.** Its only open file is its end of
  the socket (`ExtraFiles`); every other descriptor is opened `O_CLOEXEC`
  (CWE-403). It never sees the TLS keys, the passwords or the tokens.
- **It opens the tree itself, under its own identity, through `os.Root`.**
  A tree the person cannot enter is a refusal from the kernel, not from
  fileshare.
- **Its protocol is the go-filesystems interface, method for method**
  (`Filesystem`, `Opener`, `File`, `WritableFile`, …), encoded in the
  simplest way that does not allocate per byte: a length, a code, then
  arguments. On the front's side it appears as one more filesystem driver,
  [go-filesystems/remote](https://github.com/go-filesystems/remote), so a
  protocol server does not know it is talking to a worker.

## Resolving a person to a uid

Each person is resolved in this order, and the first answer counts:

1. **The directory fileshare already reads** (go-authn/directory), when it
   carries `uidNumber` and `gidNumber`: a `user` block's
   `attributes = { uidNumber = "1001", gidNumber = "100" }`, an LDAP source
   with `attributes = ["uidNumber", "gidNumber"]`, an SQL source's
   `users_attributes` query. The supplementary groups are the groups the
   person names (`memberOf`) and those that list them (a `group` block's
   `members`, `memberUid`), each by its `gidNumber`; a group without one is
   no system group.
2. **`/etc/passwd` and `/etc/group`**, by name. With `CGO_ENABLED=0`, Go reads
   only these files on Linux and the BSDs, not NSS, sssd or winbind. A site
   whose accounts exist only in sssd goes through LDAP.

There are two further rules:

- A person known only to an identity provider (OIDC) has no uid. No standard
  claim carries one (OIDC Core §5.1), and fileshare does not guess from
  `preferred_username`. They are mapped through the directory, by name, or
  refused.
- **uid 0 is always refused**, and so are gid 0, `(uid_t)-1`, any uid below
  `min_uid` and any primary gid below `min_gid` (1000 by default), and
  `deny_uids`. A supplementary group below `min_gid` is dropped, and said. An account that gets a worker as root is the
  one thing this design must never produce.

## Per protocol

| protocol | where the person is known | what changes | where |
|---|---|---|---|
| SFTP | per connection, after authentication | the connection's tree (`unionFS`) takes the worker's filesystem for identity shares | fileshare |
| WebDAV | per request (`byUser`) | a handler per person over their worker | fileshare |
| S3 | per request (SigV4 access key) | the server is chosen by access key before dispatching | fileshare |
| SMB | per SMB2 session (`SessionId`) | a share opens its filesystem per session, by user | **go-filesystems/smb**: a share option that gives a filesystem per user |
| NFS | per call, under Kerberos only | the filesystem is chosen per credential | **go-filesystems/nfs** |

## Phases

1. **The launcher as the parent, the worker, `remotefs`, and resolution from
   configuration and `/etc/passwd`. SFTP and WebDAV.** Tested as root in CI (Linux, and the
   FreeBSD lane), with two real local accounts:
   - a file created by alice belongs to alice;
   - bob is refused by the kernel on a tree that is alice's alone;
   - a worker that could get root back fails its start;
   - the launcher refuses uid 0, a uid below `min_uid`, and a request naming
     a share that does not exist;
   - the front runs as the service account, with no privilege, whatever
     started the launcher.
2. **LDAP resolution** (`posixAccount`, `memberUid`) and **S3**.
3. **SMB**, which needs a filesystem per session in go-filesystems/smb.
4. **NFS under Kerberos**, which needs a filesystem per credential in
   go-filesystems/nfs.
5. **Windows**, by a logon token, if it is still wanted.

## Not in this design

- Image shares (see the decisions above).
- Quotas: they come for free, since the kernel counts a user's files against
  their uid. That is measured, not built.
- ACLs beyond Unix permissions: the kernel applies whatever the tree carries,
  and fileshare neither reads nor writes them.

## What phase 1 built

Built on 2026-10-18 (`internal/account`, `internal/launch`, `identity*.go`,
`workerpool.go`), and where it differs from the text above:

- **Configuration.** `identity = "system"` on a directory share, and a
  top-level `identity { service_user, min_uid, min_gid, deny_uids, idle }`
  block. `check` refuses such a share over a protocol that cannot serve it
  yet, an image share, a share without the block, and a configuration that
  declares no people.
- **The processes.** `fileshare serve`, as root, binds the listeners, starts
  `fileshare serve-front` as `service_user` (with that account's own groups,
  never gid 0) with the socketpair on descriptor 3 and the listeners from 4,
  and answers its requests. A descriptor is taken only when the parent says
  in the environment that it passed one, and only if it is a socket: taking
  fd 3 on faith closed the Go runtime's own poller in a front run by hand.
- **One worker per person and share**, not per uid. A pool in the front
  counts its users, shares it across connections and protocols, closes it
  after `idle` (2 minutes by default), and replaces one that died.
- **SFTP** takes a worker per session at login and releases it when the
  connection ends: `sftp.Server` never closes the tree, so the end of the SSH
  connection is the only signal. **WebDAV** takes one per request, and keeps
  its handlers on the worker, so a lock outlives the request that took it.
- **Refusals.** A person the launcher refuses gets 403 over WebDAV and loses
  the share from their SFTP tree; a worker that cannot start gives 503. The
  reason goes to the log, never to the client. A person the provider vouches
  for gets a worker only under `local_names`.
- **Tested** without root by a fake launcher (`identity*_test.go`: per person
  trees, release at disconnect, the pool's sharing and idling), and as root
  with real accounts by `hack/identity-e2e.sh` in CI, on Linux, FreeBSD and
  OpenBSD.
- **Not yet:** a share added or changed while serving is refused by the
  launcher until a restart; `--isolate` does not go with it; the launcher
  reads the whole directory at each worker's start, which is cheap for a
  file or SQL and not for a large LDAP tree.
