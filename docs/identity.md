# Serving each person under their own system identity: design

Status: **design, 2026-10-12, decisions completed 2026-10-18**. Nothing here is built yet.

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
| **Who starts a worker** | **A separate privileged launcher**, `fileshare launcher`, built like the existing `fileshare provisioner`. The front that parses the protocols holds **no** privilege, and `CAP_SETUID` never sits in the process that talks to strangers. |
| **NFSv3 `AUTH_UNIX`** | It **never** selects a worker. Under `AUTH_UNIX` the uid is the client's own claim (RFC 5531 §14: it "SHOULD NOT be used for services that permit clients to modify data"). Over NFS, a share requiring identity is served only under Kerberos. |
| **Which uids are refused** | **Configurable**: `min_uid` and `min_gid` (default 1000 for both), plus a `deny_uids` list. **uid 0 is refused whatever the configuration**, because a worker running as root is the one thing this design exists to prevent. That is the only rule that is not a setting. |

## The design: a worker per person, behind the protocols

The front still speaks the protocols and authenticates, as today, and holds no
privilege. For a directory share marked `identity = "system"`, it no longer
opens the tree itself. Instead it asks the **launcher** for that person's
**worker**: a process that runs as the person and opens the tree under their
identity. The front then forwards each filesystem operation to it. There is
one worker per uid, shared by all of that person's connections and protocols,
and it stops after a period with nothing to do.

```
client ──SMB/WebDAV/SFTP/S3/NFS──► front (no privilege; authenticates)
                                     │ 1. "a worker for alice, share photos"
                                     ▼    (unix socket, SO_PEERCRED: the front's uid only)
                                   launcher (root; resolves alice ITSELF; checks min_uid)
                                     │ 2. starts the worker, hands the front its socket (SCM_RIGHTS)
                                     ▼
front ◄──filesystem operations──► worker as alice (uid 1001, gid 100, groups 100,27)
                                     │  os.Root over /data/photos
                                     ▼
                                   kernel: permissions, ownership
```

## The launcher

It is the same binary in another role, `fileshare launcher`, the counterpart of
`fileshare provisioner`. It applies the same rules:

- **One client, identified by the kernel.** The front's uid is read with
  `SO_PEERCRED` on Linux and `LOCAL_PEERCRED` on macOS (`internal/peercred`,
  as for the provisioner). The BSDs need `getpeereid`, which `internal/peercred`
  does not have yet: adding it is part of phase 1. Anybody else, root included, is refused before a
  byte of the request is decoded.
- **A closed set of verbs**: start a worker, and stop one.
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
- **The worker's socket is handed to the front** over the launcher's socket,
  with `SCM_RIGHTS`. The launcher keeps no open file of the worker's.

**Why this and not something else.** The bibliography is
`localhost/_bibliography/fileshare-per-user-worker-identity-2026-10-12.md`.

- **Not a process per connection, as sshd does.** Only SSH gives one user per
  connection (RFC 4252 §5.3). SMB2 carries several users' sessions on one
  connection and picks the user per request by `SessionId` (MS-SMB2 §2.2.1.2,
  §3.3.1.7). HTTP and S3 authenticate every request (RFC 9110 §3.3). NFS
  carries the credential in every call (RFC 5531, RFC 1813 §1.5).
- **Not switching threads inside one root process, as Samba and NFS-Ganesha
  do.** It is Linux only (`setfsuid`), and both keep the saved uid at 0 on
  purpose, so a compromised worker can become root again. In Go, every
  goroutine the I/O path starts runs without the identity. And
  `syscall.Setuid` has changed the whole process since Go 1.16
  (`AllThreadsSyscall`).
- **A separate process drops privileges for good.** Go's
  `SysProcAttr.Credential` does setgroups, then setgid, then setuid in the
  child, and checks each step on Linux, FreeBSD, OpenBSD and macOS. That is
  the order CERT POS36-C requires and the checking POS37-C requires.

**What it costs.** One exchange over a local socket per filesystem operation,
and one process per person who is active.

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
- **It opens the trees itself, under its own identity, through `os.Root`.**
  A tree the person cannot enter is a refusal from the kernel, not from
  fileshare.
- **Its protocol is the go-filesystems interface, method for method**
  (`Filesystem`, `Opener`, `File`, `WritableFile`, …), encoded in the
  simplest way that does not allocate per byte: a length, a code, then
  arguments. On the front's side it appears as one more filesystem driver,
  `remotefs`, so a protocol server does not know it is talking to a worker.

## Resolving a person to a uid

Each person is resolved in this order, and the first answer counts:

1. **fileshare's configuration:** `user "alice" { uid = 1001, gid = 100, groups = [27] }`.
2. **The LDAP directory:** `uidNumber`, `gidNumber`, and the groups that list
   them in `memberUid`. This is go-authn/directory, which already reads that
   directory.
3. **`/etc/passwd` and `/etc/group`**, by name. With `CGO_ENABLED=0`, Go reads
   only these files on Linux and the BSDs, not NSS, sssd or winbind. A site
   whose accounts exist only in sssd goes through LDAP.

There are two further rules:

- A person known only to an identity provider (OIDC) has no uid. No standard
  claim carries one (OIDC Core §5.1), and fileshare does not guess from
  `preferred_username`. They are mapped through the directory, by name, or
  refused.
- **uid 0 is always refused**, and so is any uid below a configured minimum
  (`min_uid`, 1000 by default). An account that gets a worker as root is the
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

1. **The launcher, the worker, `remotefs`, and resolution from configuration
   and `/etc/passwd`, plus `getpeereid` in `internal/peercred` for the BSDs.
   SFTP and WebDAV.** Tested as root in CI (Linux, and the
   FreeBSD lane), with two real local accounts:
   - a file created by alice belongs to alice;
   - bob is refused by the kernel on a tree that is alice's alone;
   - a worker that could get root back fails its start;
   - the launcher refuses uid 0, a uid below `min_uid`, a peer that is not the
     front, and a request naming a share that does not exist.
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
