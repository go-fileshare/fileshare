# Passwordless access from macOS and Linux

Status: bibliography and design note, 2026-11-23. Nothing here is implemented.

The mésocentre's path is: passkey at go-authn/bridge, a TGT minted by kdcd
(`authn-kinit`, go-authn/kinit v0.3.4), then Kerberos. No password anywhere.
The KDC is reachable only through MS-KKDCP on HTTPS 443; port 88 is never
exposed. Windows is covered by SMB 3.1.1 over QUIC (UDP 443). This note asks
what a **native** macOS (15/26/27) or Linux (Debian 13, Ubuntu 24.04/26.04,
Fedora) client can do instead, and above all evaluates a client-side
loopback gateway (§6). NFS stays supported, scoped to on-site and stable
links (§5).

Every claim cites what was opened. **[V]** = read in source or measured here;
**[I]** = inference, not tested end to end. A row with only [I] is a test to run,
not a fact.

## Summary

| Path | macOS | Linux | Ports exposed | Server work in fileshare |
|---|---|---|---|---|
| 1. SMB 2/3 over TCP 445, Kerberos | **native** (`mount_smbfs`, Finder) [V man, I e2e] | **native** in GNOME Files (gvfs, no root) [V src]; `mount.cifs sec=krb5` (root) [V man] | **445/tcp** | none (SMB+Kerberos is there, README "SMB with Kerberos") |
| 2. KKDCP for service tickets | **native**: Apple Heimdal speaks `kkdcp://` [V src, V parse] | **native**: MIT krb5 ≥ 1.13 `kdc = https://…/KdcProxy` [V docs] | 443 (already) | none; `authn-kinit` must land the TGT in the OS cache (§2.3) |
| 3. WebDAV + Negotiate | plausible via CFNetwork, Finder still prompts [V src, I e2e] | gvfs ≥ 1.45.2 [V src]; davfs2 via neon `NE_AUTH_ALL` [V src, I build flag]; KDE kio [not verified] | **443** | **add SPNEGO/Negotiate to WebDAV** (accepts Basic and Bearer today) |
| 4. SFTP + SSH certificate | needs an install (macFUSE or FUSE-T + sshfs); no Finder SFTP | sshfs packaged; gvfs has sftp | 22 or any | none (provider and OpenPubkey certs accepted, README ~404-451) |
| 5. NFS + krb5 | native `mount_nfs sec=krb5` [V man]; on site and stable links only (§5) | native, root [V man]; same scope | 2049/tcp | none for that scope; not a road-warrior path |
| 6. Loopback gateway (theca pattern) | works with go-fileshare/automount, no dialog [V theca, automount] | gvfs, no root [V automount on Ubuntu 24.04] | 443 only | **client** to build: a remote-backed filesystem; nothing on the server for WebDAV+Bearer |

**Recommendation** (details at the end): on both systems, **WebDAV on 443 with
Negotiate**, added to fileshare, as the native passwordless path; SMB on 445
with Kerberos as the high-fidelity path where a site may open 445 (inside a VPN
or campus network); a loopback gateway (§6) only if Finder's WebDAV client
proves unusable, since it is a product to maintain.

## 1. SMB over TCP 445 with Kerberos

**macOS.** `mount_smbfs //[domain;][user[:password]@]server[/share] path`
(`man mount_smbfs`, local, macOS 27.2.1) [V]. `nsmb.conf(5)` sets
`minauth=kerberos`: "Kerberos - NTLMv2, NTLM, LM, and plain-text password
authentication are not attempted"; at `ntlmv2`, "Kerberos authentication is
attempted if a Kerberos token can be obtained" (man_nsmb lines 143-151) [V].
So the client takes Kerberos whenever the default credential cache holds a TGT
for the realm that `[domain_realm]` maps the server's name to (krb5.conf(5),
`[domain_realm]`, local) [V man]. Nothing in the client is AD-specific in what
was read; a non-AD realm served by kdcd should work, provided the server is
reached **by DNS name** (the ticket is for `cifs/<name>`) [I]. fileshare
accepts `cifs/<host>@REALM` from its keytab and refuses NTLM with
`ntlm = false` (README.md:187-236) [V].

**Linux.**
- `mount.cifs -o sec=krb5` calls `cifs.upcall`, which reads the
  initiating process's `$KRB5CCNAME` unless uid 0 (then the default cache) or
  `-E`, and takes the host part of the SPN from the UNC (cifs.upcall(8), Debian
  trixie) [V]. `mount(2)` is root: a desktop user needs an fstab entry or sudo.
- **gvfs (GNOME Files) needs no root**: `gvfsbackendsmb.c` sets
  `smbc_setOptionUseKerberos(1)` and `UseCCache(1)`, and its first round is
  "Kerberos-only. Only if this fails do we enable" fallback (lines 465-582)
  [V src, GNOME/gvfs main]. libsmbclient uses the system Kerberos library [I:
  depends on the distribution's Samba build; Debian and Fedora link MIT
  krb5, not verified here].

**Ports:** 445/tcp must be reachable. That is the cost of this path.

## 2. Service tickets through MS-KKDCP (port 88 closed)

### 2.1 Linux: MIT krb5

"Add support for accessing KDCs via an HTTPS proxy server using the MS-KKDCP
protocol" — MIT krb5 1.13 major changes (web.mit.edu/kerberos/krb5-1.13) [V].
Syntax `kdc = https://server.fqdn/KdcProxy`, CA via `http_anchors` when not in
the system store (MIT doc `admin/https.html`, 1.22.3) [V]. Every listed
distribution ships far later than 1.13. So on Linux the TGS-REQ for `cifs/`,
`HTTP/` or `nfs/` goes over 443 with no client code of ours [V docs, I e2e].

### 2.2 macOS: Apple's Heimdal speaks KKDCP; upstream Heimdal does not

Apple's Heimdal (apple-oss-distributions/Heimdal, tag Heimdal-710.100.4) [V src]:
- `lib/krb5/krbhst.c:1143-1146`: a `kdc` entry starting `kkdcp://` gets
  `KRB5_KRBHST_KKDCP`, default port 443.
- `lib/krb5/send_to_kdc.c:545-574`: builds `https://host[:port]/path` and
  calls `_krb5_kkdcp_request`.
- `lib/krb5/kkdcp.m`: encodes `KDC_PROXY_MESSAGE` (the MS-KKDCP structure),
  POSTs it with `NSURLSession`, HTTP/1.1 only (line 73), decodes the reply.
- `use_kkdcp_rfc_format` (default TRUE, send_to_kdc.c:878-882) prefixes the
  4-byte length as MS-KKDCP does; documented in krb5.conf(5) [V man].
- `kkdcp.m` is present at tags Heimdal-660.100.7, -689 and -710.100.4, absent at
  -520.270.1 and -564.0.3 (`gh api …/contents/lib/krb5/kkdcp.m?ref=`) [V]. Which
  macOS each tag ships in was not checked; 689/710 are recent.
- `krb5.conf(5)` on macOS documents only `udp`, `tcp`, `http` as `kdc`
  services: **`kkdcp://` is undocumented** but parsed.

**Measured on this Mac (macOS 27.2.1, 26B131):** with a krb5.conf holding
`kdc = kkdcp://kdc.example.org/KdcProxy`,
`KRB5_CONFIG=… kcc kdc EXAMPLE.ORG` prints that entry back
(`kdc = kkdcp://kdc.example.org/KdcProxy  # source config`) [V]. No ticket was
requested (no test KDC reachable from this session): **the end-to-end TGS over
kdcd's `/KdcProxy` is the first test to run.** Caveat [I]: system daemons
(NetAuthAgent, gssd) do not inherit `KRB5_CONFIG`; the realm must be in
`/etc/krb5.conf` (or Apple's Kerberos preferences).

Upstream Heimdal (heimdal/heimdal master `lib/krb5/krbhst.c`) defines
`KD_SRV_KKDCP` but parses only `http://`/`http/` (lines 47, 100, 272) — a
non-MS HTTP transport, not MS-KKDCP [V src]. Kerberos stacks built on upstream
Heimdal (e.g. a Samba built with its bundled Heimdal) do not get KKDCP [I].

### 2.3 What `authn-kinit` must do on macOS and Linux

go-authn/kinit's README: "On other systems it runs, fetches, and writes the
KRB-CRED with `--cred-file`; loading a ticket into a logon session is Windows
only" (README.md:25-27) [V]. Since both OSes fetch service tickets themselves
over KKDCP (2.1, 2.2), **only the TGT has to reach the OS cache**; there is no
need for `authn-kinit` to fetch `cifs/` itself.
- **macOS:** Apple's `kcc` has `copy_cred_cache [--krbtgt-only] … <from> <to>`
  (kuser/kcc-commands.in:236-276; `kcc copy_cred_cache --help` locally) [V].
  So: write a `FILE:` ccache (v4 format) from the KRB-CRED, then
  `kcc copy_cred_cache FILE:/path API:` (or the KCM default) and `kswitch`
  [I]. In process, Heimdal's `krb5_cc_store_cred` on `krb5_cc_default` does the
  same through cgo [I]; a pure-Go writer cannot reach KCM without its private
  Mach IPC.
- **Linux:** write a ccache where `default_ccache_name` points (FILE: or
  KEYRING:; KEYRING needs the keyctl syscalls, FILE is pure Go) [I].
- Proposed issue on go-authn/kinit: `--ccache` writing a ccache, plus a macOS
  import via `kcc copy_cred_cache`.

## 3. WebDAV with Negotiate (SPNEGO)

fileshare's WebDAV accepts HTTP Basic or an OIDC bearer, and its challenge
offers both (README.md:153, 646-648) [V]. No Negotiate.

**macOS (webdavfs, tag webdavfs-403.100.1)** [V src]:
- The auth cache asks CFNetwork for the scheme (`CFHTTPAuthenticationCreateFromResponse`,
  `webdav_authcache.c:487`). When `CFHTTPAuthenticationRequiresUserNameAndPassword`
  is false the request proceeds with no mount credentials (lines 329-389), and
  `CFHTTPMessageApplyCredentials` is called with whatever is held (633). The
  SDK exports `kCFHTTPAuthenticationSchemeNegotiate` and `…Kerberos` since
  10.5 (`CFHTTPMessage.h:102-117`) [V header].
- The NetFS plugin declares `kNetFSSupportsKerberosKey = false`
  (`WebDAVPlugin/WebDAV_Mount.c:908`) [V]: Finder's "Connect to Server" is told
  WebDAV does not do Kerberos, so it will likely show its login sheet first [I].
- Verdict: `mount_webdav https://…` with a Negotiate-only challenge has a code
  path that works with a ticket and no password [I]; Finder's UI path is doubtful.
  Test both. `mount_webdav(8)` mentions only Basic/Digest and "additional
  authentication methods … supported by the CFNetwork framework" (10.4) [V man].

**Linux:**
- **gvfs-dav**: `soup_session_add_feature_by_type(…, SOUP_TYPE_AUTH_NEGOTIATE)`
  (`gvfsbackenddav.c:2405`), "dav: Add support for Negotiate and NTLM
  authentication" in gvfs 1.45.2 (NEWS) [V]. All target distributions are newer.
- **davfs2**: `ne_add_server_auth(session, NE_AUTH_ALL, auth, "server")`
  (src/webdav.c, savannah) [V]; neon's `NE_AUTH_ALL` is "all protocols supported
  by the library" and `NE_AUTH_NEGOTIATE` uses GSSAPI (ne_auth.h:84-122) [V];
  whether the distribution's libneon is built with GSSAPI was not checked [I].
  go-filesystems/webdav already documents a davfs2 listing bug (README:293) [V].
- **KDE kio**: not verified (the GitHub code search returned nothing).

**Server work:** an SPNEGO acceptor on WebDAV: `WWW-Authenticate: Negotiate`
next to Basic/Bearer, accept `HTTP/<host>@REALM` from the existing keytab, take
the name from the ticket as SMB does, mutual-auth token in the reply. go-filesystems/smb
already has a Kerberos acceptor (SPNEGO, `1.2.840.48018.1.2.2`, smb
README:236-281) [V] to share, not copy. **Ports: 443 only.**

## 4. SFTP with an SSH certificate

fileshare accepts provider-CA and OpenPubkey certificates over SFTP
(README.md:404-451) [V]; the cert comes from the passkey login, nothing else.
- **macOS:** no SFTP in Finder or the kernel [I: no `mount_sftp`/`mount_ssh`
  in `/sbin`, only `mount_smbfs`, `mount_webdav`, `mount_nfs` checked]. Needs
  macFUSE (a closed-source **kernel extension**, macfuse README:4,27; v5.5.0,
  2026-10-17) or **FUSE-T** ("kext-less … uses NFS v4 local server",
  "SMB and FSKit backends", `brew install … sshfs-fuse-t`; fuse-t README:3-42) [V].
- **Linux:** sshfs (FUSE, user mount) and gvfs sftp [I: packaging not checked].
- **Ports:** 22 or another TCP port; not 443 unless multiplexed.
- Verdict: works, but **not native on macOS**.

## 5. NFS: on site and over stable links, not for road warriors

NFS remains a supported fileshare protocol. Its scope is on-site clients and
stable site-to-site links, with `sec=krb5`, `krb5i` or `krb5p`. It does not
fit the road-warrior case: laptops reaching the share over a WAN or a VPN.
This was decided on 2026-11-23 and is not researched further. The reasons,
from what was read:

- **Latency:** every metadata operation costs at least one round trip.
- **Link drops:** a hard mount leaves processes waiting until the link comes
  back, and nfs(5) warns that a "soft" timeout "can cause silent data
  corruption".
- **Sleep and roaming:** a client that does not renew its lease in time loses
  its locks and delegations (RFC 8881 §1.8.4; nfs(5)).
- **Server side:** fileshare's NFS server speaks NFSv3 today
  (go-filesystems/nfs README:9). The NFSv4.1 sessions that would soften link
  drops are not in it.

The clients that fit the scope already have what they need. macOS `mount_nfs(8)`
documents `sec=krb5|krb5i|krb5p` and NFSv4 "with a minor version of zero or
one", default 0 (lines 108-164). Linux nfs(5) documents `sec=krb5*` and
versions 3 to 4.2. Port: 2049/tcp. A side finding: go-filesystems/nfs README:112 still says RPCSEC_GSS is
"not implemented", while line 303 documents `sec=krb5`.

## 6. A client-side gateway: loopback SMB in front of the remote share

### What exists [V]
- go-theca/theca `serve --mount` (README:215-251): go-filesystems/smb on a
  loopback address, one random account per run (`theca-` + 8 chars, random
  password, never printed; random because "macOS replays a stale credential for
  a fixed name on 127.0.0.1"), `RequireSigning`, mounted by
  go-fileshare/automount with no dialog. Measured on macOS 27: SMB 3.1.1 signed
  AES-128-GMAC. Linux and Windows not measured with theca.
- go-fileshare/automount (README): macOS through NetFS `NoUI`, `AllowLoopback`
  for 127.0.0.0/8; Linux through gvfs, answering `AskPassword` in process;
  **measured on Ubuntu 24.04, gvfs 1.54.4**, headless; credentials never in
  argv, env or URL.
- go-filesystems/smb serves any `filesystem.Filesystem`; byte-range locks
  enforced; change notification only for changes through this server;
  **"streams, oplocks and leases: not yet"** (smb README:103-108).
- go-filesystems/remote: a `filesystem.Filesystem` across any
  `io.ReadWriteCloser`, every optional interface, hostile-peer limits
  (32 MiB frames, 64 in flight, 4096 files), ~0.3 GB/s on a socketpair under
  load (remote README). It is fileshare's front↔worker IPC (docs/identity.md).

### What is missing [V by absence]
go-filesystems/webdav, /sftp, /s3 and /smb are **servers** (`webdav.New(fsys)`,
`s3.New(fsys, …)`, sftp README "an `sftp://` *client* transport may one day live
in go-streamkit", line 148). A code search for `PROPFIND` across go-filesystems
finds only a comment in /interface. **No go-filesystems client driver exists.**
To build, in order of cost:
1. **A WebDAV client driver** (`filesystem.Filesystem` over PROPFIND/GET with
   Range/PUT/MOVE/DELETE/MKCOL/LOCK) with `Authorization: Bearer`. fileshare
   already accepts the bearer and serves chunked PUTs with `Content-Range`
   (README:173-178). **No server work.** Ports: 443.
2. **An SFTP client driver** over go-filesystems/ssh with the provider/OpenPubkey
   certificate. Server unchanged. Port: SFTP's.
3. **`remote` over an authenticated TLS stream** on 443: least client code (the
   driver exists), but a new, authenticated, versioned endpoint on the server;
   `remote` was designed for a socketpair, has no auth and no reconnect.
4. **SMB-over-QUIC client**: largest.

The agent: passkey login → bearer (refreshed by `authn-bridge token`, README:452)
→ driver → `smb.Server` on 127.0.0.1:random with `RequireSigning` and a random
account → `automount.Mount`. FUSE-T is the same architecture (a local NFS/SMB
server the OS mounts, fuse-t README:7-22) [V], which shows the pattern holds
on macOS without a kext.

### Semantics [I unless cited]
- **Locks:** SMB byte-range locks would be enforced in the gateway only, i.e.
  per machine; two machines would not see each other's locks unless the driver
  maps them to WebDAV `LOCK` (whole-file, exclusive/shared write).
- **Caching:** without oplocks/leases (smb README:108) the macOS client caches
  little: consistent, but every `stat` is a round trip to the gateway; the
  gateway must cache (attributes with a short TTL, directory listings, a read
  cache by ETag) or every Finder metadata storm becomes a WAN round trip.
- **Rename:** WebDAV `MOVE` with `Overwrite:` is atomic per resource on
  fileshare's side; a directory rename is one MOVE.
- **mtime:** settable over SMB (`SET_INFO` → `Chtimes`, smb README:89); over
  WebDAV needs `PROPPATCH getlastmodified` support in fileshare [not checked].
- **Large files:** GET with `Range` for reads; writes need chunked PUT (exists)
  and a temp+MOVE to stay atomic.
- **Link drop / VPN change:** the loopback mount never drops (the OS sees a
  local server), which is the point; the gateway must decide what a call does
  while 443 is unreachable: block with a bound and return `STATUS_IO_TIMEOUT`,
  never succeed a write it could not send. A write-back cache offline is a sync
  engine, out of scope.
- **Performance:** no number found for macOS `smbfs`→loopback throughput;
  theca's 7.6→28.8 MiB/s (README:255-259) is bound by its journal's fsyncs, not
  by SMB. To measure before committing to it, as fileshare's
  `TestThroughputAgainstTheHost` does per protocol (README:2100-2108).

### Security
- A loopback port is reachable by **every local user**; the random per-run
  account and required signing are what keep another user out [V theca]. A
  password brute force against a random 8+-char name and random password over
  signed SMB is not practical; still add `MaxPreAuthPerSource` (exists, smb
  README:97) and bind to a per-user address if the OS permits.
- On Linux gvfs exposes the mount under `/run/user/<uid>/gvfs` for that user
  [I]; `mount.cifs` to loopback needs root and is system-wide: use gvfs.
- The bearer/cert lives in the agent's memory only; the gateway is a confused
  deputy for anyone who gets into the loopback session.

### Compared
Native WebDAV+Negotiate needs server work and Finder may still prompt; the
gateway needs client work and gives SMB semantics with no prompt on both OSes,
on 443 only, with **no server change** (option 1). It is the strongest fallback.

## Recommendation

Under the no-password rule, without 445:
1. **Both OSes, TGT:** extend `authn-kinit` to write the TGT into the OS cache
   (macOS: FILE ccache + `kcc copy_cred_cache` into the default cache; Linux: the
   `default_ccache_name` cache), and ship a krb5.conf with
   `kdc = kkdcp://kdc…/KdcProxy` (macOS) / `kdc = https://kdc…/KdcProxy`
   (Linux). First test: `kgetcred`/`kvno HTTP/fs…` over kdcd's KKDCP.
2. **fileshare: Negotiate on WebDAV** (443), sharing smb's acceptor. Linux
   gvfs-dav works with it [V src]; macOS `mount_webdav` likely, Finder doubtful.
3. **If Finder prompts or WebDAV is too slow:** the loopback gateway of §6 with
   a WebDAV+Bearer client driver: no server change, SMB semantics, no dialog.
4. **Where 445 may be opened** (campus, VPN): SMB with Kerberos is native on
   both and already served; gvfs needs no root.
5. **Not:** SFTP for Finder users (needs FUSE), NFS for road warriors (it stays the on-site and site-to-site path, §5).

## Sources opened

- fileshare README.md (this tree), docs/identity.md
- go-authn/kinit README.md (main)
- apple-oss-distributions/Heimdal: lib/krb5/krbhst.c, send_to_kdc.c, kkdcp.m,
  kuser/kcc-commands.in, tags
- heimdal/heimdal: lib/krb5/krbhst.c
- apple-oss-distributions/webdavfs: mount.tproj/webdav_authcache.c,
  WebDAVPlugin/WebDAV_Mount.c
- macOS 27.2.1 man pages: mount_smbfs, nsmb.conf, mount_webdav, mount_nfs,
  krb5.conf; CFNetwork SDK CFHTTPMessage.h; `kcc kdc`, `kcc copy_cred_cache`
- MIT krb5: web.mit.edu/kerberos/krb5-1.13, krb5-latest admin/https.html
- cifs.upcall(8) (Debian trixie), nfs(5) (man7.org)
- GNOME/gvfs: daemon/gvfsbackenddav.c, daemon/gvfsbackendsmb.c, NEWS
- davfs2 src/webdav.c (savannah); notroj/neon src/ne_auth.h
- go-filesystems: remote, smb, webdav, sftp, s3, nfs, ssh READMEs
- go-theca/theca README; go-fileshare/automount README
- macos-fuse-t/fuse-t README; macfuse/macfuse README and latest release
- RFC 8881 §1.8.4
