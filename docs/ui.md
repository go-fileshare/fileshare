# Two UIs for many servers: design

Status: **design, agreed 2026-10-09**. Built so far: phase 1 (fileshare
v0.28.0), phase 2 (go-fileshare/portal v0.1.0) and phase 3, in a browser and
natively (go-fileshare/console v0.3.0), and phase 4 in a browser
(go-fileshare/explorer v0.1.0). Each phase below says what is done.

## What is asked

- **Two separate UIs**: an **admin console** (shares, grants, volumes, server
  state — what the admin API exposes) and a **file explorer** for the people
  the shares are for.
- Each written once, in Go with **go-widgets**, and run **natively** (a window)
  **and in a browser** (wasm on a `<canvas>`).
- **One deployment drives several fileshare servers**, clustered or federated
  across organisations, possibly behind an HA web tier.
- **OIDC** for who is who.

## Decisions, and why

The sources are in the bibliography kept beside the workspace
(`_bibliography/fileshare-ui-multi-server-2026-10-09.md`, every quote checked
against the raw text).

| decision | chosen | because |
|---|---|---|
| where browser tokens live | a **BFF** — a small Go server between the browser and the fileshare servers; the browser holds only an HttpOnly session cookie | draft-ietf-oauth-browser-based-apps (-27) recommends a BFF for applications that handle personal data, which a file explorer does, and calls the browser-only pattern "not recommended" for them |
| wire protocol | **Connect** (connect-go): one handler serves gRPC, gRPC-Web and Connect | Go compiled to wasm cannot speak native gRPC — `net/http`'s js transport has no trailers; connect-go's only dependency outside the standard library is protobuf, already present; existing gRPC clients keep working |
| one token, many servers | **one audience per server** (or per cluster); the BFF holds a token per server | RFC 9068 makes `aud` required and each resource server must refuse a token that does not name it; RFC 8707 warns that a token for several audiences can be replayed by any of them to the others |
| federation | a fileshare server accepts a **list of issuers**, each with its discovery, keys and audience; a person is **(issuer, sub)** | `sub` is unique per issuer only; R&E identity reaches OIDC through proxies (SATOSA, Keycloak, CILogon) and OpenID Federation 1.0 is final (2026-02-17) |
| browser host | go-widgets/window's **browser-tab backend** (window v0.87.0) | one `w.Run(root)` natively and in an ordinary tab, no compositor, no cross-origin isolation, so the wasm is served as static files from the BFF |

## The pieces

```
 browser (wasm, canvas)          native app (window)
        │ cookie                       │ own OIDC (PKCE, loopback redirect)
        ▼                              │
   ┌─────────┐  Connect + per-server   │  Connect, token for that server
   │   BFF   │──────── tokens ─────────┼──────────────┐
   └─────────┘                         ▼              ▼
   (stateless: N copies       fileshare A ... fileshare N
    behind the HA tier)       (admin API: Connect; WebDAV for files)
```

- **fileshare** — the admin API also served over Connect, on a TCP listener
  with TLS; OIDC bearer tokens checked against a list of issuers with per-issuer
  audiences; each issuer block names the subjects and groups that may call it
  (`admin { web { issuer "<url>" { audience; subjects; groups } } }`, see the
  README). The unix socket and mutual TLS stay as they are.
- **BFF** ([`go-fileshare/portal`](https://github.com/go-fileshare/portal)) — OIDC authorization code with
  PKCE as a confidential client; the session in an encrypted cookie so that any
  copy can serve any request (no shared state, so HA is a matter of running
  several); per-server tokens (audience-restricted, by RFC 8707 resource
  indicators where the IdP supports them, by RFC 8693 token exchange across
  organisations); serves the two wasm UIs and proxies their Connect calls and
  the explorer's WebDAV.
- **admin console** ([`go-fileshare/console`](https://github.com/go-fileshare/console)) and **file explorer**
  (`go-fileshare/explorer`, to create) — go-widgets applications in the MVVM
  shape of go-widgets/app-template: a ViewModel that holds every piece of state
  as `mvvm` observables and knows no widget, a View bound through `mvvmtk`, CI
  gated by `mvvmlint` and `bricolint`. One `main.go` per target is all that
  differs: `window.Open` + `w.Run(root)` both ways.

## Constraints the sources impose

- **Uploads are chunked.** Streaming request bodies need `duplex:"half"` and
  HTTP/2 and exist in Chrome only, and Go's wasm `net/http` reads a request body
  whole before sending it. The explorer uploads in pieces: an empty PUT, then
  each piece appended where the last ended, then a MOVE to the real name.
  fileshare's WebDAV could only *patch* inside a file until go-filesystems/webdav
  v0.6.0 (fileshare v0.29.0), which appends a range that starts exactly at the
  end. Before, an upload in pieces was 416 at its first piece.
- **The root of a server is a collection.** The explorer opens a server on the
  shares the person may use, with a PROPFIND of `/`. fileshare answered every
  method at `/` with its HTML page until v0.29.0; it now answers PROPFIND there
  with the shares (207). Found by the explorer's browser test against the real
  binary; the stand-in portal had listed them all along.
- **The wasm is a few megabytes.** Measured: the go-widgets template alone is
  2.8 MB gzipped, and the console as built is 5.4 MB, once fileshare's
  generated package is replaced by messages and a Connect client without gRPC.
  That package alone put 3 MB of gRPC in the page (7.1 MB before). That is the
  price of one codebase for both targets; the portal serves the `.gz`, and the
  browser revalidates it.
- **DPoP is not used.** Its one-time-use check cannot be enforced across HA
  copies without shared state, and the tokens never reach the browser anyway.

## Phases

1. **fileshare**: admin API over Connect; OIDC issuers list with audiences;
   who may call, per issuer. **Done: v0.28.0** (#76).
2. **portal (BFF)**: login, encrypted session, per-server tokens, Connect proxy,
   static UI serving; e2e against two fileshare servers and a test IdP.
   **Done: portal v0.1.0.** The refresh token is spent in one place only
   (`POST /session/refresh`), because a provider that rotates refresh tokens
   revokes the grant on reuse. The session cookies are capped at 7600 bytes,
   which fits nginx's default 8 KiB header line. go-authn/bridge v0.21.0 issues
   the per-server tokens (RFC 8707 `resource`).
3. **console**: shares, grants, volumes, server state, over N servers.
   **Browser half done: console v0.1.0**: shares, details, grants,
   create/enable/disable/delete, grant/revoke, tested end to end in headless
   Chrome behind the portal binary and two fileshare binaries. What it needed
   in go-widgets: mvvm v0.14.0 `Queue`, webcanvas v0.4.0 `RepaintAware` and
   window v0.88.0 (a browser tab is a `Repainter`). Results from goroutines
   reach the screen through those. **Native login done: console v0.2.0**: the
   system browser and a loopback listener (go-authn/rp v0.1.0, RFC 8252, a
   public client), a token per server, the refresh token in memory and spent
   one refresh at a time; tested against two real fileshare binaries. The
   portal's own client moved to go-authn/rp too (portal v0.1.2). **Volumes
   done: console v0.3.0**: create, resize, snapshot, share and delete. The
   console never sends `destroy_data`: a volume holding data is the server's
   refusal, shown.
4. **explorer**: browse, download, chunked upload, rename, copy (server-side).
   **Browser half done: explorer v0.1.0**, through portal v0.2.0 (`/dav/<server>/...`,
   answers served inert: `CSP: sandbox`, attachment, nosniff) and fileshare
   v0.29.0 (an upload piece appended at the end; the WebDAV root a collection of
   the shares). Uploads go in 8 MiB pieces to `<name>.part`, then a MOVE; nothing
   is replaced (`Overwrite: F`). Tested end to end in headless Chrome behind the
   portal binary and a fileshare binary, each step checked on disk. The UIs'
   side of the portal is a package now (`portal/client`), refreshes serialized
   across tabs by Web Locks. **Not yet:** native login and a native file
   picker (`-demo` only).
5. Docs site and landing; a security review of each phase.
