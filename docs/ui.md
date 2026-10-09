# Two UIs for many servers: design

Status: **design, agreed 2026-10-09**. Phase 1 is built (v0.28.0); nothing
else below is built yet unless a phase says so.

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
- **BFF** (`go-fileshare/portal`, to create) — OIDC authorization code with
  PKCE as a confidential client; the session in an encrypted cookie so that any
  copy can serve any request (no shared state, so HA is a matter of running
  several); per-server tokens (audience-restricted, by RFC 8707 resource
  indicators where the IdP supports them, by RFC 8693 token exchange across
  organisations); serves the two wasm UIs and proxies their Connect calls and
  the explorer's WebDAV.
- **admin console** (`go-fileshare/console`, to create) and **file explorer**
  (`go-fileshare/explorer`, to create) — go-widgets applications in the MVVM
  shape of go-widgets/app-template: a ViewModel that holds every piece of state
  as `mvvm` observables and knows no widget, a View bound through `mvvmtk`, CI
  gated by `mvvmlint` and `bricolint`. One `main.go` per target is all that
  differs: `window.Open` + `w.Run(root)` both ways.

## Constraints the sources impose

- **Uploads are chunked.** Streaming request bodies need `duplex:"half"` and
  HTTP/2 and exist in Chrome only, and Go's wasm `net/http` reads a request body
  whole before sending it. The explorer uploads in ranges (fileshare's WebDAV
  takes `Content-Range` PUTs), so a large file never sits in memory whole.
- **The wasm is a few megabytes.** Measured: 2.8 MB gzipped with the `net/http`
  client. That is the price of one codebase for both targets; the BFF serves it
  compressed and cacheable.
- **DPoP is not used.** Its one-time-use check cannot be enforced across HA
  copies without shared state, and the tokens never reach the browser anyway.

## Phases

1. **fileshare**: admin API over Connect; OIDC issuers list with audiences;
   who may call, per issuer. **Done: v0.28.0** (#76).
2. **portal (BFF)**: login, encrypted session, per-server tokens, Connect proxy,
   static UI serving; e2e against two fileshare servers and a test IdP.
3. **console**: shares, grants, volumes, server state, over N servers.
4. **explorer**: browse, download, chunked upload, rename, copy (server-side).
5. Docs site and landing; a security review of each phase.
