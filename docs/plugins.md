# Protocols in separate processes

Three things are wanted from "don't embed everything": a smaller binary, less
attack surface, and a way to add a protocol without patching this repository.
They do not have the same answer, and one of them has an answer that costs
nothing.

## Size: build tags win, and it is not close

Measured on this machine, on top of a 1.7 MB empty Go binary:

| | |
|---|---|
| SMB | 0.9 MB |
| NFS | 1.2 MB |
| WebDAV | 3.2 MB |
| the seven filesystem drivers | 2.4 MB |
| HCL + cobra | 3.7 MB |
| **everything (this program)** | **13.1 MB** |
| **`hashicorp/go-plugin`, on its own** | **13.2 MB** |

A plugin host would be **twice the size before loading anything**, because
go-plugin brings gRPC and protobuf; each plugin binary would carry them again.
`-tags nonfs,nowebdav` takes this program from 14.8 MB to 10.3 MB today, with
no subprocesses, no IPC and no version skew.

## Attack surface: tags remove, processes isolate

For a protocol you do **not** run, a build tag is the stronger tool: the code
is not in the binary at all, so there is nothing to reach, sandboxed or not.

For the protocols you **do** run, tags give nothing and a process boundary
gives three things this program cannot otherwise have:

- **Least privilege per protocol.** Today every protocol shares one address
  space and every image is open in it — *including the ones a protocol is
  refused*. The NFS server cannot serve a restricted share, but the bytes of
  that image are one bug away from it. A per-protocol process need never open
  the image at all.
- **Containment.** A panic, a leaked goroutine, or memory exhaustion in one
  protocol's parser takes down one process instead of the file server.
- **The operating system's own tools.** A separate process can drop to another
  uid, take a seccomp profile, or be confined by the sandbox of the platform it
  runs on. There is no way to apply any of that to a goroutine.

That is a real argument, and it is an argument for **processes**, not for a
plugin framework.

## Extending: out-of-tree is the only part plugins are for

Adding a protocol in this repository is two files — `protocol_x.go` registers
it, `serve_x.go` serves it — and the registry, the configuration, the access
rules and `check` all pick it up. What that does not allow is a protocol
somebody else ships on their own schedule, under their own licence, without
recompiling this program. If that is the goal, it is the goal a plugin API
serves; nothing else does.

## The question that actually decides the design: who owns the image?

Any process boundary has to answer it, and the IPC mechanism is a detail
underneath.

**The plugin opens the image itself.** No per-operation IPC. But two processes
then hold two drivers over one file, with no common lock and two independent
caches of the same metadata — which is the property this program exists to
keep (see the shared lock in `lockedfs.go`). Safe only if a given image is
served by exactly one process, or is read-only everywhere.

**The host owns the image and the protocol calls back.** The lock survives, and
the access rules are re-checked on every call rather than trusted to the
subprocess — a compromised protocol process can ask for nothing it was not
granted. The cost is an IPC round trip per file operation: measured here, a
unix-socket round trip is **2.1 µs** for 64 bytes and **2.3 µs** for 4 KiB. A
lean codec over that is affordable; go-plugin's gRPC is heavier (protobuf
marshalling and HTTP/2 framing on top), and would want measuring before it is
believed.

## What this repository will do

1. **Build tags** — done. They answer size and they answer "not running it" for
   attack surface, at zero runtime cost.
2. **A process per protocol, using this same binary**, if isolation is wanted:
   `fileshare` execs itself once per protocol, hands each child only the shares
   that protocol may serve, and each child opens only those images. No plugin
   framework, no gRPC, no second binary to version-match — and the same
   least-privilege property. It needs one rule to be honest about the
   coherence question above: an image writable through more than one protocol
   stays in one process, or is refused.
3. **go-plugin** only if third-party, out-of-tree protocols become the point.
   Then the 13.2 MB and the RPC are the price of something they buy, rather
   than a cost paid for modularity that build tags already provide.
