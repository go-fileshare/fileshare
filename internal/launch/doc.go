// SPDX-License-Identifier: BSD-3-Clause

// Package launch starts the workers that serve a person's files as that
// person (docs/identity.md). Three parties:
//
//   - the LAUNCHER, root, the parent of everything: it is asked for "a worker
//     for alice, on share photos" over a socketpair only the front holds,
//     resolves alice itself (internal/account), and starts the worker as
//     her;
//   - the FRONT, no privilege: it asks (Client.Worker), receives the worker's
//     end of a new socketpair (SCM_RIGHTS), and talks to it through
//     go-filesystems/remote;
//   - the WORKER, the person: it checks that it is who it was started as and
//     cannot become root again, opens the share's directory, and serves it
//     (Worker).
//
// A request never carries a uid or a path. The front names a person and a
// share; the launcher decides the rest.
//
// Unix only: Windows has no setuid, and no descriptor passing in os/exec.
package launch
