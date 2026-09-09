// SPDX-License-Identifier: BSD-3-Clause

// Command fileshare serves disk images over SMB, NFS and WebDAV -- the same
// images, the same users, the same per-share access, from one configuration
// file.
//
//	fileshare --config /etc/fileshare.d
//	fileshare check /etc/fileshare.d
//
// A person wants to SHARE an image. Which protocol carries it is a property of
// the client at the other end: macOS and Windows reach for SMB, a Linux fleet
// already has NFS, a browser or a phone has HTTP. Running four servers, each
// with its own configuration file and its own idea of who "alice" is, is a way
// to get three of them subtly wrong.
//
// # What a protocol can promise
//
// The protocols do not agree about the one thing access control needs: whether
// the server can tell WHO is asking.
//
//	SMB     NTLMv2. The server proves the password without ever seeing it.
//	WebDAV  HTTP Basic over the transport's TLS, or a bearer token.
//	NFSv3   NOTHING. AUTH_UNIX is a claim -- the client says "uid 501" and
//	        the wire cannot disagree. There is no encryption either.
//
// So a share that names who may use it is NOT exported over a protocol that
// cannot tell them apart. It is not a warning and not an option: a
// configuration that says "photos belongs to alice" and a protocol that hands
// photos to whoever connects cannot both be honoured, and quietly widening
// access is the worse of the two failures.
//
// `fileshare check` prints the whole matrix -- every share against every
// protocol, and who may read and write it -- because that is the question a
// person actually has before they restart a server other people are using.
package main
