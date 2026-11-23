// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosmb && !wasip1

package main

import (
	"crypto/tls"
	"net"

	"github.com/go-filesystems/smb"
)

// SMB over QUIC ([MS-SMB2] 3.1.1, Windows 11 and Server 2025 clients): the
// same protocol on a UDP socket, inside TLS 1.3 with ALPN "smb". The socket
// is bound HERE, never inherited from the launcher, which hands over TCP
// listeners.

// listenQUIC binds addr on UDP.
func listenQUIC(addr string, conf *tls.Config) (net.Listener, error) {
	return smb.ListenQUIC(addr, conf)
}

// requireSMBClientCert makes the TLS handshake demand a client certificate
// chaining to caPEM.
func requireSMBClientCert(conf *tls.Config, caPEM []byte) error {
	return smb.RequireClientCertificate(conf, caPEM)
}
