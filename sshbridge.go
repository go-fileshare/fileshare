// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"

	fork "github.com/go-filesystems/ssh"
	xssh "golang.org/x/crypto/ssh"
)

// go-filesystems/sftp v0.11.0 speaks the go-filesystems/ssh fork of
// golang.org/x/crypto/ssh (one write per channel Write instead of one per
// packet), so its key and certificate types are the fork's. The libraries that
// judge them -- go-authn/revocation, go-authn's sshcert -- still take the
// upstream types. The two are the same bytes on the wire, so a value crosses
// by its wire encoding: nothing is trusted that was not parsed again.

// upstreamKey is key as golang.org/x/crypto/ssh reads it.
func upstreamKey(key fork.PublicKey) (xssh.PublicKey, error) {
	k, err := xssh.ParsePublicKey(key.Marshal())
	if err != nil {
		return nil, fmt.Errorf("ssh key: %w", err)
	}
	return k, nil
}

// upstreamCert is cert as golang.org/x/crypto/ssh reads it.
func upstreamCert(cert *fork.Certificate) (*xssh.Certificate, error) {
	k, err := upstreamKey(cert)
	if err != nil {
		return nil, err
	}
	c, ok := k.(*xssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("ssh certificate: parsed as %s", k.Type())
	}
	return c, nil
}
