// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosftp && noopenpubkey

package main

import (
	"errors"

	"golang.org/x/crypto/ssh"
)

// Built with -tags noopenpubkey: a configuration asking for opkssh logins is
// refused at start, rather than started with a way in that silently is not.

type opkVerifier struct{}

// haveOpenPubkey says this binary can check opkssh logins.
const haveOpenPubkey = false

func knownMaxAge(string) bool { return true }

func newOPK(*oidcBlock) (*opkVerifier, error) {
	return nil, errors.New("opkssh_client_id: this binary was built with -tags noopenpubkey")
}

func (f *federatedSFTP) openpubkey(string, *ssh.Certificate) (*ssh.Permissions, error) {
	return nil, errors.New("this binary has no OpenPubkey")
}
