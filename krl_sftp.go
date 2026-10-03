// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosftp

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/go-authn/krl"
	"github.com/go-authn/revocation"
	"github.com/go-filesystems/sftp/sshd"
	"golang.org/x/crypto/ssh"
)

// sshKRL is an OpenSSH KRL, as a revocation list: go-authn/krl reads it and
// answers for a certificate the way ssh-keygen -Q does.
type sshKRL struct{ k *krl.KRL }

func (s sshKRL) describe() string {
	return fmt.Sprintf("KRL version %d, generated %s", s.k.Version, s.k.GeneratedDate.UTC().Format(time.RFC3339))
}

// expires is the KRL's expires@go-authn.github.io extension (go-authn/krl
// v0.2.0): when the list itself says it stops being current. Zero for a list
// that does not say, which only a local file may be; max_age bounds both.
func (s sshKRL) expires() time.Time { return s.k.Expires }

func (s sshKRL) older(than revoked) bool {
	o, ok := than.(sshKRL)
	return ok && s.k.Version < o.k.Version
}

func parseKRL(b []byte) (revoked, error) {
	k, err := krl.Parse(b)
	if err != nil {
		return nil, err
	}
	return sshKRL{k}, nil
}

// openSSHKRL makes the list an oidc block names, or nil when it names none.
//
// ⛔ A KRL fetched from ssh_krl_url must come with its detached signature
// (url + ".sig") by the provider's SSH CA, and say when it expires: what
// go-authn/revocation's PROTOCOL.md asks, and what go-authn/bridge serves
// from v0.10.0. HTTPS authenticates the server that answered, not the list
// -- a mirror, a cache, a compromised web server can serve an empty one --
// and a KRL alone has no end, so a stale copy reads as a current one. A
// list placed by hand at ssh_krl_file is as trusted as the filesystem that
// holds it, and is read as before.
func openSSHKRL(o *oidcBlock, out io.Writer) (*revocationList, error) {
	if o == nil || (o.SSHKRLURL == "" && o.SSHKRLFile == "") {
		return nil, nil
	}
	refresh, maxAge, err := o.krlTiming()
	if err != nil {
		return nil, err
	}
	l, err := newRevocationList("ssh_krl", o.SSHKRLURL, o.SSHKRLFile, o.SSHKRLCAFile, refresh, maxAge, parseKRL, out)
	if err != nil || o.SSHKRLURL == "" {
		return l, err
	}
	ca, err := readSSHCA(o.SSHCAFile)
	if err != nil {
		return nil, fmt.Errorf("ssh_krl_url: the list is verified against ssh_ca_file: %w", err)
	}
	l.verify = func(ctx context.Context, body []byte, tag string) error {
		sig, err := l.fetchSignature(ctx, tag)
		if err != nil {
			return err
		}
		if _, err := revocation.VerifyKRL(body, sig, ca); err != nil {
			return err
		}
		return nil
	}
	return l, nil
}

// readSSHCA is the one key of an authorized_keys-format file.
func readSSHCA(path string) (ssh.PublicKey, error) {
	if path == "" {
		return nil, errors.New("no ssh_ca_file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	keys, err := sshd.ParseAuthorizedKeys(b)
	if err != nil || len(keys) != 1 {
		return nil, fmt.Errorf("%s: one SSH CA key is expected", path)
	}
	return keys[0], nil
}
