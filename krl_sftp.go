// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosftp

package main

import (
	"fmt"
	"io"
	"time"

	"github.com/go-authn/krl"
)

// sshKRL is an OpenSSH KRL, as a revocation list: go-authn/krl reads it and
// answers for a certificate the way ssh-keygen -Q does.
type sshKRL struct{ k *krl.KRL }

func (s sshKRL) describe() string {
	return fmt.Sprintf("KRL version %d, generated %s", s.k.Version, s.k.GeneratedDate.UTC().Format(time.RFC3339))
}

// expires: a KRL says nothing about when it must be replaced; max_age does.
func (sshKRL) expires() time.Time { return time.Time{} }

func parseKRL(b []byte) (revoked, error) {
	k, err := krl.Parse(b)
	if err != nil {
		return nil, err
	}
	return sshKRL{k}, nil
}

// openSSHKRL makes the list an oidc block names, or nil when it names none.
func openSSHKRL(o *oidcBlock, out io.Writer) (*revocationList, error) {
	if o == nil || (o.SSHKRLURL == "" && o.SSHKRLFile == "") {
		return nil, nil
	}
	refresh, maxAge, err := o.krlTiming()
	if err != nil {
		return nil, err
	}
	return newRevocationList("ssh_krl", o.SSHKRLURL, o.SSHKRLFile, o.SSHKRLCAFile, refresh, maxAge, parseKRL, out)
}
