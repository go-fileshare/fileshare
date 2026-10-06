// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosftp

package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// SFTP: version 3 has no code for a full filesystem (NO_SPACE_ON_FILESYSTEM
// and QUOTA_EXCEEDED are version 5's), so a full share is SSH_FX_FAILURE
// with "no space left on device" as the message every client shows --
// whichever errno.
func TestAFullShareOverSFTP(t *testing.T) {
	if protocolByName("sftp") == nil {
		t.Skip("built without sftp")
	}
	for _, e := range fullErrnos {
		t.Run(e.name, func(t *testing.T) {
			serveFull(t, e.errno())
			key, pub := keyPair(t)
			r := start(t, fmt.Sprintf("user \"alice\" { authorized_keys = [%q] }\n%sserve \"sftp\" { addr = \"127.0.0.1:0\" }\n",
				pub, fullDirShare(t)))
			c, done, err := sftpAs(t, r.addrs["sftp"], "alice", ssh.PublicKeys(key))
			if err != nil {
				t.Fatal(err)
			}
			defer done()
			for name, op := range map[string]func() error{
				"write": func() error {
					f, err := c.Create("/full/a.bin")
					if err != nil {
						return err
					}
					_, werr := f.Write([]byte("data"))
					cerr := f.Close()
					return errors.Join(werr, cerr)
				},
				"mkdir": func() error { return c.Mkdir("/full/d") },
			} {
				err := op()
				t.Logf("%s: %v", name, err)
				var se *sftp.StatusError
				if !errors.As(err, &se) {
					t.Errorf("%s on a full share: %v, not an SFTP status", name, err)
					continue
				}
				if se.FxCode() != sftp.ErrSSHFxFailure || !strings.Contains(err.Error(), "no space") {
					t.Errorf("%s on a full share: %v, want SSH_FX_FAILURE saying no space", name, err)
				}
			}
		})
	}
}
