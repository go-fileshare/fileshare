// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosmb

package main

import (
	"fmt"
	"net"

	"github.com/go-filesystems/smb"
)

// SMB is the protocol that can express everything this program's access model
// says, because its model is the same one: users, shares, who may connect, who
// may write. Nothing is lost in the translation.
func serveSMB(s *server, p *protocol, ln net.Listener) error {
	srv := smb.New()
	srv.SetName(s.name)
	for name := range s.who {
		// Only the people NTLMv2 can be computed for. The KEY is what goes in,
		// not the password: it is the same value either way, and it is what a
		// directory publishes for exactly this reason. The rest are told by
		// `check` rather than left to meet a refusal at a mount.
		if key, ok := s.ntKey(name); ok {
			if err := srv.AddUserHash(name, key); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	served, _ := p.exports(s.shares)
	for _, sh := range served {
		var opts []smb.ShareOption
		if sh.readOnly {
			opts = append(opts, smb.ReadOnly())
		}
		if len(sh.allow) > 0 {
			opts = append(opts, smb.AllowUsers(sh.allow...))
		}
		if len(sh.writers) > 0 {
			opts = append(opts, smb.WriteUsers(sh.writers...))
		}
		if err := srv.Share(sh.name, sh.fsys, opts...); err != nil {
			return err
		}
	}
	return srv.Serve(ln)
}
