// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"net"

	"github.com/go-filesystems/smb"
)

// SMB is the protocol that can express everything this program's access model
// says, because its model is the same one: users, shares, who may connect, who
// may write. Nothing is lost in the translation.
func serveSMB(s *server, p *protocol, ln net.Listener) error {
	srv := smb.New()
	srv.SetName(s.name)
	for user, password := range s.users {
		srv.AddUser(user, password)
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
