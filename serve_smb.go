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
	for name := range s.people() {
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
	// Somebody a directory reload adds is added here too, while this
	// generation serves: an addition needs no new generation.
	add := func(name string, key []byte) { srv.AddUserHash(name, key) }
	s.smbAddUser.Store(&add)

	served, _ := p.exports(s.cfg, s.currentShares())
	for _, sh := range served {
		var opts []smb.ShareOption
		if sh.readOnly {
			opts = append(opts, smb.ReadOnly())
		}
		if !sh.allowsAnyone() {
			if len(sh.allow) == 0 {
				// Written for somebody, and nobody is left: an empty
				// AllowUsers would be read as "everyone", so the share is
				// not offered at all.
				continue
			}
			opts = append(opts, smb.AllowUsers(sh.allow...))
		}
		if !sh.anyAllowedWrites() {
			if len(sh.writers) == 0 {
				opts = append(opts, smb.ReadOnly())
			} else {
				opts = append(opts, smb.WriteUsers(sh.writers...))
			}
		}
		if sh.capacity != nil {
			opts = append(opts, smb.WithCapacityFunc(sh.capacity))
		} else if sh.size > 0 {
			opts = append(opts, smb.WithCapacity(sh.size, sh.size))
		}
		if err := srv.Share(sh.name, sh.fsys, opts...); err != nil {
			return err
		}
	}
	return srv.Serve(ln)
}
