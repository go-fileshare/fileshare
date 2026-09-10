//go:build !nosmb

package main

import (
	"context"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2"
)

// An SMB client, for the tests that ask what a real one is told.
func mountSMB(t *testing.T, r *running, user, password, share string) *smb2.Share {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: user, Password: password}}
	s, err := d.Dial(ctx, r.addrs["smb"])
	if err != nil {
		cancel()
		t.Fatalf("%s dialing smb: %v", user, err)
	}
	fs, err := s.Mount(share)
	if err != nil {
		s.Logoff()
		cancel()
		t.Fatalf("%s mounting %s: %v", user, share, err)
	}
	t.Cleanup(func() { fs.Umount(); s.Logoff(); cancel() })
	return fs
}

// tryMountSMB is the same, for a mount that is EXPECTED to be refused
// somewhere: the refusal can come at the session (a password that is wrong) or
// at the tree connect (a share that is not yours), and a test about access
// should not care which -- only that it did not end with a usable share.
func tryMountSMB(t *testing.T, r *running, user, password, share string) *smb2.Share {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: user, Password: password}}
	s, err := d.Dial(ctx, r.addrs["smb"])
	if err != nil {
		cancel()
		return nil
	}
	fs, err := s.Mount(share)
	if err != nil {
		s.Logoff()
		cancel()
		return nil
	}
	t.Cleanup(func() { fs.Umount(); s.Logoff(); cancel() })
	return fs
}
