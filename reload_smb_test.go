// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosql && !nosmb && !nowebdav

package main

import (
	"slices"
	"testing"
)

// SMB registers its people when a generation starts, so somebody a reload
// ADDS must reach the running SMB server too -- without a new generation, or
// every SMB session would drop for each application password created.
func TestAReloadAddsToTheRunningSMBServer(t *testing.T) {
	needUsers(t)
	rl := startReloading(t, "serve \"webdav\" { addr = \"127.0.0.1:0\" }\nserve \"smb\" { addr = \"127.0.0.1:0\" }\n")
	r := &running{srv: rl.srv, addrs: map[string]string{}}
	rl.srv.runMu.Lock()
	for _, f := range rl.srv.feeds {
		r.addrs[f.proto] = f.ln.Addr().String()
	}
	rl.srv.runMu.Unlock()

	// Control: fay is not there yet.
	if fs := tryMountSMB(t, r, "fay", "correct horse", "open"); fs != nil {
		t.Fatal("fay mounted before she was in the database")
	}
	dora := mountSMB(t, r, "dora", "hunter2", "t")

	rl.exec(t, `insert into staff values ('fay', 'correct horse')`)
	res, err := rl.srv.reload()
	if err != nil || res.swapped || !slices.Equal(res.added, []string{"fay"}) {
		t.Fatalf("reload: %+v %v", res, err)
	}
	fs := mountSMB(t, r, "fay", "correct horse", "open")
	if got, err := fs.ReadFile("b.txt"); err != nil || string(got) != "anyone" {
		t.Fatalf("fay over SMB after the reload: %q %v", got, err)
	}
	if got, err := dora.ReadFile("a.txt"); err != nil || string(got) != "engineers only" {
		t.Fatalf("an addition disturbed an SMB session already open: %q %v", got, err)
	}

	// ⛔ The share's only group empties. An empty AllowUsers would read as
	// "everyone", so the share must not be offered over SMB at all.
	rl.exec(t, `delete from teams`)
	if res, err := rl.srv.reload(); err != nil || !res.swapped {
		t.Fatalf("emptying the group: %+v %v", res, err)
	}
	for _, who := range [][2]string{{"dora", "hunter2"}, {"fay", "correct horse"}, {"eli", "swordfish"}} {
		if fs := tryMountSMB(t, r, who[0], who[1], "t"); fs != nil {
			if _, err := fs.ReadFile("a.txt"); err == nil {
				t.Fatalf("%s read a share whose every group is gone", who[0])
			}
		}
	}
	if fs := mountSMB(t, r, "eli", "swordfish", "open"); fs == nil {
		t.Fatal("the open share went with it")
	}
}
