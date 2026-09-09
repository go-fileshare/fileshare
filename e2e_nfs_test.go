//go:build !nonfs

package main

import (
	"fmt"
	"strings"
	"testing"
)

// What NFS makes of a share that names who may use it: nothing, on purpose.
func TestNFSIsNotOfferedARestrictedShare(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	img := image(t, dir, "photos.img", map[string]string{"/greeting.txt": "hello"})
	open := image(t, dir, "open.img", map[string]string{"/greeting.txt": "everyone"})
	r := start(t, configFor(t, dir, fmt.Sprintf(`
share "photos" {
  image   = %q
  allow   = ["alice", "bob"]
  writers = ["alice"]
}

share "open" {
  image = %q
}`, hclPath(img), hclPath(open))))

	nfs := protocolByName("nfs")
	served, refused := nfs.exports(r.srv.shares)
	if len(served) != 1 || served[0].name != "open" {
		t.Errorf("nfs serves %v", names(served))
	}
	if len(refused) != 1 || refused[0].name != "photos" {
		t.Errorf("nfs refuses %v", names(refused))
	}
	if !strings.Contains(nfs.refusal(refused[0]), "AUTH_UNIX") {
		t.Errorf("the refusal does not say why: %q", nfs.refusal(refused[0]))
	}
	// And it is said out loud where a person will see it.
	if !strings.Contains(r.out.String(), "photos is not served over nfs") {
		t.Errorf("the announcement does not say it:\n%s", r.out.String())
	}
}
