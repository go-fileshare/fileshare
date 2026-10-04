// SPDX-License-Identifier: BSD-3-Clause

//go:build !nowebdav

package main

import (
	"fmt"
	"net/http"
	"testing"
)

// A share's name is not confirmed to anybody who has not authenticated: an
// anonymous request for a share and for a name that is no share get the same
// challenge, and only after authenticating does "not yours" and "not there"
// become the same 404. WebDAV once answered 401 for a share and 404 for
// anything else, a list of the share names for whoever asked. The control is
// alice, who may use photos, and gets it.
func TestWebDAVDoesNotTellAnAnonymousClientWhichNamesAreShares(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	r := start(t, configFor(t, dir, fmt.Sprintf(`
share "photos" {
  image = %q
  allow = ["alice"]
}
share "scratch" { image = %q }`, hclPath(image(t, dir, "photos.img", map[string]string{"/a.txt": "a"})),
		hclPath(image(t, dir, "scratch.img", nil)))))
	ask := func(user, password, path string) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, "http://"+r.addrs["webdav"]+path, nil)
		if user != "" {
			req.SetBasicAuth(user, password)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res
	}
	share, none := ask("", "", "/photos/a.txt"), ask("", "", "/nosuchshare/a.txt")
	if share.StatusCode != http.StatusUnauthorized || none.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous: a share -> %d, no share -> %d; want 401 for both", share.StatusCode, none.StatusCode)
	}
	if a, b := share.Header.Values("WWW-Authenticate"), none.Header.Values("WWW-Authenticate"); fmt.Sprint(a) != fmt.Sprint(b) {
		t.Errorf("anonymous: the challenges differ: %q and %q", a, b)
	}
	for _, path := range []string{"/photos/a.txt", "/nosuchshare/a.txt"} {
		if code := ask("bob", "swordfish", path).StatusCode; code != http.StatusNotFound {
			t.Errorf("bob, who may not use photos, GET %s -> %d, want 404", path, code)
		}
	}
	if code := ask("bob", "wrong", "/nosuchshare/a.txt").StatusCode; code != http.StatusUnauthorized {
		t.Errorf("a wrong password for no share -> %d, want 401", code)
	}
	if code := ask("alice", "hunter2", "/photos/a.txt").StatusCode; code != http.StatusOK {
		t.Errorf("CONTROL: alice GET /photos/a.txt -> %d", code)
	}
}
