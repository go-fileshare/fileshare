// SPDX-License-Identifier: BSD-3-Clause

//go:build !nowebdav

package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// WebDAV: a full share is 507 Insufficient Storage (RFC 4918 §11.5), for a
// PUT and an MKCOL, whichever errno the filesystem said it with.
func TestAFullShareOverWebDAV(t *testing.T) {
	for _, e := range fullErrnos {
		t.Run(e.name, func(t *testing.T) {
			serveFull(t, e.errno())
			r := start(t, onlyProtocol(t, t.TempDir(), "webdav", fullDirShare(t)))
			for _, c := range []struct{ method, path string }{{http.MethodPut, "/full/a.bin"}, {"MKCOL", "/full/d"}} {
				var body io.Reader
				if c.method == http.MethodPut {
					body = strings.NewReader("data")
				}
				req, _ := http.NewRequest(c.method, "http://"+r.addrs["webdav"]+c.path, body)
				req.SetBasicAuth("alice", "hunter2")
				res, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				res.Body.Close()
				t.Logf("%s %s: %d", c.method, c.path, res.StatusCode)
				if res.StatusCode != 507 {
					t.Errorf("%s on a full share: %d, want 507 Insufficient Storage", c.method, res.StatusCode)
				}
			}
		})
	}
}
