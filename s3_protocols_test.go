// SPDX-License-Identifier: BSD-3-Clause

//go:build !nos3 && !nowebdav

package main

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"slices"
	"testing"
)

// A share's `protocols` list holds over S3 as over every other protocol: a
// share written for WebDAV only is not a bucket, not listed and not read. S3
// once chose the buckets from who may use a share alone, and served the
// WebDAV-only share to alice. The control is the same share read over WebDAV,
// and a share with no list, which S3 serves.
func TestS3HonoursAShareProtocolsList(t *testing.T) {
	dir := t.TempDir()
	secret := image(t, dir, "secret.img", map[string]string{"/plan.txt": "webdav-only content"})
	alice := write(t, dir, "alice.pw", "hunter2\n")
	r := start(t, fmt.Sprintf(`
name = "TESTFS"
user "alice" { password_file = %q }
share "secret" {
  image     = %q
  allow     = ["alice"]
  protocols = ["webdav"]
}
share "pub" {
  image = %q
}
serve "webdav" { addr = "127.0.0.1:0" }
serve "s3"     { addr = "127.0.0.1:0" }
`, hclPath(alice), hclPath(secret), hclPath(image(t, dir, "pub.img", nil))))

	if got, err := webdavGet(r, "alice", "hunter2", "/secret/plan.txt"); err != nil || string(got) != "webdav-only content" {
		t.Fatalf("CONTROL: alice over WebDAV: %q %v", got, err)
	}
	resp, body := s3Do(t, r, "alice", "hunter2", http.MethodGet, "/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ListBuckets: %d %s", resp.StatusCode, body)
	}
	var list struct {
		Buckets []struct{ Name string } `xml:"Buckets>Bucket"`
	}
	if err := xml.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, b := range list.Buckets {
		names = append(names, b.Name)
	}
	if slices.Contains(names, "secret") || !slices.Contains(names, "pub") {
		t.Errorf("S3 lists %v; want pub and not the WebDAV-only secret", names)
	}
	if resp, body := s3Do(t, r, "alice", "hunter2", http.MethodGet, "/secret/plan.txt"); resp.StatusCode == http.StatusOK {
		t.Errorf("S3 read the WebDAV-only share: %d %q", resp.StatusCode, body)
	}
}
