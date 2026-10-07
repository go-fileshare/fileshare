// SPDX-License-Identifier: BSD-3-Clause

//go:build !nowebdav

package main

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The WebDAV client of the tests. It lives on its own, behind the WebDAV tag
// only: it was in a file that also needed SMB, and a build without SMB lost
// it from under every WebDAV test that used it.

func webdavGet(r *running, user, password, path string) ([]byte, error) {
	req, _ := http.NewRequest(http.MethodGet, "http://"+r.addrs["webdav"]+path, nil)
	req.SetBasicAuth(user, password)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %d", path, res.StatusCode)
	}
	return body, nil
}

func webdavPut(r *running, user, password, path, body string) error {
	req, _ := http.NewRequest(http.MethodPut, "http://"+r.addrs["webdav"]+path, strings.NewReader(body))
	req.SetBasicAuth(user, password)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	io.Copy(io.Discard, res.Body)
	if res.StatusCode >= 300 {
		return fmt.Errorf("%s: %d", path, res.StatusCode)
	}
	return nil
}

var quotaProp = regexp.MustCompile(`<(?:\w+:)?(quota-available-bytes|quota-used-bytes)[^>]*>(\d+)<`)

// webdavQuota asks PROPFIND for the RFC 4331 quota properties of a
// collection, as alice.
func webdavQuota(t *testing.T, addr, path string) (avail, used uint64) {
	t.Helper()
	body := `<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop>` +
		`<D:quota-available-bytes/><D:quota-used-bytes/></D:prop></D:propfind>`
	req, _ := http.NewRequest("PROPFIND", "http://"+addr+path, strings.NewReader(body))
	req.Header.Set("Depth", "0")
	req.SetBasicAuth("alice", "hunter2")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	got := map[string]uint64{}
	for _, m := range quotaProp.FindAllStringSubmatch(string(b), -1) {
		n, _ := strconv.ParseUint(m[2], 10, 64)
		got[m[1]] = n
	}
	if len(got) != 2 {
		t.Fatalf("PROPFIND %s: %d: no quota properties in\n%s", path, res.StatusCode, b)
	}
	return got["quota-available-bytes"], got["quota-used-bytes"]
}
