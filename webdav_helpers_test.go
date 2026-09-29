// SPDX-License-Identifier: BSD-3-Clause

//go:build !nowebdav

package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
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
