// SPDX-License-Identifier: BSD-3-Clause

//go:build !nowebdav

package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// An upload in pieces, as the go-fileshare explorer makes one from a browser:
// an empty PUT, then each piece where the last ended (go-filesystems/webdav
// v0.6.0), then a MOVE to the real name -- through the server as it runs, onto
// the disk. No request carries the whole file.
func TestWebDAVUploadInPieces(t *testing.T) {
	share := fullDirShare(t)
	dir := regexp.MustCompile(`directory = "([^"]+)"`).FindStringSubmatch(share)[1]
	r := start(t, onlyProtocol(t, t.TempDir(), "webdav", share))
	base := "http://" + r.addrs["webdav"] + "/full/"
	do := func(method, path string, body []byte, hdr ...string) int {
		t.Helper()
		req, _ := http.NewRequest(method, base+path, bytes.NewReader(body))
		req.SetBasicAuth("alice", "hunter2")
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return res.StatusCode
	}
	want := bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB
	const piece = 300_000                                   // not a divisor: the last piece is short
	if c := do(http.MethodPut, "big.part", nil); c != http.StatusCreated {
		t.Fatalf("empty PUT: %d", c)
	}
	for off := 0; off < len(want); off += piece {
		end := min(off+piece, len(want)) - 1
		rng := fmt.Sprintf("bytes %d-%d/%d", off, end, len(want))
		if c := do(http.MethodPut, "big.part", want[off:end+1], "Content-Range", rng); c != http.StatusNoContent {
			t.Fatalf("%s: %d", rng, c)
		}
	}
	// A piece past the end would leave a hole: refused.
	if c := do(http.MethodPut, "big.part", []byte("x"), "Content-Range", fmt.Sprintf("bytes %d-%d/*", len(want)+1, len(want)+1)); c != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("a gap: %d", c)
	}
	if c := do("MOVE", "big.part", nil, "Destination", base+"big.bin"); c != http.StatusCreated {
		t.Fatalf("MOVE: %d", c)
	}
	got, err := os.ReadFile(filepath.Join(dir, "big.bin"))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("on disk: %d bytes, %v; equal %v", len(got), err, bytes.Equal(got, want))
	}
	if _, err := os.Stat(filepath.Join(dir, "big.part")); !os.IsNotExist(err) {
		t.Fatal("the part file is still there")
	}
}
