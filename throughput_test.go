// SPDX-License-Identifier: BSD-3-Clause

//go:build !nonfs && !nowebdav && !nosmb && !nosftp

package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2"
	"golang.org/x/crypto/ssh"
)

// TestThroughputAgainstTheHost reads one file of a directory share through
// every protocol and compares it with reading the same file on the host.
// It is a measurement, not a check: it runs only when
// FILESHARE_THROUGHPUT_MIB says how big the file is, and it fails nothing.
//
//	FILESHARE_THROUGHPUT_MIB=256 go test -run TestThroughputAgainstTheHost -v
//
// Each line is the median of three runs, after a first read that warms the
// page cache, so what is measured is the server's own cost, not the disk's.
// "x4" is four clients reading the file at once: a server that serialises
// every read shows it there.
func TestThroughputAgainstTheHost(t *testing.T) {
	mib, _ := strconv.Atoi(os.Getenv("FILESHARE_THROUGHPUT_MIB"))
	if mib <= 0 {
		t.Skip("set FILESHARE_THROUGHPUT_MIB to run it")
	}
	size := int64(mib) << 20

	dir := t.TempDir()
	tree := filepath.Join(dir, "tree")
	if err := os.Mkdir(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(tree, "big.bin")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(f, rand.Reader, size); err != nil {
		t.Fatal(err)
	}
	f.Close()

	key, pub := keyPair(t)
	pw := write(t, dir, "alice.pw", "hunter2\n")
	r := start(t, fmt.Sprintf(`name = "TP"
user "alice" {
  password_file   = %q
  authorized_keys = [%q]
}
share "tree" {
  directory = %q
  read_only = true
}
serve "webdav" { addr = "127.0.0.1:0" }
serve "sftp"   { addr = "127.0.0.1:0" }
serve "nfs"    { addr = "127.0.0.1:0" }
serve "smb"    { addr = "127.0.0.1:0" }
`, hclPath(pw), pub, hclPath(tree)))

	readers := []struct {
		name string
		read func() int64
	}{
		{"host", func() int64 { return hostRead(t, path) }},
		{"webdav", func() int64 { return webdavRead(t, r.addrs["webdav"], "/tree/big.bin") }},
		{"sftp", func() int64 { return sftpRead(t, r.addrs["sftp"], key, "/tree/big.bin") }},
		{"smb", func() int64 { return smbRead(t, r.addrs["smb"], "tree", "big.bin") }},
		{"nfs", func() int64 { return nfsRead(t, r.addrs["nfs"], "/tree", "big.bin", size) }},
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%d MiB file, page cache warm, median of 3\n", mib)
	fmt.Fprintf(&b, "%-8s %12s %8s %12s %8s\n", "", "x1 MB/s", "/host", "x4 MB/s", "/host")
	var host1, host4 float64
	for _, rd := range readers {
		rd.read() // warm
		one := median(t, 3, size, 1, rd.read)
		four := median(t, 3, size, 4, rd.read)
		if rd.name == "host" {
			host1, host4 = one, four
		}
		fmt.Fprintf(&b, "%-8s %12.0f %7.0f%% %12.0f %7.0f%%\n", rd.name, one, 100*one/host1, four, 100*four/host4)
	}
	t.Log("\n" + b.String())
}

// median runs read on n goroutines at once, three times, and returns the
// median aggregate rate in MB/s (10^6 bytes, as dd and fio say it).
func median(t *testing.T, runs int, size int64, n int, read func() int64) float64 {
	t.Helper()
	var rates []float64
	for range runs {
		var wg sync.WaitGroup
		begin := time.Now()
		for range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if got := read(); got != size {
					t.Errorf("read %d bytes, want %d", got, size)
				}
			}()
		}
		wg.Wait()
		rates = append(rates, float64(size)*float64(n)/time.Since(begin).Seconds()/1e6)
	}
	sort.Float64s(rates)
	return rates[len(rates)/2]
}

const tpChunk = 1 << 20

// discard is io.Discard without its ReadFrom. io.CopyBuffer hands the copy
// to a destination's ReadFrom when it has one, and io.Discard's reads in
// 8 KiB whatever buffer was passed: every SMB READ was 8 KiB, and the host
// read too, until this.
var discard io.Writer = struct{ io.Writer }{io.Discard}

func hostRead(t *testing.T, path string) int64 {
	f, err := os.Open(path)
	if err != nil {
		t.Error(err)
		return 0
	}
	defer f.Close()
	n, _ := io.CopyBuffer(discard, struct{ io.Reader }{f}, make([]byte, tpChunk))
	return n
}

func webdavRead(t *testing.T, addr, path string) int64 {
	req, _ := http.NewRequest("GET", "http://"+addr+path, nil)
	req.SetBasicAuth("alice", "hunter2")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Error(err)
		return 0
	}
	defer res.Body.Close()
	n, _ := io.CopyBuffer(discard, res.Body, make([]byte, tpChunk))
	return n
}

func sftpRead(t *testing.T, addr string, key ssh.Signer, path string) int64 {
	c, done, err := sftpAs(t, addr, "alice", ssh.PublicKeys(key))
	if err != nil {
		t.Error(err)
		return 0
	}
	defer done()
	f, err := c.Open(path)
	if err != nil {
		t.Error(err)
		return 0
	}
	defer f.Close()
	// WriteTo: pkg/sftp's concurrent read-ahead, as `sftp get` does.
	n, _ := f.WriteTo(discard)
	return n
}

func smbRead(t *testing.T, addr, share, name string) int64 {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: "alice", Password: "hunter2"}}
	s, err := d.Dial(ctx, addr)
	if err != nil {
		t.Error(err)
		return 0
	}
	defer s.Logoff()
	fs, err := s.Mount(share)
	if err != nil {
		t.Error(err)
		return 0
	}
	defer fs.Umount()
	f, err := fs.Open(name)
	if err != nil {
		t.Error(err)
		return 0
	}
	defer f.Close()
	n, _ := io.CopyBuffer(discard, struct{ io.Reader }{f}, make([]byte, tpChunk))
	return n
}

// nfsRead reads the file with NFSv3 READs one at a time on one connection,
// as a client with no read-ahead would. Each asks for 1 MiB, the Linux
// client's default rsize, and gets what the server's rtmax allows.
func nfsRead(t *testing.T, addr, export, name string, size int64) int64 {
	root := nfsMount(t, addr, export)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Error(err)
		return 0
	}
	defer c.Close()
	call := func(proc uint32, args []byte) []byte {
		cred := append(append(xdrU32(0), xdrOpaque([]byte("tp"))...), xdrU32(0, 0, 0)...)
		msg := xdrU32(1, 0, 2, 100003, 3, proc, 1)
		msg = append(msg, xdrOpaque(cred)...)
		msg = append(msg, xdrU32(0, 0)...)
		msg = append(msg, args...)
		if _, err := c.Write(append(xdrU32(0x80000000|uint32(len(msg))), msg...)); err != nil {
			t.Fatal(err)
		}
		var body []byte
		for last := false; !last; {
			var mark [4]byte
			if _, err := io.ReadFull(c, mark[:]); err != nil {
				t.Fatal(err)
			}
			frag := make([]byte, getBE32(mark[:])&^0x80000000)
			if _, err := io.ReadFull(c, frag); err != nil {
				t.Fatal(err)
			}
			body = append(body, frag...)
			last = getBE32(mark[:])&0x80000000 != 0
		}
		return body[24:] // xid, reply, accepted, verifier, success
	}
	res := call(3, append(xdrOpaque(root), xdrOpaque([]byte(name))...)) // LOOKUP
	if getBE32(res) != 0 {
		t.Errorf("LOOKUP %s: status %d", name, getBE32(res))
		return 0
	}
	fh := append([]byte(nil), res[8:8+getBE32(res[4:])]...)
	const count = 1 << 20
	var got int64
	for off := int64(0); off < size; {
		args := append(xdrOpaque(fh), xdrU32(uint32(off>>32), uint32(off), count)...)
		res := call(6, args) // READ
		if getBE32(res) != 0 {
			t.Errorf("READ at %d: status %d", off, getBE32(res))
			return got
		}
		p := 4
		if getBE32(res[p:]) == 1 { // post_op_attr present: fattr3 is 84 bytes
			p += 4 + 84
		} else {
			p += 4
		}
		n := int64(getBE32(res[p:]))
		if n == 0 {
			break
		}
		got += n
		off += n
	}
	return got
}
