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
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// TestThroughputAgainstTheHost reads one file of a writable directory share
// -- the common case, and the one whose files a wrapper once kept from
// sendfile(2) -- through every protocol and compares it with reading the same
// file on the host. It is a measurement, not a check: it runs only when
// FILESHARE_THROUGHPUT_MIB says how big the file is, and it fails nothing.
//
//	FILESHARE_THROUGHPUT_MIB=256 go test -run TestThroughputAgainstTheHost -v
//
// This is the P0 harness of the performance plan. What it varies:
//
//   - sftp with 64 requests in flight per file (what OpenSSH's sftp does, and
//     the client's default) and with 1 (a client with no pipelining), so a
//     server that answers one request at a time shows against both;
//   - nfs over 1, 4 and 8 connections, each reading its own stripe of the
//     file: the Linux client's nconnect=N, from Go;
//   - "x1" is one client, "x4" four at once, each with its own session or
//     connection, so a server that serialises every read shows there;
//   - rounds are INTERLEAVED (every configuration once per round, then the
//     next round), so drift in the machine's load hits all of them alike, and
//     each line is the median of the rounds.
//
// Knobs, all environment variables:
//
//	FILESHARE_THROUGHPUT_ROUNDS=5   rounds (default 3)
//	FILESHARE_THROUGHPUT_COLD=1     evict the file from the page cache before
//	                                every run, where the OS lets a program
//	                                do it (Linux: posix_fadvise DONTNEED). On
//	                                macOS it cannot be done without root
//	                                (`sudo purge`), and the run says "warm".
//	FILESHARE_THROUGHPUT_FORCE=1    run although the 1-minute load average is
//	                                above 8; the table is then stamped
//	                                INVALID. Times taken under load are not
//	                                measurements; allocation counts are.
//
// Against the references, from outside Go: the same file, the same client,
// pointed at Linux knfsd, Samba or OpenSSH's sftp-server (run it under
// `sshd -D -p N -o Subsystem="sftp /usr/lib/openssh/sftp-server"`):
//
//	# sftp: 64 requests in flight (the default) and 1
//	sftp -R 64 -P N -b <(echo 'get big.bin /dev/null') host
//	sftp -R 1  -P N -b <(echo 'get big.bin /dev/null') host
//	# nfs: one connection and eight, cold cache on the client
//	mount -t nfs -o vers=3,nconnect=1,rsize=1048576 host:/tree /mnt/a
//	mount -t nfs -o vers=3,nconnect=8,rsize=1048576 host:/tree /mnt/b
//	echo 3 > /proc/sys/vm/drop_caches; dd if=/mnt/b/big.bin of=/dev/null bs=1M
//	# four clients at once: run four of the above in parallel and add the rates
func TestThroughputAgainstTheHost(t *testing.T) {
	mib, _ := strconv.Atoi(os.Getenv("FILESHARE_THROUGHPUT_MIB"))
	if mib <= 0 {
		t.Skip("set FILESHARE_THROUGHPUT_MIB to run it")
	}
	rounds := 3
	if n, _ := strconv.Atoi(os.Getenv("FILESHARE_THROUGHPUT_ROUNDS")); n > 0 {
		rounds = n
	}
	cold := os.Getenv("FILESHARE_THROUGHPUT_COLD") != ""
	load, loadKnown := loadAverage1()
	invalid := ""
	if loadKnown && load > 8 {
		if os.Getenv("FILESHARE_THROUGHPUT_FORCE") == "" {
			t.Skipf("1-minute load average is %.1f (> 8): times are not measurements now; FILESHARE_THROUGHPUT_FORCE=1 to run anyway", load)
		}
		invalid = fmt.Sprintf("  INVALID: load %.1f > 8", load)
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
}
serve "webdav" { addr = "127.0.0.1:0" }
serve "sftp"   { addr = "127.0.0.1:0" }
serve "nfs"    { addr = "127.0.0.1:0" }
serve "smb"    { addr = "127.0.0.1:0" }
`, hclPath(pw), pub, hclPath(tree)))

	configs := []struct {
		name string
		read func() int64
	}{
		{"host", func() int64 { return hostRead(t, path) }},
		{"webdav", func() int64 { return webdavRead(t, r.addrs["webdav"], "/tree/big.bin") }},
		{"sftp r64", func() int64 { return sftpRead(t, r.addrs["sftp"], key, "/tree/big.bin", 64) }},
		{"sftp r1", func() int64 { return sftpRead(t, r.addrs["sftp"], key, "/tree/big.bin", 1) }},
		{"smb", func() int64 { return smbRead(t, r.addrs["smb"], "tree", "big.bin") }},
		{"nfs c1", func() int64 { return nfsRead(t, r.addrs["nfs"], "/tree", "big.bin", size, 1) }},
		{"nfs c4", func() int64 { return nfsRead(t, r.addrs["nfs"], "/tree", "big.bin", size, 4) }},
		{"nfs c8", func() int64 { return nfsRead(t, r.addrs["nfs"], "/tree", "big.bin", size, 8) }},
	}

	evicted := false
	prepare := func() {
		if cold {
			evicted = evictFromCache(path)
		}
	}
	if !cold {
		for _, c := range configs {
			c.read() // warm
		}
	}
	samples := make([][2][]float64, len(configs)) // [x1, x4] per configuration
	for range rounds {
		for i, c := range configs {
			for k, n := range []int{1, 4} {
				prepare()
				samples[i][k] = append(samples[i][k], rate(t, size, n, c.read))
			}
		}
	}

	var b strings.Builder
	state := "page cache warm"
	switch {
	case cold && evicted:
		state = "page cache evicted before every run"
	case cold:
		state = "page cache WARM (eviction not possible here; see FILESHARE_THROUGHPUT_COLD)"
	}
	loadText := "load unknown"
	if loadKnown {
		loadText = fmt.Sprintf("load %.1f", load)
	}
	fmt.Fprintf(&b, "%d MiB file, %s, %d interleaved rounds, median, %s%s\n", mib, state, rounds, loadText, invalid)
	fmt.Fprintf(&b, "%-10s %12s %8s %12s %8s\n", "", "x1 MB/s", "/host", "x4 MB/s", "/host")
	host1, host4 := median(samples[0][0]), median(samples[0][1])
	for i, c := range configs {
		one, four := median(samples[i][0]), median(samples[i][1])
		fmt.Fprintf(&b, "%-10s %12.0f %7.0f%% %12.0f %7.0f%%\n", c.name, one, 100*one/host1, four, 100*four/host4)
	}
	t.Log("\n" + b.String())
}

// rate runs read on n goroutines at once and returns the aggregate rate in
// MB/s (10^6 bytes, as dd and fio say it).
func rate(t *testing.T, size int64, n int, read func() int64) float64 {
	t.Helper()
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
	return float64(size) * float64(n) / time.Since(begin).Seconds() / 1e6
}

func median(rates []float64) float64 {
	s := append([]float64(nil), rates...)
	sort.Float64s(s)
	return s[len(s)/2]
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

// sftpRead reads the file with `depth` requests outstanding on it
// (pkg/sftp's MaxConcurrentRequestsPerFile; OpenSSH's sftp keeps 64).
func sftpRead(t *testing.T, addr string, key ssh.Signer, path string, depth int) int64 {
	c, done, err := sftpAsWith(t, addr, "alice", ssh.PublicKeys(key), sftp.MaxConcurrentRequestsPerFile(depth))
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

// sftpAsWith is sftpAs with client options.
func sftpAsWith(t *testing.T, addr, user string, auth ssh.AuthMethod, opts ...sftp.ClientOption) (*sftp.Client, func(), error) {
	t.Helper()
	c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		return nil, func() {}, err
	}
	cl, err := sftp.NewClient(c, opts...)
	if err != nil {
		c.Close()
		return nil, func() {}, err
	}
	return cl, func() { cl.Close(); c.Close() }, nil
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

// nfsCaller returns a function that makes one NFSv3 call on c and returns the
// reply body after the RPC header.
func nfsCaller(t *testing.T, c net.Conn) func(proc uint32, args []byte) []byte {
	return func(proc uint32, args []byte) []byte {
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
}

// nfsRead reads the file with NFSv3 READs, one at a time on each of `conns`
// connections, each connection reading its own stripe of the file: what a
// client with no read-ahead and mount option nconnect=conns would do. Each
// READ asks for 1 MiB, the Linux client's default rsize, and gets what the
// server's rtmax allows.
func nfsRead(t *testing.T, addr, export, name string, size int64, conns int) int64 {
	root := nfsMount(t, addr, export)
	dial := func() (net.Conn, func(proc uint32, args []byte) []byte) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Error(err)
			return nil, nil
		}
		return c, nfsCaller(t, c)
	}
	c0, call0 := dial()
	if c0 == nil {
		return 0
	}
	defer c0.Close()
	res := call0(3, append(xdrOpaque(root), xdrOpaque([]byte(name))...)) // LOOKUP
	if getBE32(res) != 0 {
		t.Errorf("LOOKUP %s: status %d", name, getBE32(res))
		return 0
	}
	fh := append([]byte(nil), res[8:8+getBE32(res[4:])]...)

	const count = 1 << 20
	stripe := (size/int64(conns) + count - 1) / count * count
	var total int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := range conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, call := c0, call0
			if i > 0 {
				if c, call = dial(); c == nil {
					return
				}
				defer c.Close()
			}
			lo, hi := int64(i)*stripe, min(int64(i+1)*stripe, size)
			var got int64
			for off := lo; off < hi; {
				args := append(xdrOpaque(fh), xdrU32(uint32(off>>32), uint32(off), count)...)
				res := call(6, args) // READ
				if getBE32(res) != 0 {
					t.Errorf("READ at %d: status %d", off, getBE32(res))
					break
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
			mu.Lock()
			total += got
			mu.Unlock()
		}()
	}
	wg.Wait()
	return total
}
