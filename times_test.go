// SPDX-License-Identifier: BSD-3-Clause

//go:build !nonfs && !nowebdav && !nosmb && !nosftp

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2"
	fat32 "github.com/go-filesystems/fat32"
	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/osfs"
	"github.com/go-filesystems/remote"
	ufs "github.com/go-filesystems/ufs"
	"golang.org/x/crypto/ssh"

	"github.com/pkg/sftp"
)

// Real timestamps over four protocols (interface v0.6.0 TimesReader, interface#14).
//
// The expected time is the one the driver records, read back from the driver
// itself, and each protocol is compared with it at the COARSER of the format's
// resolution and the protocol's own (SFTP v3: 1 s; WebDAV getlastmodified: 1 s;
// SMB FILETIME: 100 ns; NFSv3 nfstime3: 1 ns). "Now" is excluded by two
// separate means: the fixture's mtime is 90 days old, and the FAT image is left
// to age for three seconds -- longer than its 2 s write resolution -- before it
// is served.

// timesFixture is a host directory with one file of known times, and a FAT
// image whose file the driver stamped when it was written.
type timesFixture struct {
	dir, img         string
	hostM, hostA     time.Time // what the host file was given (os.Chtimes)
	host, fat        filesystem.FileTimes
	servedAfterWrite time.Time
}

func newTimesFixture(t *testing.T) *timesFixture {
	t.Helper()
	dir := t.TempDir()
	tree := filepath.Join(dir, "tree")
	if err := os.Mkdir(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &timesFixture{dir: tree}
	f.hostM = time.Now().Add(-90 * 24 * time.Hour).Truncate(time.Second).Add(123456789)
	f.hostA = f.hostM.Add(3*time.Hour + 500*time.Millisecond)
	if err := os.Chtimes(filepath.Join(tree, "a.txt"), f.hostA, f.hostM); err != nil {
		t.Fatal(err)
	}
	host, err := osfs.Open(tree)
	if err != nil {
		t.Fatal(err)
	}
	f.host, err = host.Times("/a.txt")
	host.Close()
	if err != nil {
		t.Fatal(err)
	}
	if m, ok := f.host.Mtime.Get(); !ok || !m.Equal(f.hostM) {
		t.Skipf("this filesystem keeps the mtime as %v, not the %v it was given", f.host.Mtime, f.hostM)
	}

	f.img = image(t, dir, "fat.img", map[string]string{"/a.txt": "hello"})
	time.Sleep(3 * time.Second)
	f.servedAfterWrite = time.Now()
	imgFile, err := os.Open(f.img)
	if err != nil {
		t.Fatal(err)
	}
	defer imgFile.Close()
	st, err := imgFile.Stat()
	if err != nil {
		t.Fatal(err)
	}
	fsys, err := fat32.OpenReader(imgFile, st.Size())
	if err != nil {
		t.Fatal(err)
	}
	f.fat, err = fsys.(filesystem.TimesReader).Times("/a.txt")
	fsys.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !f.fat.Mtime.Recorded() || f.fat.Mtime.Resolution() != 2*time.Second {
		t.Fatalf("control: FAT mtime %v at %v", f.fat.Mtime, f.fat.Mtime.Resolution())
	}
	if f.fat.Ctime.Recorded() {
		t.Fatalf("control: FAT has no ctime, the driver says %v", f.fat.Ctime)
	}
	if m, _ := f.fat.Mtime.Get(); f.servedAfterWrite.Sub(m) < 2*time.Second {
		t.Fatalf("control: the FAT mtime %v is not older than 2 s at %v", m, f.servedAfterWrite)
	}
	return f
}

func (f *timesFixture) shares() string {
	return fmt.Sprintf("share \"host\" { directory = %q }\nshare \"fat\" { image = %q }\n", hclPath(f.dir), hclPath(f.img))
}

// agree reports whether got and want are the same instant at the coarser of
// their resolutions.
func agree(got, want time.Time, res ...time.Duration) bool {
	r := time.Nanosecond
	for _, x := range res {
		r = max(r, x)
	}
	return got.Truncate(r).Equal(want.Truncate(r))
}

func recorded(ts filesystem.Timestamp) (time.Time, time.Duration) {
	m, _ := ts.Get()
	return m, ts.Resolution()
}

func TestSFTPServesTheRecordedTimes(t *testing.T) {
	needUsers(t)
	f := newTimesFixture(t)
	key, pub := keyPair(t)
	r := start(t, fmt.Sprintf("user \"alice\" { authorized_keys = [%q] }\n%sserve \"sftp\" { addr = \"127.0.0.1:0\" }\n", pub, f.shares()))
	c, done, err := sftpAs(t, r.addrs["sftp"], "alice", ssh.PublicKeys(key))
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	for name, want := range map[string]filesystem.FileTimes{"host": f.host, "fat": f.fat} {
		fi, err := c.Stat("/" + name + "/a.txt")
		if err != nil {
			t.Fatal(err)
		}
		m, mres := recorded(want.Mtime)
		if !agree(fi.ModTime(), m, mres, time.Second) {
			t.Errorf("%s: SFTP mtime %v, the driver records %v (resolution %v)", name, fi.ModTime(), m, mres)
		}
		if age := time.Since(fi.ModTime()); age < 2*time.Second {
			t.Errorf("%s: SFTP mtime %v is \"now\"", name, fi.ModTime())
		}
		st := fi.Sys().(*sftp.FileStat)
		if a, ares := recorded(want.Atime); !agree(time.Unix(int64(st.Atime), 0), a, ares, time.Second) {
			t.Errorf("%s: SFTP atime %v, the driver records %v (resolution %v)", name, time.Unix(int64(st.Atime), 0), a, ares)
		}
	}
}

// OpenSSH's own sftp, as the judge of the one thing a person looks at: ls -l.
func TestOpenSSHListsTheRecordedTime(t *testing.T) {
	needUsers(t)
	_, sftpBin := needOpenSSH(t)
	f := newTimesFixture(t)
	dir := t.TempDir()
	keyFile, _, _ := keyFiles(t, dir, "k")
	pub, err := os.ReadFile(keyFile + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	r := start(t, fmt.Sprintf("user \"alice\" { authorized_keys = [%q] }\n%sserve \"sftp\" { addr = \"127.0.0.1:0\" }\n",
		strings.TrimSpace(string(pub)), f.shares()))
	host, port, _ := strings.Cut(r.addrs["sftp"], ":")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, sftpBin, "-b", "-", "-P", port, "-o", "ConnectTimeout=10",
		"-i", keyFile, "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes", "alice@"+host)
	cmd.Stdin = strings.NewReader("ls -l /host\nls -l /fat\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sftp: %v\n%s", err, out)
	}
	// ls -l shows the minute for a time less than six
	// months old; the host file is 90 days old.
	// (OpenSSH formats the attribute with gmtime: UTC, whatever the client's zone.)
	want := f.hostM.UTC().Format("Jan _2 15:04")
	var line string
	for l := range strings.SplitSeq(string(out), "\n") {
		if strings.HasSuffix(strings.TrimSpace(l), "a.txt") && strings.Contains(l, want) {
			line = l
		}
	}
	if line == "" {
		t.Errorf("no listing says %q for a.txt:\n%s", want, out)
	}
	// And the FAT file is listed with its own minute, which is not 90 days ago.
	fm, _ := f.fat.Mtime.Get()
	if wantFat := fm.UTC().Format("Jan _2 15:04"); !strings.Contains(string(out), wantFat) {
		t.Errorf("no listing says %q (the FAT mtime):\n%s", wantFat, out)
	}
}

func TestSMBServesTheRecordedTimes(t *testing.T) {
	needUsers(t)
	f := newTimesFixture(t)
	r := start(t, onlyProtocol(t, t.TempDir(), "smb", f.shares()))
	for name, want := range map[string]filesystem.FileTimes{"host": f.host, "fat": f.fat} {
		share := mountSMB(t, r, "alice", "hunter2", name)
		fi, err := share.Stat("a.txt")
		if err != nil {
			t.Fatal(err)
		}
		st := fi.Sys().(*smb2.FileStat)
		m, mres := recorded(want.Mtime)
		if !agree(fi.ModTime(), m, mres, 100*time.Nanosecond) {
			t.Errorf("%s: SMB LastWriteTime %v, the driver records %v (resolution %v)", name, fi.ModTime(), m, mres)
		}
		if time.Since(fi.ModTime()) < 2*time.Second {
			t.Errorf("%s: SMB LastWriteTime %v is \"now\"", name, fi.ModTime())
		}
		if a, ares := recorded(want.Atime); !agree(st.LastAccessTime, a, ares, 100*time.Nanosecond) {
			t.Errorf("%s: SMB LastAccessTime %v, the driver records %v (resolution %v)", name, st.LastAccessTime, a, ares)
		}
		if b, ok := want.Btime.Get(); ok && !agree(st.CreationTime, b, want.Btime.Resolution(), 100*time.Nanosecond) {
			t.Errorf("%s: SMB CreationTime %v, the driver records %v", name, st.CreationTime, b)
		}
	}
}

func TestNFSServesTheRecordedTimes(t *testing.T) {
	f := newTimesFixture(t)
	r := start(t, f.shares()+"serve \"nfs\" { addr = \"127.0.0.1:0\" }\n")
	addr := r.addrs["nfs"]
	for name, want := range map[string]filesystem.FileTimes{"host": f.host, "fat": f.fat} {
		dir := nfsMount(t, addr, "/"+name)
		res := nfsRPC(t, addr, 100003, 3, 3, append(xdrOpaque(dir), xdrOpaque([]byte("a.txt"))...))
		if len(res) < 8 || getBE32(res) != 0 {
			t.Fatalf("%s: LOOKUP: % x", name, res)
		}
		fh := res[8 : 8+getBE32(res[4:])]
		attr := nfsRPC(t, addr, 100003, 3, 1, xdrOpaque(fh))
		if len(attr) < 4+84 || getBE32(attr) != 0 {
			t.Fatalf("%s: GETATTR: % x", name, attr)
		}
		// fattr3 (RFC 1813 §2.5.2): atime, mtime and ctime are at 60, 68, 76.
		at := func(off int) time.Time {
			return time.Unix(int64(getBE32(attr[4+off:])), int64(getBE32(attr[4+off+4:])))
		}
		atime, mtime, ctime := at(60), at(68), at(76)
		m, mres := recorded(want.Mtime)
		if !agree(mtime, m, mres) {
			t.Errorf("%s: NFS mtime %v, the driver records %v (resolution %v)", name, mtime, m, mres)
		}
		if time.Since(mtime) < 2*time.Second {
			t.Errorf("%s: NFS mtime %v is \"now\"", name, mtime)
		}
		if a, ares := recorded(want.Atime); !agree(atime, a, ares) {
			t.Errorf("%s: NFS atime %v, the driver records %v (resolution %v)", name, atime, a, ares)
		}
		// A time the format does not keep is the mtime: FAT has no ctime.
		wantC := m
		if c, ok := want.Ctime.Get(); ok {
			wantC = c
		}
		if !agree(ctime, wantC, want.Ctime.Resolution(), mres) {
			t.Errorf("%s: NFS ctime %v, want %v (the driver records %v)", name, ctime, wantC, want.Ctime)
		}
	}
}

var (
	davModified = regexp.MustCompile(`<(?:\w+:)?getlastmodified[^>]*>([^<]*)<`)
	davCreated  = regexp.MustCompile(`<(?:\w+:)?creationdate[^>]*>([^<]*)<`)
)

func TestWebDAVServesTheRecordedTimes(t *testing.T) {
	needUsers(t)
	f := newTimesFixture(t)
	r := start(t, onlyProtocol(t, t.TempDir(), "webdav", f.shares()))
	for name, want := range map[string]filesystem.FileTimes{"host": f.host, "fat": f.fat} {
		req, _ := http.NewRequest("PROPFIND", "http://"+r.addrs["webdav"]+"/"+name+"/a.txt", strings.NewReader(
			`<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop><D:getlastmodified/><D:creationdate/></D:prop></D:propfind>`))
		req.Header.Set("Depth", "0")
		req.SetBasicAuth("alice", "hunter2")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusMultiStatus {
			t.Fatalf("%s: PROPFIND: %d\n%s", name, res.StatusCode, body)
		}
		mm := davModified.FindStringSubmatch(string(body))
		if mm == nil {
			t.Fatalf("%s: no getlastmodified in\n%s", name, body)
		}
		got, err := http.ParseTime(mm[1])
		if err != nil {
			t.Fatal(err)
		}
		m, mres := recorded(want.Mtime)
		if !agree(got, m, mres, time.Second) {
			t.Errorf("%s: WebDAV getlastmodified %v, the driver records %v (resolution %v)", name, got, m, mres)
		}
		if time.Since(got) < 2*time.Second {
			t.Errorf("%s: WebDAV getlastmodified %v is \"now\"", name, got)
		}
		// creationdate is the birth time, and absent when none is recorded.
		cm := davCreated.FindStringSubmatch(string(body))
		if b, ok := want.Btime.Get(); ok {
			if cm == nil {
				t.Errorf("%s: no creationdate, the driver records %v", name, b)
			} else if cd, err := time.Parse(time.RFC3339, cm[1]); err != nil || !agree(cd, b, want.Btime.Resolution(), time.Second) {
				t.Errorf("%s: WebDAV creationdate %q (%v), the driver records %v", name, cm[1], err, b)
			}
		} else if cm != nil && strings.TrimSpace(cm[1]) != "" {
			t.Errorf("%s: WebDAV creationdate %q, the driver records none", name, cm[1])
		}
	}
}

// A driver without the capability is served as before: no Times is invented
// by the wrappers, the union says "unsupported", and SMB still answers now.
func TestADriverWithoutTimesIsServedAsBefore(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "ufs.img")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(16 << 20); err != nil {
		t.Fatal(err)
	}
	u, err := ufs.Mkfs(file, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := any(u).(filesystem.TimesReader); ok {
		t.Skip("ufs gained TimesReader: pick another driver for this control")
	}
	if err := u.WriteFile("/a.txt", []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	file.Close()

	if _, ok := lockFS(plainFS{}).(filesystem.TimesReader); ok {
		t.Error("lockFS invented TimesReader for a driver without it")
	}
	un := &unionFS{entries: []unionEntry{{name: "u", fsys: lockFS(plainFS{})}}}
	if _, err := un.Times("/u/a.txt"); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("union Times over a driver without it: %v, want ErrUnsupported", err)
	}
	if _, err := un.Times("/u"); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("union Times of a share's own directory: %v, want ErrUnsupported", err)
	}

	shares := fmt.Sprintf("share \"u\" { image = %q }\n", hclPath(path))
	smbR := start(t, onlyProtocol(t, t.TempDir(), "smb", shares))
	fi, err := mountSMB(t, smbR, "alice", "hunter2", "u").Stat("a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(fi.ModTime()); d < -time.Minute || d > time.Minute {
		t.Errorf("SMB LastWriteTime %v of a driver without Times is not \"now\" (%v away)", fi.ModTime(), d)
	}
	if fi.Size() != 5 {
		t.Errorf("SMB size %d", fi.Size())
	}

	key, pub := keyPair(t)
	sftpR := start(t, fmt.Sprintf("user \"alice\" { authorized_keys = [%q] }\n%sserve \"sftp\" { addr = \"127.0.0.1:0\" }\n", pub, shares))
	c, done, err := sftpAs(t, sftpR.addrs["sftp"], "alice", ssh.PublicKeys(key))
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	if sf, err := c.Stat("/u/a.txt"); err != nil || sf.Size() != 5 {
		t.Errorf("SFTP stat: %v, %v", sf, err)
	}

	davR := start(t, onlyProtocol(t, t.TempDir(), "webdav", shares))
	if b, err := webdavGet(davR, "alice", "hunter2", "/u/a.txt"); err != nil || string(b) != "hello" {
		t.Errorf("WebDAV GET: %q, %v", b, err)
	}

	nfsR := start(t, shares+"serve \"nfs\" { addr = \"127.0.0.1:0\" }\n")
	root := nfsMount(t, nfsR.addrs["nfs"], "/u")
	res := nfsRPC(t, nfsR.addrs["nfs"], 100003, 3, 3, append(xdrOpaque(root), xdrOpaque([]byte("a.txt"))...))
	if getBE32(res) != 0 {
		t.Errorf("NFS LOOKUP: status %d", getBE32(res))
	}
}

// The time crosses the worker boundary: osfs behind remote.Serve, the client
// remote.New hands to the union, and the union answers Times for it.
func TestTheTimeCrossesTheRemoteWorker(t *testing.T) {
	f := newTimesFixture(t)
	host, err := osfs.Open(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	go func() { _ = remote.Serve(b, host); host.Close() }()
	rfs, err := remote.New(a)
	if err != nil {
		t.Fatal(err)
	}
	defer rfs.Close()
	un := &unionFS{entries: []unionEntry{{name: "home", fsys: rfs}}}
	for name, tr := range map[string]filesystem.TimesReader{"remote client": rfs, "union over the worker": underHome{un}} {
		ft, err := tr.Times("/a.txt")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for what, p := range map[string][2]filesystem.Timestamp{
			"mtime": {ft.Mtime, f.host.Mtime}, "atime": {ft.Atime, f.host.Atime},
			"ctime": {ft.Ctime, f.host.Ctime}, "btime": {ft.Btime, f.host.Btime},
		} {
			if p[0] != p[1] {
				t.Errorf("%s: %s %v across the worker, the host records %v", name, what, p[0], p[1])
			}
		}
	}
}

// underHome asks the union for a path under /home.
type underHome struct{ u *unionFS }

func (h underHome) Times(p string) (filesystem.FileTimes, error) { return h.u.Times("/home" + p) }
