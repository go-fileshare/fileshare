// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !nogrpc && !nowebdav && !nosftp && !nonfs && !nosmb

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cloudsoda/go-smb2"
	"github.com/grpc-transports/control"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	adminv1 "github.com/go-fileshare/fileshare/proto/fileshare/admin/v1"
)

// THE WHOLE CHAIN, ON REAL FILESYSTEMS. The CI job "provisioner" runs this
// as root after the provisioner's own integration tests, on the same four
// filesystems:
//
//   - `fileshare provisioner` runs as root, answering uid nobody;
//   - `fileshare check` runs as root and must say it would serve no volume;
//   - before the fills, a volume of each kind is shared with nobody named
//     (read-only for anyone, so NFS serves it too), and what every protocol's
//     client is told its size and free space are is measured -- and measured
//     again after 8 MiB are written into it: E2E-SIZE lines. statfs inside
//     the volume is measured beside them: for btrfs it is the WHOLE
//     filesystem (its statfs ignores qgroups), which every protocol reported
//     before capacity.go;
//   - `fileshare serve` runs as nobody -- a copy of this test binary, the
//     helper below -- with the admin API's allowed_uids naming nobody, and
//     drives it as nobody: CreateVolume on every parent, CreateShare from
//     each, writes as a granted person over WebDAV and over SFTP until the
//     volume is full, and checks the answer each protocol gives; then
//     DeleteVolume (refused while used), DeleteShare, DeleteVolume.
//
// It is nobody who writes because ext4 lets root past a project quota: a
// fill run as root would prove nothing there. Every skip says "volume e2e:",
// and the job fails on any.

const (
	e2eUID   = 65534
	e2eGID   = 65534
	e2eQuota = 32 << 20
	e2eChunk = 1 << 20
)

// An e2eResult is what the helper measured on one volume.
type e2eResult struct {
	Parent   string `json:"parent"`
	Kind     string `json:"kind"`
	Protocol string `json:"protocol"`
	Written  int64  `json:"written"`
	Answer   string `json:"answer"`
	// Size is the share's size as served: what statfs says inside it.
	Size uint64 `json:"size"`
}

// An e2eSize is what one client was told of a 32 MiB volume's size, before
// and after 8 MiB were written into it.
type e2eSize struct {
	Kind     string `json:"kind"`
	Protocol string `json:"protocol"` // "statfs" is the kernel, inside the volume
	Total    uint64 `json:"total"`
	Avail    uint64 `json:"avail"`
	// After is what was available once the 8 MiB were written.
	After uint64 `json:"after"`
}

// e2eSizeWrite is what the size probe writes into its volume.
const e2eSizeWrite = 8 << 20

func TestVolumesEndToEnd(t *testing.T) {
	if os.Getenv("FILESHARE_VOLUME_E2E") == "" {
		t.Skip("volume e2e: FILESHARE_VOLUME_E2E is not set")
	}
	if os.Geteuid() != 0 {
		t.Skip("volume e2e: not root")
	}
	bin := os.Getenv("FILESHARE_BIN")
	if bin == "" {
		t.Skip("volume e2e: FILESHARE_BIN is not set")
	}
	var parents strings.Builder
	for _, p := range []struct{ env, block string }{
		{"FILESHARE_IT_ZFS_DATASET", "  parent \"z\" {\n    zfs  = %q\n    root = %q\n  }\n"},
		{"FILESHARE_IT_BTRFS", "  parent \"b\" {\n    btrfs        = %q\n    enable_quota = true\n  }\n"},
		{"FILESHARE_IT_XFS", "  parent \"x\" {\n    xfs         = %q\n    project_ids = \"300000-300099\"\n  }\n"},
		{"FILESHARE_IT_EXT4", "  parent \"e\" {\n    ext4        = %q\n    project_ids = \"400000-400099\"\n  }\n"},
	} {
		v := os.Getenv(p.env)
		if v == "" {
			t.Skipf("volume e2e: %s is not set", p.env)
		}
		if strings.Contains(p.block, "root") {
			fmt.Fprintf(&parents, p.block, v, os.Getenv("FILESHARE_IT_ZFS_ROOT"))
		} else {
			fmt.Fprintf(&parents, p.block, v)
		}
	}

	d, err := os.MkdirTemp("", "fs-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"run", "pstate"} {
		if err := os.Mkdir(filepath.Join(d, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	serveDir := filepath.Join(d, "serve")
	if err := os.Mkdir(serveDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(serveDir, e2eUID, e2eGID); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(d, "run", "p.sock")
	pcfg := filepath.Join(d, "p.hcl")
	os.WriteFile(pcfg, []byte(fmt.Sprintf(`provisioner {
  listen     = "unix://%s"
  client_uid = %d
  group      = "%d"
  max_volume = "1G"
  state_file = %q
%s}
`, sock, e2eUID, e2eGID, filepath.Join(d, "pstate", "volumes.json"), parents.String())), 0o600)

	var perr bytes.Buffer
	prov := exec.Command(bin, "provisioner", "-c", pcfg)
	prov.Stdout, prov.Stderr = &perr, &perr
	if err := prov.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		prov.Process.Signal(syscall.SIGTERM)
		prov.Wait()
		t.Logf("provisioner output:\n%s", perr.String())
	})
	for deadline := time.Now().Add(30 * time.Second); ; {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the provisioner did not start:\n%s", perr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}

	// `check` as root: it must say it would serve no volume.
	rootDir := filepath.Join(d, "rootcheck")
	os.Mkdir(rootDir, 0o700)
	ccfg := filepath.Join(rootDir, "c.hcl")
	os.WriteFile(ccfg, []byte(fmt.Sprintf(`name = "E2E"
serve "webdav" { addr = "127.0.0.1:0" }
admin {
  listen       = "unix://%s/admin.sock"
  state_file   = "%s/shares.json"
  source_roots = ["/srv/it"]
  provisioner  = "unix://%s"
}
`, rootDir, rootDir, sock)), 0o600)
	out, err := exec.Command(bin, "check", "-c", ccfg).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "this process runs as root (uid 0), so it serves no volume share") {
		t.Fatalf("`fileshare check` as root: %v\n%s", err, out)
	}
	t.Logf("`fileshare check` as root says:\n%s", out)

	// The helper: this test binary, as nobody.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(d, "fileshare.test")
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(helper, data, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(helper, "-test.run=^TestVolumesE2EHelper$", "-test.v", "-test.count=1", "-test.timeout=10m")
	cmd.Dir = serveDir
	cmd.Env = append(os.Environ(), "FILESHARE_VOLUME_E2E_HELPER="+serveDir, "FILESHARE_VOLUME_E2E_SOCK="+sock)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: e2eUID, Gid: e2eGID}}
	hout, herr := cmd.CombinedOutput()
	t.Logf("the helper, as uid %d:\n%s", e2eUID, hout)
	if herr != nil || !strings.Contains(string(hout), "--- PASS: TestVolumesE2EHelper") {
		t.Fatalf("the helper failed: %v", herr)
	}
	var results []e2eResult
	for _, line := range strings.Split(string(hout), "\n") {
		if j, ok := strings.CutPrefix(strings.TrimSpace(line), "E2E-RESULT "); ok {
			var r e2eResult
			if err := json.Unmarshal([]byte(j), &r); err != nil {
				t.Fatalf("%q: %v", line, err)
			}
			results = append(results, r)
		}
	}
	if len(results) != 8 {
		t.Fatalf("%d results, want 8 (4 kinds x WebDAV and SFTP)", len(results))
	}
	var sizes []e2eSize
	for _, line := range strings.Split(string(hout), "\n") {
		if j, ok := strings.CutPrefix(strings.TrimSpace(line), "E2E-SIZE "); ok {
			var r e2eSize
			if err := json.Unmarshal([]byte(j), &r); err != nil {
				t.Fatalf("%q: %v", line, err)
			}
			sizes = append(sizes, r)
		}
	}
	if len(sizes) != 16 {
		t.Fatalf("%d sizes, want 16 (4 kinds x statfs, NFS, WebDAV, SMB)", len(sizes))
	}
	const mib = 1 << 20
	for _, r := range sizes {
		t.Logf("size: %-5s %-6s total %6.1f MiB, available %6.1f MiB, after writing 8 MiB %6.1f MiB",
			r.Kind, r.Protocol, float64(r.Total)/mib, float64(r.Avail)/mib, float64(r.After)/mib)
		if r.Protocol == "statfs" {
			continue // the kernel's, for comparison: btrfs's is the whole filesystem
		}
		// Every protocol, every kind: the quota, give or take what a
		// filesystem keeps for itself, and 8 MiB less after 8 MiB.
		if r.Total < e2eQuota-2*mib || r.Total > e2eQuota+2*mib {
			t.Errorf("%s over %s: a %d-byte volume reported as %d bytes", r.Kind, r.Protocol, e2eQuota, r.Total)
		}
		if r.Avail > r.Total || r.After > r.Avail-e2eSizeWrite+mib || r.After+e2eSizeWrite+2*mib < r.Avail {
			t.Errorf("%s over %s: available %d, then %d after writing %d", r.Kind, r.Protocol, r.Avail, r.After, e2eSizeWrite)
		}
	}
	for _, r := range results {
		t.Logf("%-5s %-6s %9d bytes into a %d-byte volume, then %s (the share's size: %d)", r.Kind, r.Protocol, r.Written, e2eQuota, r.Answer, r.Size)
	}
}

// TestVolumesE2EHelper is `fileshare serve` as nobody, and its client.
func TestVolumesE2EHelper(t *testing.T) {
	dir := os.Getenv("FILESHARE_VOLUME_E2E_HELPER")
	if dir == "" {
		t.Skip("run by TestVolumesEndToEnd only")
	}
	if os.Getuid() != e2eUID {
		t.Fatalf("the helper runs as uid %d", os.Getuid())
	}
	// The real read of /proc/self/status, not a seam.
	if why := processQuotaExempt(); why != "" {
		t.Fatalf("nobody is judged quota-exempt: %s", why)
	}
	key, pub := keyPair(t)
	pw := write(t, dir, "alice.pw", "hunter2\n")
	cfgPath := write(t, dir, "serve.hcl", fmt.Sprintf(`name = "E2E"
user "alice" {
  password_file   = %q
  authorized_keys = [%q]
}
serve "webdav" { addr = "127.0.0.1:0" }
serve "sftp"   { addr = "127.0.0.1:0" }
serve "nfs"    { addr = "127.0.0.1:0" }
serve "smb"    { addr = "127.0.0.1:0" }
admin {
  listen          = "unix://%s/admin.sock"
  state_file      = "%s/shares.json"
  source_roots    = ["/srv/it"]
  provisioner     = "unix://%s"
  provisioner_uid = 0
  allowed_uids    = [%d]
}
`, pw, pub, dir, dir, os.Getenv("FILESHARE_VOLUME_E2E_SOCK"), e2eUID))
	cfg, err := loadConfig([]string{cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := withState(cfg); err != nil {
		t.Fatal(err)
	}
	out := &safeBuffer{}
	srv, err := open(cfg, out)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.run(ctx, cfg) }()
	defer func() {
		cancel()
		<-done
		srv.Close()
		t.Logf("the server said:\n%s", out)
	}()
	for deadline := time.Now().Add(10 * time.Second); srv.mgr.Load() == nil || !srv.ready.Load(); {
		select {
		case err := <-done:
			// Put back for the deferred receive, which would wait forever.
			done <- err
			t.Fatalf("the server stopped: %v\n%s", err, out)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("never ready:\n%s", out)
		}
		time.Sleep(10 * time.Millisecond)
	}
	addrs := map[string]string{}
	srv.runMu.Lock()
	for _, f := range srv.feeds {
		addrs[f.proto] = f.ln.Addr().String()
	}
	srv.runMu.Unlock()
	conn, err := control.Dial(control.ClientConfig{Target: "unix://" + dir + "/admin.sock"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	api := adminv1.NewAdminServiceClient(conn)

	parents, err := api.ListParents(ctx, &adminv1.ListParentsRequest{})
	if err != nil || len(parents.GetParents()) != 4 {
		t.Fatalf("ListParents: %v %v", parents, err)
	}
	for _, p := range parents.GetParents() {
		kind := strings.ToLower(strings.TrimPrefix(p.GetKind().String(), "VOLUME_KIND_"))
		for _, r := range probeSize(t, ctx, api, addrs, p.GetId(), kind) {
			j, _ := json.Marshal(r)
			fmt.Printf("E2E-SIZE %s\n", j)
		}
		for _, proto := range []string{"webdav", "sftp"} {
			name := "e2e-" + proto
			share := p.GetId() + "-" + proto
			v, err := api.CreateVolume(ctx, &adminv1.CreateVolumeRequest{Parent: p.GetId(), Name: name, QuotaBytes: e2eQuota})
			if err != nil {
				t.Fatalf("%s: CreateVolume: %v", kind, err)
			}
			created, err := api.CreateShare(ctx, &adminv1.CreateShareRequest{Name: share,
				Source: volumeSource(p.GetId(), name), Grants: aliceWrites()})
			if err != nil {
				t.Fatalf("%s: CreateShare from %s: %v", kind, v.GetVolume().GetPath(), err)
			}
			var r e2eResult
			if proto == "webdav" {
				r = fillWebDAV(t, addrs["webdav"], share)
			} else {
				r = fillSFTP(t, addrs["sftp"], share, key)
			}
			r.Parent, r.Kind, r.Protocol, r.Size = p.GetId(), kind, proto, created.GetShare().GetSizeBytes()
			j, _ := json.Marshal(r)
			fmt.Printf("E2E-RESULT %s\n", j)
			if r.Written < e2eQuota/2 || r.Written > e2eQuota+8*e2eChunk {
				t.Errorf("%s over %s: %d bytes into a %d-byte volume", kind, proto, r.Written, e2eQuota)
			}

			_, err = api.DeleteVolume(ctx, &adminv1.DeleteVolumeRequest{Parent: p.GetId(), Name: name, DestroyData: true})
			if status.Code(err) != codes.FailedPrecondition {
				t.Errorf("%s: DeleteVolume while %s uses it: %v", kind, share, err)
			}
			if _, err := api.DeleteShare(ctx, &adminv1.DeleteShareRequest{Name: share}); err != nil {
				t.Fatalf("%s: DeleteShare: %v", kind, err)
			}
			if d, err := api.DeleteVolume(ctx, &adminv1.DeleteVolumeRequest{Parent: p.GetId(), Name: name, DestroyData: true}); err != nil || !d.GetDeleted() {
				t.Fatalf("%s: DeleteVolume: %v %v", kind, d, err)
			}
		}
	}
}

// fillWebDAV PUTs random megabytes as alice until the server refuses one:
// the refusal must be 507 Insufficient Storage.
func fillWebDAV(t *testing.T, addr, share string) e2eResult {
	t.Helper()
	chunk := make([]byte, e2eChunk)
	var r e2eResult
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	for i := range 4 * e2eQuota / e2eChunk {
		rand.Read(chunk) // random: ZFS compresses a repeated pattern away
		req, _ := http.NewRequest(http.MethodPut, fmt.Sprintf("http://%s/%s/f%03d", addr, share, i), bytes.NewReader(chunk))
		req.SetBasicAuth("alice", "hunter2")
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		res.Body.Close()
		if res.StatusCode == http.StatusCreated {
			r.Written += e2eChunk
			continue
		}
		r.Answer = fmt.Sprintf("HTTP %d", res.StatusCode)
		if res.StatusCode != 507 {
			t.Errorf("%s: a full volume answered %d, want 507", share, res.StatusCode)
		}
		return r
	}
	t.Errorf("%s: %d bytes written and never full", share, r.Written)
	return r
}

// fillSFTP writes random megabytes into one file as alice until a write
// fails: SSH_FX_FAILURE saying "no space".
func fillSFTP(t *testing.T, addr, share string, key ssh.Signer) e2eResult {
	t.Helper()
	c, done, err := sftpAs(t, addr, "alice", ssh.PublicKeys(key))
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	f, err := c.Create("/" + share + "/fill")
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, e2eChunk)
	var r e2eResult
	for range 4 * e2eQuota / e2eChunk {
		rand.Read(chunk)
		n, err := f.Write(chunk)
		r.Written += int64(n)
		if err != nil {
			r.Answer = err.Error()
			if !strings.Contains(err.Error(), "SSH_FX_FAILURE") || !strings.Contains(err.Error(), "no space") {
				t.Errorf("%s: a full volume answered %v", share, err)
			}
			f.Close()
			return r
		}
	}
	f.Close()
	t.Errorf("%s: %d bytes written and never full", share, r.Written)
	return r
}

// probeSize shares a new 32 MiB volume with alice and asks each protocol's
// client, and statfs inside it, what its size and free space are. Not NFS:
// the admin API always names who may use a share, and NFS without kerberos
// or client certificates serves only shares open to everyone -- its size
// hook is the same function, pinned by capacity_protocols_test.go. Then it
// writes 8 MiB into the volume directly (this process is the server's uid),
// syncs so that btrfs commits the qgroup's new count, and waits for each to
// report the space gone.
func probeSize(t *testing.T, ctx context.Context, api adminv1.AdminServiceClient, addrs map[string]string, parent, kind string) []e2eSize {
	t.Helper()
	name, share := "e2e-size", parent+"-size"
	v, err := api.CreateVolume(ctx, &adminv1.CreateVolumeRequest{Parent: parent, Name: name, QuotaBytes: e2eQuota})
	if err != nil {
		t.Fatalf("%s: CreateVolume: %v", kind, err)
	}
	if _, err := api.CreateShare(ctx, &adminv1.CreateShareRequest{Name: share, Source: volumeSource(parent, name), Grants: aliceWrites()}); err != nil {
		t.Fatalf("%s: CreateShare: %v", kind, err)
	}
	path := v.GetVolume().GetPath()
	probes := []struct {
		proto string
		read  func() (total, avail uint64)
	}{
		{"statfs", func() (uint64, uint64) {
			var st syscall.Statfs_t
			if err := syscall.Statfs(path, &st); err != nil {
				t.Fatalf("statfs %s: %v", path, err)
			}
			return st.Blocks * uint64(st.Frsize), st.Bavail * uint64(st.Frsize)
		}},
		{"webdav", func() (uint64, uint64) {
			avail, used := webdavQuota(t, addrs["webdav"], "/"+share+"/")
			return avail + used, avail
		}},
		{"smb", func() (uint64, uint64) {
			fi, err := smbAt(t, addrs["smb"], share).Statfs(".")
			if err != nil {
				t.Fatalf("%s: SMB statfs: %v", kind, err)
			}
			return fi.TotalBlockCount() * fi.BlockSize(), fi.AvailableBlockCount() * fi.BlockSize()
		}},
	}
	out := make([]e2eSize, len(probes))
	for i, p := range probes {
		out[i].Kind, out[i].Protocol = kind, p.proto
		out[i].Total, out[i].Avail = p.read()
	}

	data := make([]byte, e2eSizeWrite)
	rand.Read(data) // random: ZFS compresses a repeated pattern away
	f, err := os.Create(filepath.Join(path, "size.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	// btrfs counts a qgroup's bytes at a transaction commit; a sync makes
	// one rather than waiting out the 30 s commit interval.
	syscall.Sync()
	for i, p := range probes {
		for deadline := time.Now().Add(90 * time.Second); ; {
			_, avail := p.read()
			out[i].After = avail
			if avail+e2eSizeWrite-1<<20 <= out[i].Avail || time.Now().After(deadline) {
				break
			}
			syscall.Sync()
			time.Sleep(500 * time.Millisecond)
		}
	}

	if _, err := api.DeleteShare(ctx, &adminv1.DeleteShareRequest{Name: share}); err != nil {
		t.Fatalf("%s: DeleteShare: %v", kind, err)
	}
	if _, err := api.DeleteVolume(ctx, &adminv1.DeleteVolumeRequest{Parent: parent, Name: name, DestroyData: true}); err != nil {
		t.Fatalf("%s: DeleteVolume: %v", kind, err)
	}
	return out
}

// smbAt mounts share as alice, for a size query.
func smbAt(t *testing.T, addr, share string) *smb2.Share {
	t.Helper()
	cctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: "alice", Password: "hunter2"}}
	s, err := d.Dial(cctx, addr)
	if err != nil {
		cancel()
		t.Fatalf("dialing smb: %v", err)
	}
	fs, err := s.Mount(share)
	if err != nil {
		s.Logoff()
		cancel()
		t.Fatalf("mounting %s: %v", share, err)
	}
	t.Cleanup(func() { fs.Umount(); s.Logoff(); cancel() })
	return fs
}
