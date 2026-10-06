// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package provision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/go-fsctl/btrfs"
	"github.com/go-fsctl/projquota"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"

	"github.com/go-fileshare/fileshare/internal/provisionclient"
	pb "github.com/go-fileshare/fileshare/proto/fileshare/provision/v1"
)

// The integration tests run `fileshare provisioner` as root on real
// filesystems and call it as an UNPRIVILEGED uid over its socket -- the uid
// check is the point, and so is writing as somebody the quota holds: ext4
// lets root (CAP_SYS_RESOURCE) write past a project quota, so a fill run as
// root would prove nothing there.
//
// The CI job "provisioner" builds the filesystems and sets:
//
//	FILESHARE_IT=1                   run at all
//	FILESHARE_BIN                    the fileshare binary
//	FILESHARE_IT_ZFS_DATASET/_ROOT   a dataset and a directory to mount under
//	FILESHARE_IT_BTRFS               a btrfs mount, quotas OFF (enable_quota turns them on)
//	FILESHARE_IT_XFS                 an XFS mount with prjquota
//	FILESHARE_IT_EXT4                an ext4 (-O quota,project) mount with prjquota
//
// Every skip says "integration:", and the job fails on any.

const (
	itUID  = 65534 // nobody: the client_uid
	itGID  = 65534 // nogroup: the volumes' group
	itMiB  = 1 << 20
	itQuot = 32 * itMiB
)

func requireIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("FILESHARE_IT") == "" {
		t.Skip("integration: FILESHARE_IT is not set")
	}
	if os.Geteuid() != 0 {
		t.Skip("integration: not root")
	}
	if os.Getenv("FILESHARE_BIN") == "" {
		t.Skip("integration: FILESHARE_BIN is not set")
	}
}

// itEnv is what the CI job built, by kind.
func itEnv(t *testing.T, kind string) string {
	t.Helper()
	v := map[string]string{"zfs": "FILESHARE_IT_ZFS_DATASET", "btrfs": "FILESHARE_IT_BTRFS",
		"xfs": "FILESHARE_IT_XFS", "ext4": "FILESHARE_IT_EXT4"}[kind]
	s := os.Getenv(v)
	if s == "" {
		t.Skipf("integration: %s is not set", v)
	}
	return s
}

// itWorld is a running provisioner.
type itWorld struct {
	t      *testing.T
	dir    string // world-traversable: the helper's binary lives here
	cfg    string
	sock   string
	cmd    *exec.Cmd
	stderr *bytes.Buffer
	helper string
}

func (w *itWorld) start() {
	w.t.Helper()
	w.stderr = &bytes.Buffer{}
	w.cmd = exec.Command(os.Getenv("FILESHARE_BIN"), "provisioner", "-c", w.cfg)
	w.cmd.Stderr = w.stderr
	w.cmd.Stdout = w.stderr
	if err := w.cmd.Start(); err != nil {
		w.t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if st, err := os.Stat(w.sock); err == nil && st.Mode().Perm() == 0o660 {
			return
		}
		if time.Now().After(deadline) || w.cmd.ProcessState != nil {
			w.stop()
			w.t.Fatalf("the provisioner did not start:\n%s", w.stderr)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (w *itWorld) stop() {
	if w.cmd == nil || w.cmd.Process == nil {
		return
	}
	w.cmd.Process.Signal(syscall.SIGTERM)
	w.cmd.Wait()
	w.t.Logf("provisioner output:\n%s", w.stderr)
	w.cmd = nil
}

func newItWorld(t *testing.T) *itWorld {
	t.Helper()
	requireIntegration(t)
	d, err := os.MkdirTemp("", "fs-it-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"run", "state"} {
		if err := os.Mkdir(filepath.Join(d, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	w := &itWorld{t: t, dir: d, sock: filepath.Join(d, "run", "p.sock"), cfg: filepath.Join(d, "p.hcl")}

	var parents strings.Builder
	if ds := os.Getenv("FILESHARE_IT_ZFS_DATASET"); ds != "" {
		fmt.Fprintf(&parents, "  parent \"z\" {\n    zfs  = %q\n    root = %q\n  }\n", ds, os.Getenv("FILESHARE_IT_ZFS_ROOT"))
	}
	if p := os.Getenv("FILESHARE_IT_BTRFS"); p != "" {
		fmt.Fprintf(&parents, "  parent \"b\" {\n    btrfs        = %q\n    enable_quota = true\n  }\n", p)
	}
	if p := os.Getenv("FILESHARE_IT_XFS"); p != "" {
		fmt.Fprintf(&parents, "  parent \"x\" {\n    xfs         = %q\n    project_ids = \"100000-100099\"\n  }\n", p)
	}
	if p := os.Getenv("FILESHARE_IT_EXT4"); p != "" {
		fmt.Fprintf(&parents, "  parent \"e\" {\n    ext4        = %q\n    project_ids = \"200000-200099\"\n  }\n", p)
	}
	text := fmt.Sprintf(`provisioner {
  listen     = "unix://%s"
  client_uid = %d
  group      = "%d"
  max_volume = "1G"
  state_file = %q
%s}
`, w.sock, itUID, itGID, filepath.Join(d, "state", "volumes.json"), parents.String())
	if err := os.WriteFile(w.cfg, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("configuration:\n%s", text)

	// A copy of this test binary the unprivileged helper can execute.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	w.helper = filepath.Join(d, "provision.test")
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w.helper, data, 0o755); err != nil {
		t.Fatal(err)
	}
	w.start()
	t.Cleanup(w.stop)
	return w
}

// A step is one thing the unprivileged helper does, and its answer.
type step struct {
	Op       string `json:"op"`
	Parent   string `json:"parent,omitempty"`
	Name     string `json:"name,omitempty"`
	Snapshot string `json:"snapshot,omitempty"`
	Quota    uint64 `json:"quota,omitempty"`
	Destroy  bool   `json:"destroy,omitempty"`
	Path     string `json:"path,omitempty"`
	Sock     string `json:"sock,omitempty"`
}

type answer struct {
	Code      string   `json:"code"`
	Msg       string   `json:"msg,omitempty"`
	Created   bool     `json:"created,omitempty"`
	Deleted   bool     `json:"deleted,omitempty"`
	Path      string   `json:"path,omitempty"`
	Quota     uint64   `json:"quota,omitempty"`
	Used      uint64   `json:"used,omitempty"`
	Snapshots []string `json:"snapshots,omitempty"`
	Written   uint64   `json:"written,omitempty"`
	Errno     string   `json:"errno,omitempty"`
	Dials     int32    `json:"dials,omitempty"`
	UID       int      `json:"uid"`
}

const helperResult = "HELPER-RESULT "

// as runs one step as uid nobody, group nogroup.
func (w *itWorld) as(s step) answer {
	w.t.Helper()
	s.Sock = w.sock
	b, _ := json.Marshal(s)
	cmd := exec.Command(w.helper, "-test.run=^TestIntegrationHelper$", "-test.v")
	cmd.Dir = w.dir
	cmd.Env = append(os.Environ(), "FILESHARE_IT_HELPER="+string(b))
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: itUID, Gid: itGID}}
	out, err := cmd.CombinedOutput()
	for _, line := range strings.Split(string(out), "\n") {
		if r, ok := strings.CutPrefix(line, helperResult); ok {
			var a answer
			if err := json.Unmarshal([]byte(r), &a); err != nil {
				w.t.Fatalf("helper said %q: %v", r, err)
			}
			if a.UID != itUID {
				w.t.Fatalf("the helper ran as uid %d", a.UID)
			}
			return a
		}
	}
	w.t.Fatalf("the helper (%s) gave no answer: %v\n%s", b, err, out)
	return answer{}
}

func (w *itWorld) want(s step, code string) answer {
	w.t.Helper()
	a := w.as(s)
	if a.Code != code {
		w.t.Fatalf("%s %s/%s: %s (%s), want %s\nprovisioner so far:\n%s", s.Op, s.Parent, s.Name, a.Code, a.Msg, code, w.stderr)
	}
	return a
}

// TestIntegrationHelper is the unprivileged side: it is this test binary,
// run by `as` under another uid, and does nothing otherwise.
func TestIntegrationHelper(t *testing.T) {
	spec := os.Getenv("FILESHARE_IT_HELPER")
	if spec == "" {
		return
	}
	var s step
	if err := json.Unmarshal([]byte(spec), &s); err != nil {
		t.Fatal(err)
	}
	a := runStep(s)
	a.UID = os.Getuid()
	b, _ := json.Marshal(a)
	fmt.Println(helperResult + string(b))
}

func runStep(s step) answer {
	if s.Op == "fill" {
		n, err := fill(s.Path, s.Quota)
		a := answer{Code: "OK", Written: n}
		var errno syscall.Errno
		if errors.As(err, &errno) {
			a.Errno = unix.ErrnoName(errno)
		} else if err != nil {
			a.Code, a.Msg = "ERROR", err.Error()
		}
		return a
	}
	var dials atomic.Int32
	c, err := provisionclient.Dial(s.Sock, provisionclient.WithDialOption(grpc.WithContextDialer(
		func(ctx context.Context, addr string) (net.Conn, error) {
			dials.Add(1)
			var d net.Dialer
			return d.DialContext(ctx, "unix", strings.TrimPrefix(addr, "unix://"))
		})))
	if err != nil {
		return answer{Code: "ERROR", Msg: err.Error()}
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var a answer
	switch s.Op {
	case "create":
		v, created, err := c.Create(ctx, s.Parent, s.Name, s.Quota)
		a = vol(v, err)
		a.Created = created
	case "resize":
		v, err := c.Resize(ctx, s.Parent, s.Name, s.Quota)
		a = vol(v, err)
	case "snapshot":
		v, created, err := c.Snapshot(ctx, s.Parent, s.Name, s.Snapshot)
		a = vol(v, err)
		a.Created = created
	case "get":
		v, err := c.Get(ctx, s.Parent, s.Name)
		a = vol(v, err)
	case "delete":
		ok, err := c.Delete(ctx, s.Parent, s.Name, s.Destroy)
		a = vol(nil, err)
		a.Deleted = ok
	case "unknown":
		// A method the provisioner does not have, then one it does: the
		// second must need a new connection.
		if _, err := c.Capabilities(ctx); err != nil {
			return vol(nil, err)
		}
		err := c.Conn().Invoke(ctx, "/fileshare.provision.v1.ProvisionService/MountAnything", &pb.GetCapabilitiesRequest{}, &pb.GetCapabilitiesResponse{})
		a = vol(nil, err)
		if _, err := c.Capabilities(ctx); err != nil {
			a.Msg += "; then: " + err.Error()
		}
	default:
		return answer{Code: "ERROR", Msg: "no op " + s.Op}
	}
	a.Dials = dials.Load()
	return a
}

// vol is a call's answer. A nil volume reads as empty: protobuf's getters
// are nil-safe.
func vol(v *pb.Volume, err error) answer {
	if err != nil {
		st := status.Convert(err)
		return answer{Code: st.Code().String(), Msg: st.Message()}
	}
	return answer{Code: "OK", Path: v.GetPath(), Quota: v.GetQuotaBytes(), Used: v.GetUsedBytes(), Snapshots: v.GetSnapshots()}
}

// fill writes zeros in 1 MiB chunks, syncing each, until max or an error.
func fill(path string, max uint64) (uint64, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	buf := make([]byte, itMiB)
	for i := range buf {
		buf[i] = byte(i) // not zeros: no filesystem may compress it away
	}
	var n uint64
	for n < max {
		w, err := f.Write(buf)
		n += uint64(w)
		if err == nil {
			err = f.Sync()
		}
		if err != nil {
			var pe *os.PathError
			if errors.As(err, &pe) {
				err = pe.Err
			}
			return n, err
		}
	}
	return n, nil
}

// TestIntegrationProvisioner drives every kind the job built through the
// whole life of a volume, as the unprivileged client_uid.
func TestIntegrationProvisioner(t *testing.T) {
	w := newItWorld(t)

	t.Run("peer", func(t *testing.T) {
		// Root is not client_uid, and is refused like anybody else.
		c, err := provisionclient.Dial(w.sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := c.Capabilities(ctx); status.Code(err).String() != "PermissionDenied" {
			t.Errorf("root calling: %v, want PermissionDenied", err)
		}
		// The client_uid is answered.
		w.want(step{Op: "get", Parent: firstParent(), Name: "nothing-here"}, "NotFound")
		// A method outside the set closes the connection.
		a := w.as(step{Op: "unknown"})
		if a.Code == "OK" || a.Dials < 2 || strings.Contains(a.Msg, "then:") {
			t.Errorf("an unknown method: %+v; want refused, then a second connection that works", a)
		}
		if !strings.Contains(w.stderr.String(), "not a provisioner verb") {
			t.Errorf("the closed connection was not logged")
		}
	})

	for _, k := range []struct {
		kind, parent string
		full         string // the errno a full volume answers with
		slack        uint64 // how far past the quota a write may land
		snapshots    bool
	}{
		{"zfs", "z", "EDQUOT", itQuot / 4, true},
		{"btrfs", "b", "EDQUOT", itQuot / 4, true},
		{"xfs", "x", "ENOSPC", 0, false},
		{"ext4", "e", "EDQUOT", 0, false},
	} {
		t.Run(k.kind, func(t *testing.T) {
			itEnv(t, k.kind)
			p, n := k.parent, "vol-"+k.kind

			// The refusals that need no storage.
			w.want(step{Op: "create", Parent: p, Name: n, Quota: 0}, "InvalidArgument")
			w.want(step{Op: "create", Parent: p, Name: n, Quota: 2 << 30}, "OutOfRange")
			w.want(step{Op: "create", Parent: p, Name: "../" + n, Quota: itQuot}, "InvalidArgument")

			a := w.want(step{Op: "create", Parent: p, Name: n, Quota: itQuot}, "OK")
			if !a.Created || a.Quota != itQuot {
				t.Fatalf("create: %+v", a)
			}
			path := a.Path
			st, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			sys := st.Sys().(*syscall.Stat_t)
			if sys.Uid != 0 || sys.Gid != itGID || st.Mode()&os.ModeSetgid == 0 || st.Mode().Perm() != 0o770 {
				t.Errorf("volume root: uid %d gid %d mode %v; want root:%d 2770", sys.Uid, sys.Gid, st.Mode(), itGID)
			}
			// Idempotent by name.
			if a := w.want(step{Op: "create", Parent: p, Name: n, Quota: itQuot}, "OK"); a.Created {
				t.Error("the same create again created something")
			}
			w.want(step{Op: "create", Parent: p, Name: n, Quota: 2 * itQuot}, "AlreadyExists")

			// Written as client_uid until the filesystem says no.
			f := w.as(step{Op: "fill", Path: filepath.Join(path, "data"), Quota: 2 * itQuot})
			t.Logf("%s: uid %d wrote %d bytes into a %d-byte volume, then %s %s", k.kind, itUID, f.Written, itQuot, f.Errno, f.Msg)
			if f.Errno != k.full {
				t.Fatalf("filling the volume ended with %q (%s), want %s", f.Errno, f.Msg, k.full)
			}
			if f.Written < itQuot/2 || f.Written > itQuot+k.slack {
				t.Errorf("full after %d bytes, want near %d", f.Written, itQuot)
			}
			unix.Sync()
			if g := w.want(step{Op: "get", Parent: p, Name: n}, "OK"); g.Used < itQuot/2 {
				t.Errorf("used_bytes = %d after writing %d", g.Used, f.Written)
			}

			// Never below what is used; growing lets the writer go on.
			w.want(step{Op: "resize", Parent: p, Name: n, Quota: itMiB}, "FailedPrecondition")
			if r := w.want(step{Op: "resize", Parent: p, Name: n, Quota: 3 * itQuot}, "OK"); r.Quota != 3*itQuot {
				t.Errorf("resize: %+v", r)
			}
			if f := w.as(step{Op: "fill", Path: filepath.Join(path, "more"), Quota: 8 * itMiB}); f.Errno != "" || f.Written != 8*itMiB {
				t.Errorf("after growing, writing 8 MiB: %+v", f)
			}

			if k.snapshots {
				if s := w.want(step{Op: "snapshot", Parent: p, Name: n, Snapshot: "monday"}, "OK"); !s.Created || len(s.Snapshots) != 1 {
					t.Errorf("snapshot: %+v", s)
				}
				if s := w.want(step{Op: "snapshot", Parent: p, Name: n, Snapshot: "monday"}, "OK"); s.Created {
					t.Error("the same snapshot again created one")
				}
			} else {
				w.want(step{Op: "snapshot", Parent: p, Name: n, Snapshot: "monday"}, "Unimplemented")
			}

			if k.kind == "zfs" {
				// A reboot unmounts a legacy dataset; the start mounts it
				// again.
				w.stop()
				if err := unix.Unmount(path, 0); err != nil {
					t.Fatal(err)
				}
				w.start()
				data, _ := os.ReadFile("/proc/self/mountinfo")
				if src, fs, ok := parseMountinfo(string(data), path); !ok || fs != "zfs" || !strings.HasSuffix(src, "/"+n) {
					t.Errorf("not mounted again at the start: %q %q %v", src, fs, ok)
				}
				if _, err := os.Stat(filepath.Join(path, "data")); err != nil {
					t.Errorf("the data is not there after the remount: %v", err)
				}
			}

			// Ownership: what it did not create, it does not touch.
			stray := strayOf(t, k.kind, w, p)
			w.want(step{Op: "create", Parent: p, Name: stray, Quota: itQuot}, "AlreadyExists")
			w.want(step{Op: "delete", Parent: p, Name: stray, Destroy: true}, "FailedPrecondition")

			// Delete: refused with data, then destroy_data, then nothing.
			w.want(step{Op: "delete", Parent: p, Name: n}, "FailedPrecondition")
			if d := w.want(step{Op: "delete", Parent: p, Name: n, Destroy: true}, "OK"); !d.Deleted {
				t.Errorf("delete: %+v", d)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the volume is still there: %v", err)
			}
			if d := w.want(step{Op: "delete", Parent: p, Name: n, Destroy: true}, "OK"); d.Deleted {
				t.Error("deleting it again deleted something")
			}
			if !strings.Contains(w.stderr.String(), "audit: delete volume "+p+"/"+n) {
				t.Error("no audit line")
			}
		})
	}
}

func firstParent() string {
	for _, k := range []struct{ env, id string }{{"FILESHARE_IT_ZFS_DATASET", "z"}, {"FILESHARE_IT_BTRFS", "b"},
		{"FILESHARE_IT_XFS", "x"}, {"FILESHARE_IT_EXT4", "e"}} {
		if os.Getenv(k.env) != "" {
			return k.id
		}
	}
	return "z"
}

// strayOf puts, where a volume would go, something of the same kind that the
// provisioner did not create, and returns its name.
func strayOf(t *testing.T, kind string, w *itWorld, parent string) string {
	t.Helper()
	switch kind {
	case "zfs":
		ds := os.Getenv("FILESHARE_IT_ZFS_DATASET")
		// ⛔ The inherited mark, with exactly the value a volume of that
		// name would carry: set on the PARENT dataset, read by its child.
		runCmd(t, "zfs", "set", ownerProp+"="+parent+"/inherited", ds)
		runCmd(t, "zfs", "create", "-o", "mountpoint=legacy", "-o", "refquota="+strconv.Itoa(itQuot), ds+"/inherited")
		t.Cleanup(func() {
			exec.Command("zfs", "destroy", ds+"/inherited").Run()
			exec.Command("zfs", "inherit", ownerProp, ds).Run()
		})
		return "inherited"
	case "btrfs":
		root := os.Getenv("FILESHARE_IT_BTRFS")
		if err := btrfs.SubvolCreate(root, "stray"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { btrfs.SubvolDelete(root, "stray") })
		return "stray"
	default:
		root := os.Getenv(map[string]string{"xfs": "FILESHARE_IT_XFS", "ext4": "FILESHARE_IT_EXT4"}[kind])
		p := filepath.Join(root, "stray")
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(p) })
		// A project id outside the parent's range.
		if err := projquota.SetProject(p, 4242, true); err != nil {
			t.Fatal(err)
		}
		return "stray"
	}
}

func runCmd(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}
