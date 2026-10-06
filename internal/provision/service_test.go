// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package provision

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/go-fsctl/projquota"
	"github.com/go-fsctl/zfs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/go-fileshare/fileshare/proto/fileshare/provision/v1"
)

func create(s *service, parent, name string, quota uint64) (*pb.CreateVolumeResponse, error) {
	return s.CreateVolume(bg, &pb.CreateVolumeRequest{Parent: parent, Name: name, QuotaBytes: quota})
}

func del(s *service, parent, name string, destroy bool) (*pb.DeleteVolumeResponse, error) {
	return s.DeleteVolume(bg, &pb.DeleteVolumeRequest{Parent: parent, Name: name, DestroyData: destroy})
}

func wantCode(t *testing.T, err error, want codes.Code, what string) {
	t.Helper()
	if got := status.Code(err); got != want {
		t.Errorf("%s: %v (%v), want %v", what, got, err, want)
	}
}

func mustCreate(t *testing.T, s *service, parent, name string, quota uint64) *pb.Volume {
	t.Helper()
	r, err := create(s, parent, name, quota)
	if err != nil {
		t.Fatalf("CreateVolume %s/%s: %v", parent, name, err)
	}
	if !r.GetCreated() {
		t.Fatalf("CreateVolume %s/%s: created = false for a new volume", parent, name)
	}
	return r.GetVolume()
}

func TestTheNameGrammar(t *testing.T) {
	good := []string{"a", "0", "home-alice", "a_b", "x" + strings.Repeat("y", 62)}
	bad := []string{"", ".", "..", "A", "-a", "_a", "a.b", "a/b", "a@b", "a#b", "a b", "é",
		"x" + strings.Repeat("y", 63), ".snapshots"}
	for _, n := range good {
		if err := checkName("a volume", n); err != nil {
			t.Errorf("%q refused: %v", n, err)
		}
	}
	for _, n := range bad {
		if err := checkName("a volume", n); status.Code(statusOf(err)) != codes.InvalidArgument {
			t.Errorf("%q accepted (%v)", n, err)
		}
	}
	// And the service applies it before anything else.
	s := newWorld(t).service()
	for _, n := range bad {
		_, err := create(s, "tank", n, 1<<20)
		wantCode(t, err, codes.InvalidArgument, "create "+n)
		_, err = del(s, "tank", n, true)
		wantCode(t, err, codes.InvalidArgument, "delete "+n)
	}
}

func TestARequestNamesAParentNeverAPath(t *testing.T) {
	s := newWorld(t).service()
	for _, p := range []string{"", "/", "/srv", "pool/fs", "../tank", "nope"} {
		_, err := create(s, p, "v", 1<<20)
		wantCode(t, err, codes.InvalidArgument, "parent "+p)
	}
	_, err := s.ListVolumes(bg, &pb.ListVolumesRequest{Parent: "/etc"})
	wantCode(t, err, codes.InvalidArgument, "list /etc")
}

func TestQuotaLimits(t *testing.T) {
	w := newWorld(t)
	s := w.service()
	_, err := create(s, "tank", "v", 0)
	wantCode(t, err, codes.InvalidArgument, "quota 0")
	_, err = create(s, "tank", "v", 1<<40+1)
	wantCode(t, err, codes.OutOfRange, "above max_volume")
	if _, err := create(s, "tank", "v", 1<<40); err != nil {
		t.Errorf("max_volume itself refused: %v", err)
	}
	// The parent full: the ZFS one asks the dataset, the others statfs.
	w.zfs.ds["pool/fs"].props["available"] = uint64(1 << 20)
	_, err = create(s, "tank", "big", 2<<20)
	wantCode(t, err, codes.ResourceExhausted, "zfs parent full")
	w.sys.free = 1 << 20
	_, err = create(s, "plain", "big", 2<<20)
	wantCode(t, err, codes.ResourceExhausted, "xfs parent full")
	// A kernel's own "full", while creating, is the same answer.
	w.sys.free = 1 << 40
	w.zfs.errCreate = syscall.ENOSPC
	_, err = create(s, "tank", "k", 1<<20)
	wantCode(t, err, codes.ResourceExhausted, "ENOSPC from the kernel")
	w.zfs.errCreate = syscall.EDQUOT
	_, err = create(s, "tank", "k", 1<<20)
	wantCode(t, err, codes.ResourceExhausted, "EDQUOT from the kernel")
}

func TestCreateIsIdempotentByName(t *testing.T) {
	for _, parent := range []string{"tank", "fast", "plain", "four"} {
		t.Run(parent, func(t *testing.T) {
			w := newWorld(t)
			s := w.service()
			v := mustCreate(t, s, parent, "data", 8<<20)
			if v.GetPath() != w.path(parent, "data") || v.GetQuotaBytes() != 8<<20 || v.GetParent() != parent || v.GetName() != "data" {
				t.Errorf("volume = %+v", v)
			}
			// Owned root:<group> 2770, fileshare through the group.
			if o := w.sys.owners[w.path(parent, "data")]; o != (owner{0, testGID, os.ModeSetgid | 0o770}) {
				t.Errorf("volume root owner = %+v", o)
			}
			// The same again: OK, the volume that exists, not created.
			r, err := create(s, parent, "data", 8<<20)
			if err != nil || r.GetCreated() || r.GetVolume().GetPath() != v.GetPath() {
				t.Errorf("the same create again = %+v, %v", r, err)
			}
			// Different parameters: ALREADY_EXISTS.
			_, err = create(s, parent, "data", 16<<20)
			wantCode(t, err, codes.AlreadyExists, "a different quota")
			// Delete is idempotent too.
			if r, err := del(s, parent, "data", false); err != nil || !r.GetDeleted() {
				t.Errorf("delete = %+v, %v", r, err)
			}
			if r, err := del(s, parent, "data", false); err != nil || r.GetDeleted() {
				t.Errorf("deleting it again = %+v, %v; want OK, deleted false", r, err)
			}
			if _, err := os.Lstat(w.path(parent, "data")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the volume's directory is still there: %v", err)
			}
			if r, err := del(s, parent, "never", true); err != nil || r.GetDeleted() {
				t.Errorf("deleting what never was = %+v, %v", r, err)
			}
		})
	}
}

func TestZFSCreatesInOneCallWithTheMark(t *testing.T) {
	w := newWorld(t)
	s := w.service()
	mustCreate(t, s, "tank", "data", 8<<20)
	if len(w.zfs.created) != 1 {
		t.Fatalf("%d creates", len(w.zfs.created))
	}
	props := w.zfs.created[0]
	if props["refquota"] != uint64(8<<20) || props["mountpoint"] != zfs.ZFS_MOUNTPOINT_LEGACY || props[ownerProp] != "tank/data" {
		t.Errorf("created with %v", props)
	}
	if m := w.sys.mounts[w.path("tank", "data")]; m != [2]string{"pool/fs/data", "zfs"} {
		t.Errorf("mounted %v", m)
	}
}

func TestZFSNeverTouchesWhatItDidNotCreate(t *testing.T) {
	w := newWorld(t)
	s := w.service()

	// An untagged dataset where a volume would go -- also what a create
	// looks like in the instant before the kernel applies its properties.
	w.zfs.add("pool/fs/untagged")
	_, err := create(s, "tank", "untagged", 1<<20)
	wantCode(t, err, codes.AlreadyExists, "create over an untagged dataset")
	_, err = del(s, "tank", "untagged", true)
	wantCode(t, err, codes.FailedPrecondition, "delete an untagged dataset")
	if w.zfs.ds["pool/fs/untagged"] == nil {
		t.Fatal("the untagged dataset was destroyed")
	}

	// ⛔ An INHERITED mark with exactly the right value: the parent dataset
	// carries fileshare:volume=tank/inh, so its child reports that value --
	// with the parent as the source.
	w.zfs.ds["pool/fs"].user[ownerProp] = "tank/inh"
	// With the quota asked, so that a mark taken as ours would be adopted
	// rather than refused for its size.
	w.zfs.add("pool/fs/inh").props["refquota"] = uint64(1 << 20)
	if v, src, _ := w.zfs.UserProp("pool/fs/inh", ownerProp); v != "tank/inh" || src != "pool/fs" {
		t.Fatalf("the fake does not inherit: %q from %q", v, src)
	}
	_, err = create(s, "tank", "inh", 1<<20)
	wantCode(t, err, codes.AlreadyExists, "create over a dataset with an inherited mark")
	_, err = del(s, "tank", "inh", true)
	wantCode(t, err, codes.FailedPrecondition, "delete a dataset with an inherited mark")
	delete(w.zfs.ds["pool/fs"].user, ownerProp)

	// A mark that came in a send stream is not a mark we set.
	d := w.zfs.add("pool/fs/recv")
	d.recvd[ownerProp] = "tank/recv"
	_, err = create(s, "tank", "recv", 1<<20)
	wantCode(t, err, codes.AlreadyExists, "create over a received mark")

	// A local mark naming another volume.
	d = w.zfs.add("pool/fs/other")
	d.user[ownerProp] = "tank/somebody-else"
	_, err = create(s, "tank", "other", 1<<20)
	wantCode(t, err, codes.AlreadyExists, "create over another volume's mark")

	// A volume of ours whose mark was removed afterwards.
	mustCreate(t, s, "tank", "mine", 1<<20)
	delete(w.zfs.ds["pool/fs/mine"].user, ownerProp)
	_, err = s.ResizeVolume(bg, &pb.ResizeVolumeRequest{Parent: "tank", Name: "mine", QuotaBytes: 2 << 20})
	wantCode(t, err, codes.FailedPrecondition, "resize after the mark went")
	_, err = s.SnapshotVolume(bg, &pb.SnapshotVolumeRequest{Parent: "tank", Name: "mine", Snapshot: "s"})
	wantCode(t, err, codes.FailedPrecondition, "snapshot after the mark went")
	_, err = del(s, "tank", "mine", true)
	wantCode(t, err, codes.FailedPrecondition, "delete after the mark went")
	_, err = create(s, "tank", "mine", 1<<20)
	wantCode(t, err, codes.FailedPrecondition, "create again after the mark went")
	if w.zfs.ds["pool/fs/mine"] == nil {
		t.Fatal("an unmarked dataset was destroyed")
	}
}

func TestAZFSVolumeWithItsMarkAndNoRecordIsStillOurs(t *testing.T) {
	w := newWorld(t)
	s := w.service()
	mustCreate(t, s, "tank", "lost", 4<<20)
	s.st.remove("tank", "lost")
	if err := s.st.save(); err != nil {
		t.Fatal(err)
	}
	r, err := create(s, "tank", "lost", 4<<20)
	if err != nil || r.GetCreated() {
		t.Fatalf("create of a marked, unrecorded dataset = %+v, %v; want OK, not created", r, err)
	}
	if s.st.get("tank", "lost") == nil {
		t.Error("it was not recorded again")
	}
	if !strings.Contains(w.log.String(), "recorded again") {
		t.Error("finding it was not logged")
	}
	_, err = create(s, "tank", "lost", 5<<20)
	wantCode(t, err, codes.AlreadyExists, "a different quota")

	// Deleting one that lost its record works too.
	s.st.remove("tank", "lost")
	if r, err := del(s, "tank", "lost", false); err != nil || !r.GetDeleted() {
		t.Errorf("delete of a marked, unrecorded dataset = %+v, %v", r, err)
	}
	// And one recorded with another quota.
	mustCreate(t, s, "tank", "q", 4<<20)
	s.st.remove("tank", "q")
	_, err = create(s, "tank", "q", 8<<20)
	wantCode(t, err, codes.AlreadyExists, "re-recorded with another quota")
}

func TestDeleteRefusesDataAndSnapshotsWithoutDestroyData(t *testing.T) {
	for _, parent := range []string{"tank", "fast", "plain"} {
		t.Run(parent, func(t *testing.T) {
			w := newWorld(t)
			s := w.service()
			v := mustCreate(t, s, parent, "data", 8<<20)
			if err := os.WriteFile(filepath.Join(v.GetPath(), "f"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := del(s, parent, "data", false)
			wantCode(t, err, codes.FailedPrecondition, "a volume with a file")
			if strings.Contains(w.log.String(), "audit: delete") {
				t.Error("a refused delete was logged as a delete")
			}
			if parent != "plain" {
				os.Remove(filepath.Join(v.GetPath(), "f"))
				if _, err := s.SnapshotVolume(bg, &pb.SnapshotVolumeRequest{Parent: parent, Name: "data", Snapshot: "s1"}); err != nil {
					t.Fatal(err)
				}
				_, err = del(s, parent, "data", false)
				wantCode(t, err, codes.FailedPrecondition, "a volume with a snapshot")
			}
			// destroy_data: it goes, snapshots and all, logged first.
			if r, err := del(s, parent, "data", true); err != nil || !r.GetDeleted() {
				t.Fatalf("destroy_data = %+v, %v", r, err)
			}
			if !strings.Contains(w.log.String(), "audit: delete volume "+parent+"/data") {
				t.Errorf("no audit line:\n%s", w.log)
			}
			if s.st.get(parent, "data") != nil {
				t.Error("still recorded")
			}
		})
	}
}

// The audit line is written BEFORE the destruction: a destroy that fails
// half way is in the log all the same.
func TestTheAuditLineComesFirst(t *testing.T) {
	w := newWorld(t)
	s := w.service()
	mustCreate(t, s, "tank", "data", 1<<20)
	// The destroy fails: the dataset refuses to go.
	s.backends["tank"] = &failingDestroy{backend: s.backends["tank"]}
	_, err := del(s, "tank", "data", true)
	if err == nil {
		t.Fatal("the failing destroy succeeded")
	}
	if !strings.Contains(w.log.String(), "audit: delete volume tank/data") {
		t.Errorf("a failed destroy left no audit line:\n%s", w.log)
	}
	if s.st.get("tank", "data") == nil {
		t.Error("a volume that was not destroyed was forgotten")
	}
}

type failingDestroy struct{ backend }

func (failingDestroy) destroy(*record, []string) error { return errors.New("EBUSY, say") }

func TestResize(t *testing.T) {
	for _, parent := range []string{"tank", "fast", "plain"} {
		t.Run(parent, func(t *testing.T) {
			w := newWorld(t)
			s := w.service()
			mustCreate(t, s, parent, "data", 8<<20)
			r, err := s.ResizeVolume(bg, &pb.ResizeVolumeRequest{Parent: parent, Name: "data", QuotaBytes: 16 << 20})
			if err != nil || r.GetVolume().GetQuotaBytes() != 16<<20 {
				t.Fatalf("grow = %+v, %v", r, err)
			}
			if q, _ := s.backends[parent].quota(s.st.get(parent, "data")); q != 16<<20 {
				t.Errorf("the filesystem's limit is %d", q)
			}
			// The same size is nothing to do.
			if _, err := s.ResizeVolume(bg, &pb.ResizeVolumeRequest{Parent: parent, Name: "data", QuotaBytes: 16 << 20}); err != nil {
				t.Error(err)
			}
			// Never below what is used.
			setUsed(w, parent, "data", 10<<20)
			_, err = s.ResizeVolume(bg, &pb.ResizeVolumeRequest{Parent: parent, Name: "data", QuotaBytes: 4 << 20})
			wantCode(t, err, codes.FailedPrecondition, "shrink below use")
			if r, err := s.ResizeVolume(bg, &pb.ResizeVolumeRequest{Parent: parent, Name: "data", QuotaBytes: 12 << 20}); err != nil || r.GetVolume().GetUsedBytes() != 10<<20 {
				t.Errorf("shrink above use = %+v, %v", r, err)
			}
			_, err = s.ResizeVolume(bg, &pb.ResizeVolumeRequest{Parent: parent, Name: "nope", QuotaBytes: 4 << 20})
			wantCode(t, err, codes.NotFound, "resize nothing")
			_, err = s.ResizeVolume(bg, &pb.ResizeVolumeRequest{Parent: parent, Name: "data", QuotaBytes: 0})
			wantCode(t, err, codes.InvalidArgument, "resize to 0")
			_, err = s.ResizeVolume(bg, &pb.ResizeVolumeRequest{Parent: parent, Name: "data", QuotaBytes: 2 << 40})
			wantCode(t, err, codes.OutOfRange, "resize above max")
			// Growth the parent cannot hold.
			w.sys.free = 1 << 20
			w.zfs.ds["pool/fs"].props["available"] = uint64(1 << 20)
			_, err = s.ResizeVolume(bg, &pb.ResizeVolumeRequest{Parent: parent, Name: "data", QuotaBytes: 100 << 20})
			wantCode(t, err, codes.ResourceExhausted, "grow past the parent")
		})
	}
}

func setUsed(w *world, parent, name string, n uint64) {
	switch parent {
	case "tank":
		w.zfs.ds["pool/fs/"+name].props["referenced"] = n
	case "fast":
		id, _, _ := w.btrfs.subvol(w.path(parent, name))
		w.btrfs.rfer[id] = n
	default:
		for p, id := range w.proj.ids {
			if p == w.path(parent, name) {
				w.proj.usage[id] = n
			}
		}
	}
}

func TestSnapshots(t *testing.T) {
	w := newWorld(t)
	s := w.service()
	mustCreate(t, s, "tank", "z", 1<<20)
	mustCreate(t, s, "fast", "b", 1<<20)
	mustCreate(t, s, "plain", "x", 1<<20)
	for _, p := range []struct{ parent, name string }{{"tank", "z"}, {"fast", "b"}} {
		r, err := s.SnapshotVolume(bg, &pb.SnapshotVolumeRequest{Parent: p.parent, Name: p.name, Snapshot: "monday"})
		if err != nil || !r.GetCreated() || !slices.Equal(r.GetVolume().GetSnapshots(), []string{"monday"}) {
			t.Errorf("%s: snapshot = %+v, %v", p.parent, r, err)
		}
		r, err = s.SnapshotVolume(bg, &pb.SnapshotVolumeRequest{Parent: p.parent, Name: p.name, Snapshot: "monday"})
		if err != nil || r.GetCreated() {
			t.Errorf("%s: the same snapshot again = %+v, %v; want OK, not created", p.parent, r, err)
		}
		_, err = s.SnapshotVolume(bg, &pb.SnapshotVolumeRequest{Parent: p.parent, Name: p.name, Snapshot: "../x"})
		wantCode(t, err, codes.InvalidArgument, "a snapshot name outside the grammar")
	}
	// btrfs: read-only, under <root>/.snapshots/<volume>/.
	snap := w.path("fast", ".snapshots", "b", "monday")
	if sv, ok := w.btrfs.subvols[snap]; !ok || !sv.ro {
		t.Errorf("btrfs snapshot at %s: %+v, %v", snap, sv, ok)
	}
	_, err := s.SnapshotVolume(bg, &pb.SnapshotVolumeRequest{Parent: "plain", Name: "x", Snapshot: "monday"})
	wantCode(t, err, codes.Unimplemented, "an xfs snapshot")
	_, err = s.SnapshotVolume(bg, &pb.SnapshotVolumeRequest{Parent: "tank", Name: "nope", Snapshot: "monday"})
	wantCode(t, err, codes.NotFound, "a snapshot of nothing")
	w.zfs.errSnap = errors.New("no")
	_, err = s.SnapshotVolume(bg, &pb.SnapshotVolumeRequest{Parent: "tank", Name: "z", Snapshot: "tuesday"})
	wantCode(t, err, codes.Internal, "a snapshot the kernel refused")

	// destroy_data takes the snapshots with it.
	if _, err := del(s, "fast", "b", true); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.btrfs.subvols[snap]; ok {
		t.Error("the btrfs snapshot survived its volume")
	}
	if _, err := os.Stat(w.path("fast", ".snapshots", "b")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the snapshot directory survived: %v", err)
	}
	if _, err := del(s, "tank", "z", true); err != nil {
		t.Fatal(err)
	}
	if w.zfs.ds["pool/fs/z"] != nil {
		t.Error("the dataset survived")
	}
}

func TestBtrfsOwnershipIsTheRecordedSubvolume(t *testing.T) {
	w := newWorld(t)
	s := w.service()
	mustCreate(t, s, "fast", "data", 1<<20)
	r := s.st.get("fast", "data")
	if r.SubvolID == 0 || r.SubvolUUID == "" {
		t.Fatalf("not recorded: %+v", r)
	}
	if w.btrfs.limits[r.SubvolID] != 1<<20 {
		t.Errorf("limit = %d", w.btrfs.limits[r.SubvolID])
	}
	// Replaced by another subvolume of the same name: not ours.
	if err := w.btrfs.SubvolDelete(w.path("fast"), "data"); err != nil {
		t.Fatal(err)
	}
	if err := w.btrfs.SubvolCreate(w.path("fast"), "data"); err != nil {
		t.Fatal(err)
	}
	_, err := del(s, "fast", "data", true)
	wantCode(t, err, codes.FailedPrecondition, "delete a replaced subvolume")
	// A plain directory where a volume would be.
	if err := os.Mkdir(w.path("fast", "plain-dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = create(s, "fast", "plain-dir", 1<<20)
	wantCode(t, err, codes.AlreadyExists, "create over a directory")
	_, err = del(s, "fast", "plain-dir", true)
	wantCode(t, err, codes.FailedPrecondition, "delete a directory it did not make")
	// A subvolume nobody recorded.
	if err := w.btrfs.SubvolCreate(w.path("fast"), "stray"); err != nil {
		t.Fatal(err)
	}
	_, err = create(s, "fast", "stray", 1<<20)
	wantCode(t, err, codes.AlreadyExists, "create over a stray subvolume")
	// A file.
	if err := os.WriteFile(w.path("fast", "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = del(s, "fast", "file", true)
	wantCode(t, err, codes.FailedPrecondition, "delete a file")
}

func TestProjectIDsComeFromTheRangeAndAreOwnership(t *testing.T) {
	w := newWorld(t)
	s := w.service()
	// The range is 100-102: three volumes, then RESOURCE_EXHAUSTED.
	for i, n := range []string{"a", "b", "c"} {
		mustCreate(t, s, "plain", n, 1<<20)
		if id := s.st.get("plain", n).ProjectID; id != uint32(100+i) {
			t.Errorf("%s got project %d", n, id)
		}
		if l := w.proj.limits[uint32(100+i)]; l.BlockHard != 1<<20 {
			t.Errorf("%s limits %+v", n, l)
		}
	}
	_, err := create(s, "plain", "d", 1<<20)
	wantCode(t, err, codes.ResourceExhausted, "the range used up")
	if _, err := os.Stat(w.path("plain", "d")); !errors.Is(err, os.ErrNotExist) {
		t.Error("an exhausted create left a directory")
	}

	// ⛔ An id outside the range is never ours, recorded or not.
	w.proj.ids[w.path("plain", "b")] = 7
	_, err = del(s, "plain", "b", true)
	wantCode(t, err, codes.FailedPrecondition, "delete with a project id outside the range")
	// An id in the range that is not the recorded one.
	w.proj.ids[w.path("plain", "b")] = 102
	_, err = s.ResizeVolume(bg, &pb.ResizeVolumeRequest{Parent: "plain", Name: "b", QuotaBytes: 2 << 20})
	wantCode(t, err, codes.FailedPrecondition, "resize with another volume's id")
	w.proj.ids[w.path("plain", "b")] = 101
	// The range is checked even against the record: a record holding an id
	// outside it (a state file edited by hand) does not make the id ours.
	odd := &record{Parent: "plain", Name: "b", ProjectID: 7}
	w.proj.ids[w.path("plain", "b")] = 7
	if err := s.backends["plain"].owned(odd); !errors.Is(err, errNotOurs) {
		t.Errorf("a recorded id outside the range: %v", err)
	}
	w.proj.ids[w.path("plain", "b")] = 101

	// A directory nobody recorded, even one in the range.
	if err := os.Mkdir(w.path("four", "stray"), 0o755); err != nil {
		t.Fatal(err)
	}
	w.proj.ids[w.path("four", "stray")] = 250
	_, err = create(s, "four", "stray", 1<<20)
	wantCode(t, err, codes.AlreadyExists, "create over a stray directory")
	_, err = del(s, "four", "stray", true)
	wantCode(t, err, codes.FailedPrecondition, "delete a stray directory")

	// Deleting frees the id -- after its limits are lifted -- and only then
	// may it be given out again.
	if _, err := del(s, "plain", "a", false); err != nil {
		t.Fatal(err)
	}
	if l := w.proj.limits[100]; l != (projquota.Limits{}) {
		t.Errorf("limits of a deleted project: %+v", l)
	}
	mustCreate(t, s, "plain", "d", 1<<20)
	if id := s.st.get("plain", "d").ProjectID; id != 100 {
		t.Errorf("the freed id was not reused: %d", id)
	}
}

func TestDestroyDataRemovesTheTreeWithoutFollowingLinks(t *testing.T) {
	w := newWorld(t)
	s := w.service()
	v := mustCreate(t, s, "plain", "data", 1<<20)
	outside := w.path("outside")
	if err := os.MkdirAll(filepath.Join(outside, "keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"a", "a/b", "a/b/c"} {
		if err := os.Mkdir(filepath.Join(v.GetPath(), d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 600; i++ { // more than one Readdirnames batch
		if err := os.WriteFile(filepath.Join(v.GetPath(), "a", "f"+strconv.Itoa(i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(v.GetPath(), "a", "b", "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(v.GetPath(), "toplink")); err != nil {
		t.Fatal(err)
	}
	if _, err := del(s, "plain", "data", true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outside, "keep")); err != nil {
		t.Errorf("the walk followed a link out of the volume: %v", err)
	}
	if _, err := os.Lstat(v.GetPath()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the volume is still there: %v", err)
	}
}

func TestRemoveTreeRefusals(t *testing.T) {
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "f"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeTree(d, "f"); err == nil {
		t.Error("removeTree of a file succeeded")
	}
	if err := os.Symlink(d, filepath.Join(d, "l")); err != nil {
		t.Fatal(err)
	}
	if err := removeTree(d, "l"); err == nil {
		t.Error("removeTree of a link succeeded")
	}
	if err := removeTree(filepath.Join(d, "nope"), "x"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing parent: %v", err)
	}
	if err := removeTree(d, "nope"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing tree: %v", err)
	}
	// A directory it may not read stops it with an error, not a panic.
	if os.Getuid() != 0 {
		if err := os.MkdirAll(filepath.Join(d, "t", "locked"), 0o755); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(d, "t", "locked", "f"), nil, 0o600)
		os.Chmod(filepath.Join(d, "t", "locked"), 0o000)
		defer os.Chmod(filepath.Join(d, "t", "locked"), 0o755)
		if err := removeTree(d, "t"); err == nil {
			t.Error("an unreadable directory was removed")
		}
	}
}

// A creation that fails half way leaves a pending record: CreateVolume with
// the same parameters finishes it, and DeleteVolume removes it. One that
// fails before anything was made leaves nothing, and its project id goes back.
func TestAnUnfinishedCreation(t *testing.T) {
	w := newWorld(t)
	s := w.service()

	w.proj.errLimit = errors.New("quotactl says no")
	_, err := create(s, "plain", "half", 1<<20)
	wantCode(t, err, codes.Internal, "the limit refused")
	r := s.st.get("plain", "half")
	if r == nil || !r.Pending {
		t.Fatalf("record after a half creation: %+v", r)
	}
	if _, err := os.Stat(w.path("plain", "half")); err != nil {
		t.Fatalf("the half-made directory: %v", err)
	}
	if _, ok := w.sys.owners[w.path("plain", "half")]; ok {
		t.Error("a volume without its limit was given to the group")
	}
	_, err = s.GetVolume(bg, &pb.GetVolumeRequest{Parent: "plain", Name: "half"})
	wantCode(t, err, codes.FailedPrecondition, "get a pending volume")
	if l, _ := s.ListVolumes(bg, &pb.ListVolumesRequest{}); len(l.GetVolumes()) != 0 {
		t.Errorf("a pending volume is listed: %v", l)
	}
	_, err = create(s, "plain", "half", 2<<20)
	wantCode(t, err, codes.AlreadyExists, "finish with other parameters")
	w.proj.errLimit = nil
	if r, err := create(s, "plain", "half", 1<<20); err != nil || !r.GetCreated() {
		t.Fatalf("finishing = %+v, %v", r, err)
	}
	if s.st.get("plain", "half").Pending {
		t.Error("still pending")
	}

	// Half made, then deleted.
	w.btrfs.errLimit = errors.New("ENOTCONN, say")
	if _, err := create(s, "fast", "half", 1<<20); err == nil {
		t.Fatal("the failing create succeeded")
	}
	w.btrfs.errLimit = nil
	if r, err := del(s, "fast", "half", false); err != nil || !r.GetDeleted() {
		t.Errorf("delete of a pending volume = %+v, %v", r, err)
	}
	if s.st.get("fast", "half") != nil {
		t.Error("the pending record survived its delete")
	}

	// Nothing made at all: nothing recorded.
	w.zfs.errCreate = errors.New("EINVAL, say")
	if _, err := create(s, "tank", "none", 1<<20); err == nil {
		t.Fatal("the failing create succeeded")
	}
	if s.st.get("tank", "none") != nil {
		t.Error("a creation that made nothing is recorded")
	}
	w.zfs.errCreate = nil
	// Mounting fails after the dataset exists: pending, and finished later.
	w.sys.errMnt = errors.New("EBUSY, say")
	if _, err := create(s, "tank", "m", 1<<20); err == nil {
		t.Fatal("the failing mount succeeded")
	}
	if r := s.st.get("tank", "m"); r == nil || !r.Pending {
		t.Fatalf("after a failed mount: %+v", r)
	}
	w.sys.errMnt = nil
	if _, err := create(s, "tank", "m", 1<<20); err != nil {
		t.Fatal(err)
	}
}

func TestGetAndListAndCapabilities(t *testing.T) {
	w := newWorld(t)
	s := w.service()
	mustCreate(t, s, "tank", "a", 1<<20)
	mustCreate(t, s, "plain", "b", 2<<20)
	setUsed(w, "plain", "b", 4096)
	l, err := s.ListVolumes(bg, &pb.ListVolumesRequest{})
	if err != nil || len(l.GetVolumes()) != 2 {
		t.Fatalf("list = %v, %v", l, err)
	}
	l, err = s.ListVolumes(bg, &pb.ListVolumesRequest{Parent: "plain"})
	if err != nil || len(l.GetVolumes()) != 1 || l.GetVolumes()[0].GetUsedBytes() != 4096 || l.GetVolumes()[0].GetKind() != pb.Kind_KIND_XFS {
		t.Fatalf("list plain = %v, %v", l, err)
	}
	g, err := s.GetVolume(bg, &pb.GetVolumeRequest{Parent: "tank", Name: "a"})
	if err != nil || g.GetVolume().GetKind() != pb.Kind_KIND_ZFS || g.GetVolume().GetCreated().AsTime().Year() != 2026 {
		t.Errorf("get = %v, %v", g, err)
	}
	_, err = s.GetVolume(bg, &pb.GetVolumeRequest{Parent: "tank", Name: "b"})
	wantCode(t, err, codes.NotFound, "get nothing")

	c, err := s.GetCapabilities(bg, &pb.GetCapabilitiesRequest{})
	if err != nil || c.GetMaxVolumeBytes() != 1<<40 || len(c.GetParents()) != 4 {
		t.Fatalf("capabilities = %v, %v", c, err)
	}
	want := map[string]struct {
		k    pb.Kind
		snap bool
	}{"tank": {pb.Kind_KIND_ZFS, true}, "fast": {pb.Kind_KIND_BTRFS, true}, "plain": {pb.Kind_KIND_XFS, false}, "four": {pb.Kind_KIND_EXT4, false}}
	for _, p := range c.GetParents() {
		if wp := want[p.GetId()]; wp.k != p.GetKind() || wp.snap != p.GetSnapshots() || p.GetRoot() != w.path(p.GetId()) || p.GetTotalBytes() == 0 {
			t.Errorf("parent %+v", p)
		}
	}
	// Space that cannot be read is 0, and refuses nothing.
	w.sys.noSpace = true
	c, _ = s.GetCapabilities(bg, &pb.GetCapabilitiesRequest{})
	for _, p := range c.GetParents() {
		if p.GetId() == "plain" && p.GetTotalBytes() != 0 {
			t.Errorf("unreadable space reported as %d", p.GetTotalBytes())
		}
	}
	mustCreate(t, s, "plain", "c", 1<<20)
}

// A recorded volume that vanished: get and resize say so, delete forgets it
// and lifts its limits.
func TestARecordedVolumeThatVanished(t *testing.T) {
	w := newWorld(t)
	s := w.service()
	mustCreate(t, s, "plain", "gone", 1<<20)
	if err := os.Remove(w.path("plain", "gone")); err != nil {
		t.Fatal(err)
	}
	_, err := s.GetVolume(bg, &pb.GetVolumeRequest{Parent: "plain", Name: "gone"})
	wantCode(t, err, codes.FailedPrecondition, "get a vanished volume")
	_, err = create(s, "plain", "gone", 1<<20)
	wantCode(t, err, codes.FailedPrecondition, "create a vanished volume again")
	if r, err := del(s, "plain", "gone", false); err != nil || r.GetDeleted() {
		t.Errorf("delete of a vanished volume = %+v, %v", r, err)
	}
	if s.st.get("plain", "gone") != nil || w.proj.limits[100] != (projquota.Limits{}) {
		t.Error("the vanished volume was not forgotten, or its limits not lifted")
	}
}

func TestStatusOf(t *testing.T) {
	if statusOf(nil) != nil {
		t.Error("nil")
	}
	wantCode(t, statusOf(&os.PathError{Err: syscall.ENOSPC}), codes.ResourceExhausted, "ENOSPC")
	wantCode(t, statusOf(syscall.EDQUOT), codes.ResourceExhausted, "EDQUOT")
	wantCode(t, statusOf(errors.New("x")), codes.Internal, "other")
	wantCode(t, statusOf(refuse(codes.OutOfRange, "x")), codes.OutOfRange, "refusal")
}
