// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// Shares served from volumes: storage the privileged `fileshare provisioner`
// creates, which this server serves as a directory. See docs/volumes.md for
// the design, volume_grpc.go for the admin API's half, and
// internal/provision for the provisioner.
//
// A share made from a volume keeps the volume's NAME in the state file, not
// only its path: at every start the provisioner is asked again where it is,
// and the answer is checked again before anything is served. A volume that
// is gone, or fails a check, leaves its share defined and unserved -- said
// in `check`, in ListShares and at the start -- rather than stopping the
// server and every other share with it.

// A volumeRef names a volume the way the provisioner does.
type volumeRef struct {
	Parent string `json:"parent"`
	Name   string `json:"name"`
}

func (r volumeRef) String() string { return r.Parent + "/" + r.Name }

// A volumeResolution is what asking for a volume share's volume found: the
// path to serve, checked, or why it is not served.
type volumeResolution struct {
	path string
	why  string
}

// An unavailableShare is a volume share that is defined, not disabled, and
// not served, with the reason.
type unavailableShare struct {
	block shareBlock
	why   string
}

// unavailable says why an API share is not served although it is enabled,
// or "" when nothing stands in its way.
func (m managedShare) unavailable() string {
	switch {
	case m.Volume == nil:
		return ""
	case m.resolved == nil:
		return fmt.Sprintf("volume %s has not been looked up", m.Volume)
	}
	return m.resolved.why
}

// checkVolumes refuses the admin block's volume settings when they cannot
// work, without touching anything.
func (a *adminBlock) checkVolumes() error {
	if a.Provisioner != "" {
		rest, ok := strings.CutPrefix(a.Provisioner, "unix://")
		if !ok || !strings.HasPrefix(rest, "/") || path.Clean(rest) != rest {
			return fmt.Errorf("provisioner %q: want unix:///absolute/path -- the provisioner listens on a unix socket only", a.Provisioner)
		}
	}
	if a.ProvisionerUID != nil && a.Provisioner == "" {
		return errors.New("provisioner_uid without provisioner: it is the uid the provisioner's socket must answer as")
	}
	if len(a.AllowedUIDs) > 0 {
		if !strings.HasPrefix(a.Listen, "unix:") {
			return errors.New("allowed_uids is for a unix socket: over TCP the client certificate is the check")
		}
		if !peerUIDReadable() {
			return fmt.Errorf("allowed_uids: this system (%s) does not say who is at the other end of a unix socket", runtime.GOOS)
		}
	}
	return nil
}

// provisionerUID is the uid the provisioner must run as.
func (a *adminBlock) provisionerUID() uint32 {
	if a.ProvisionerUID != nil {
		return *a.ProvisionerUID
	}
	return 0
}

// peerUIDReadable is whether internal/peercred can name a unix socket's peer
// here: SO_PEERCRED and LOCAL_PEERCRED.
func peerUIDReadable() bool { return runtime.GOOS == "linux" || runtime.GOOS == "darwin" }

// Which statfs f_type each kind of volume must be on. ZFS's is not in
// golang.org/x/sys: OpenZFS include/sys/zfs_vfsops.h, ZFS_SUPER_MAGIC.
const (
	zfsSuperMagic   = 0x2fc12fc1
	btrfsSuperMagic = 0x9123683e // BTRFS_SUPER_MAGIC
	xfsSuperMagic   = 0x58465342 // XFS_SUPER_MAGIC
	ext4SuperMagic  = 0xef53     // EXT4_SUPER_MAGIC (ext2 and ext3 share it)
	// btrfsSubvolRoot is the inode number of every btrfs subvolume's root
	// directory (BTRFS_FIRST_FREE_OBJECTID): a plain directory has another.
	btrfsSubvolRoot = 256
)

// The kinds, as the checks below name them.
const (
	kindZFS   = "zfs"
	kindBtrfs = "btrfs"
	kindXFS   = "xfs"
	kindExt4  = "ext4"
)

// What the checks ask the system, as functions a test can replace: the
// real ones read the kernel (volume_linux.go), and refuse elsewhere.
var (
	// quotaExempt says why this process would write past a quota, or "".
	quotaExempt = processQuotaExempt
	// fsMagic is statfs(2)'s f_type.
	fsMagic = statfsMagic
	// devIno is the device and inode a path is on, not following a link.
	devIno = pathDevIno
	// projectOf is an XFS or ext4 directory's project id, and whether new
	// files inherit it.
	projectOf = pathProject
)

// A volumeFound is what the provisioner says about a volume, in this
// server's words.
type volumeFound struct {
	ref  volumeRef
	kind string
	path string
}

// checkVolume is every check made before a volume is served, and the path
// to serve. It refuses:
//
//   - a process that would write past a quota: root, or CAP_SYS_RESOURCE,
//     which ext4 lets past a project quota (measured in go-fsctl/projquota's
//     CI: root wrote 16 MiB into an 8 MiB project);
//   - a path that is not absolute, or not clean, or -- resolved -- not under
//     the source roots: the provisioner is trusted to create volumes, not to
//     name what this server opens;
//   - what is not a directory;
//   - a filesystem other than the kind's, by statfs's f_type;
//   - ZFS: a directory that is not a mount point (its device is its
//     parent's), which is the empty directory a dataset would be mounted on
//     -- writes there land in the parent, under no quota;
//   - btrfs: a directory that is not a subvolume's root;
//   - XFS, ext4: a directory with no project id, or one its new files do
//     not inherit, which no project quota limits.
func checkVolume(v volumeFound, roots []string) (string, error) {
	if why := quotaExempt(); why != "" {
		return "", fmt.Errorf("this server %s, and would write past the volume's quota (ext4 lets CAP_SYS_RESOURCE past "+
			"a project quota): run `fileshare serve` as an unprivileged user without CAP_SYS_RESOURCE", why)
	}
	if !filepath.IsAbs(v.path) || filepath.Clean(v.path) != v.path {
		return "", fmt.Errorf("the provisioner says volume %s is at %q, which is not a clean absolute path", v.ref, v.path)
	}
	if len(roots) == 0 {
		return "", errors.New("the admin block names no source_roots, so no volume can be served: add the provisioner's parent roots")
	}
	real, err := filepath.EvalSymlinks(v.path)
	if err != nil {
		return "", fmt.Errorf("volume %s at %s: %v", v.ref, v.path, err)
	}
	if _, _, err := rootOf(roots, real); err != nil {
		return "", fmt.Errorf("volume %s: %v", v.ref, err)
	}
	dev, ino, isDir, err := devIno(real)
	if err != nil {
		return "", fmt.Errorf("volume %s at %s: %v", v.ref, real, err)
	}
	if !isDir {
		return "", fmt.Errorf("volume %s at %s is not a directory", v.ref, real)
	}
	want := map[string]int64{kindZFS: zfsSuperMagic, kindBtrfs: btrfsSuperMagic, kindXFS: xfsSuperMagic, kindExt4: ext4SuperMagic}
	magic, known := want[v.kind]
	if !known {
		return "", fmt.Errorf("volume %s is of a kind this server does not know (%q)", v.ref, v.kind)
	}
	got, err := fsMagic(real)
	if err != nil {
		return "", fmt.Errorf("volume %s at %s: statfs: %v", v.ref, real, err)
	}
	if got != magic {
		return "", fmt.Errorf("volume %s at %s is on a filesystem with magic %#x, not %s (%#x): it is not the volume the provisioner made",
			v.ref, real, got, v.kind, magic)
	}
	switch v.kind {
	case kindZFS:
		pdev, _, _, err := devIno(filepath.Dir(real))
		if err != nil {
			return "", fmt.Errorf("volume %s: its parent directory: %v", v.ref, err)
		}
		if pdev == dev {
			return "", fmt.Errorf("volume %s at %s is not mounted: it is on its parent's device, and a write there "+
				"would land in the parent, under no quota", v.ref, real)
		}
	case kindBtrfs:
		if ino != btrfsSubvolRoot {
			return "", fmt.Errorf("volume %s at %s is not the root of a btrfs subvolume (inode %d, not %d): no qgroup limits it",
				v.ref, real, ino, btrfsSubvolRoot)
		}
	case kindXFS, kindExt4:
		id, inherit, err := projectOf(real)
		if err != nil {
			return "", fmt.Errorf("volume %s at %s: reading its project id: %v", v.ref, real, err)
		}
		if id == 0 || !inherit {
			return "", fmt.Errorf("volume %s at %s has project id %d (inherited: %t): no project quota limits what is written there",
				v.ref, real, id, inherit)
		}
	}
	return real, nil
}

// capSysResource is CAP_SYS_RESOURCE's bit in a capability set
// (include/uapi/linux/capability.h).
const capSysResource = 24

// quotaExemptFrom is processQuotaExempt's judgement, from an effective uid
// and the text of /proc/self/status: root, or CAP_SYS_RESOURCE in CapEff.
// A status that cannot be read for CapEff is judged exempt -- a check that
// cannot see must not say "fine".
func quotaExemptFrom(euid int, status []byte, readErr error) string {
	if euid == 0 {
		return "runs as root (uid 0)"
	}
	if readErr != nil {
		return fmt.Sprintf("cannot tell whether it holds CAP_SYS_RESOURCE (%v)", readErr)
	}
	// ⛔ The PERMITTED set counts as much as the effective one: a process
	// holding CAP_SYS_RESOURCE in CapPrm raises it into CapEff with one
	// capset(2) call, so a compromised server would write past the quota
	// whenever it liked. Only a capability in neither set is out of reach.
	sets := map[string]uint64{}
	for _, line := range strings.Split(string(status), "\n") {
		for _, name := range []string{"CapPrm", "CapEff"} {
			hex, ok := strings.CutPrefix(line, name+":")
			if !ok {
				continue
			}
			var caps uint64
			if _, err := fmt.Sscanf(strings.TrimSpace(hex), "%x", &caps); err != nil {
				return fmt.Sprintf("cannot tell whether it holds CAP_SYS_RESOURCE (%s %q)", name, strings.TrimSpace(hex))
			}
			sets[name] = caps
		}
	}
	for _, name := range []string{"CapEff", "CapPrm"} {
		caps, ok := sets[name]
		if !ok {
			return fmt.Sprintf("cannot tell whether it holds CAP_SYS_RESOURCE (no %s in /proc/self/status)", name)
		}
		if caps&(1<<capSysResource) != 0 {
			set := "effective"
			if name == "CapPrm" {
				set = "permitted"
			}
			return "holds CAP_SYS_RESOURCE in its " + set + " set"
		}
	}
	return ""
}
