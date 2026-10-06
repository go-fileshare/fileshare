// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package provision

import (
	"errors"
	"fmt"
	"math"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"

	provisionv1 "github.com/go-fileshare/fileshare/proto/fileshare/provision/v1"
)

// Config is the provisioner's own file. It is NOT fileshare's: the two
// processes have different privileges and different owners, and the file
// that says which storage may be created belongs to the privileged one.
//
//	provisioner {
//	  listen     = "unix:///run/fileshare-provisioner/provisioner.sock"
//	  client_uid = 990                       # fileshare's
//	  group      = "fileshare"
//	  max_volume = "10T"
//	  state_file = "/var/lib/fileshare-provisioner/volumes.json"
//
//	  parent "tank"  { zfs = "tank/fileshare",  root = "/srv/fileshare/volumes/tank" }
//	  parent "fast"  { btrfs = "/srv/fileshare/volumes/fast" }
//	  parent "plain" { xfs = "/srv/fileshare/volumes/plain", project_ids = "100000-199999" }
//	}
type Config struct {
	// Listen is unix://<absolute path>, and nothing else: CSI's rule, "Only
	// UNIX Domain Sockets MAY be used as endpoints". The socket is made 0660,
	// owned by this process and the group below.
	Listen string `hcl:"listen"`
	// ClientUID is the one uid answered: fileshare's.
	//
	// ⛔ Not 0. fileshare must not run as root, nor with CAP_SYS_RESOURCE:
	// ext4 lets either write past a project quota (fs/quota/dquot.c
	// ignore_hardlimit), so a root fileshare would not be held to the volumes
	// this process sizes.
	ClientUID int64 `hcl:"client_uid"`
	// Group owns every volume root (root:<group>, mode 2770): fileshare writes
	// through it and never OWNS a volume, because the owner of a directory may
	// clear its project id without any privilege (fs/file_attr.c,
	// vfs_fileattr_set). A name or a number.
	Group string `hcl:"group"`
	// MaxVolume is the largest quota one volume may have: "10T", "500G",
	// "1048576". Above it is OUT_OF_RANGE.
	MaxVolume string `hcl:"max_volume"`
	// StateFile is where the volumes this process created are recorded --
	// the btrfs subvolume ids, the XFS/ext4 project ids it allocated -- so
	// that it knows, after a restart, what is its own.
	StateFile string        `hcl:"state_file"`
	Parents   []ParentBlock `hcl:"parent,block"`

	maxVolume uint64
	gid       int
}

// A ParentBlock is where volumes may be created, under an id a request names.
// Exactly one of zfs, btrfs, xfs and ext4.
type ParentBlock struct {
	ID string `hcl:"id,label"`
	// ZFS is the dataset the volumes are children of, and Root the directory
	// they are mounted under: dataset <zfs>/<name> at <root>/<name>.
	ZFS  string `hcl:"zfs,optional"`
	Root string `hcl:"root,optional"`
	// Btrfs, XFS and Ext4 are the directory the volumes are created in.
	Btrfs string `hcl:"btrfs,optional"`
	XFS   string `hcl:"xfs,optional"`
	Ext4  string `hcl:"ext4,optional"`
	// ProjectIDs is the range of XFS/ext4 project ids this parent may give
	// out, "100000-199999". An id outside it is never this provisioner's.
	ProjectIDs string `hcl:"project_ids,optional"`
	// EnableQuota lets the provisioner turn btrfs quotas on when they are
	// off. Without it a btrfs parent with quotas off stops the start:
	// qgroups slow every commit as snapshots multiply (btrfs-progs
	// ch-quota-intro.rst), and that is the operator's choice to make.
	EnableQuota bool `hcl:"enable_quota,optional"`

	kind   provisionv1.Kind
	root   string
	lo, hi uint32
}

// configFile is the whole file. It has no ",remain": anything but the
// provisioner block -- a share, an admin block -- is refused by the decoder,
// because it means fileshare's file was handed to the provisioner, and
// starting anyway would hide that.
type configFile struct {
	Provisioner *Config `hcl:"provisioner,block"`
}

// LoadConfig reads the files named, and every .hcl file in the directories
// named, as one configuration holding one provisioner block, and checks it.
func LoadConfig(paths []string) (*Config, error) {
	parser := hclparse.NewParser()
	var files []*hcl.File
	var names []string
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			m, _ := filepath.Glob(filepath.Join(p, "*.hcl"))
			sort.Strings(m)
			names = append(names, m...)
			continue
		}
		names = append(names, p)
	}
	for _, p := range names {
		f, diags := parser.ParseHCLFile(p)
		if diags.HasErrors() {
			return nil, diagError(parser, diags)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no configuration files were found in %s", strings.Join(paths, ", "))
	}
	var cf configFile
	if diags := gohcl.DecodeBody(hcl.MergeFiles(files), nil, &cf); diags.HasErrors() {
		return nil, diagError(parser, diags)
	}
	if cf.Provisioner == nil {
		return nil, errors.New("the configuration has no provisioner block")
	}
	if err := cf.Provisioner.Check(); err != nil {
		return nil, err
	}
	return cf.Provisioner, nil
}

// diagError keeps the file, the line and the snippet of HCL's diagnostics.
func diagError(parser *hclparse.Parser, diags hcl.Diagnostics) error {
	var sb strings.Builder
	w := hcl.NewDiagnosticTextWriter(&sb, parser.Files(), 78, false)
	if err := w.WriteDiagnostics(diags); err != nil {
		return diags
	}
	return fmt.Errorf("%s", strings.TrimSpace(sb.String()))
}

// Check refuses a configuration that names something it cannot mean. It looks
// at nothing on disk; Run does that, at the start.
func (c *Config) Check() error {
	if _, err := socketPath(c.Listen); err != nil {
		return err
	}
	if c.ClientUID <= 0 || c.ClientUID >= math.MaxUint32 {
		return fmt.Errorf("client_uid = %d: it must be fileshare's uid, and not 0 -- ext4 lets root write past a project quota", c.ClientUID)
	}
	gid, err := lookupGroup(c.Group)
	if err != nil {
		return err
	}
	c.gid = gid
	if c.maxVolume, err = ParseSize(c.MaxVolume); err != nil {
		return fmt.Errorf("max_volume: %w", err)
	}
	if c.maxVolume == 0 {
		return errors.New("max_volume = 0 would refuse every volume")
	}
	if !filepath.IsAbs(c.StateFile) {
		return fmt.Errorf("state_file %q is not an absolute path", c.StateFile)
	}
	if len(c.Parents) == 0 {
		return errors.New("the provisioner block names no parent: there is nowhere to create a volume")
	}
	seen := map[string]bool{}
	for i := range c.Parents {
		p := &c.Parents[i]
		if seen[p.ID] {
			return fmt.Errorf("parent %q is defined twice", p.ID)
		}
		seen[p.ID] = true
		if err := p.check(); err != nil {
			return fmt.Errorf("parent %q: %w", p.ID, err)
		}
	}
	return c.checkApart()
}

func lookupGroup(g string) (int, error) {
	if g == "" {
		return 0, errors.New("group is empty: it is the group fileshare writes into the volumes through")
	}
	n, err := strconv.ParseUint(g, 10, 31)
	if err != nil {
		gr, lerr := user.LookupGroup(g)
		if lerr != nil {
			return 0, fmt.Errorf("group %q: %w", g, lerr)
		}
		if n, err = strconv.ParseUint(gr.Gid, 10, 31); err != nil {
			return 0, fmt.Errorf("group %q has gid %q", g, gr.Gid)
		}
	}
	if n == 0 {
		return 0, errors.New("group 0 would give the volumes to root's group, not to fileshare's")
	}
	return int(n), nil
}

func (p *ParentBlock) check() error {
	if err := checkName("a parent id", p.ID); err != nil {
		return err
	}
	set := 0
	for _, k := range []struct {
		v    string
		kind provisionv1.Kind
	}{{p.ZFS, provisionv1.Kind_KIND_ZFS}, {p.Btrfs, provisionv1.Kind_KIND_BTRFS},
		{p.XFS, provisionv1.Kind_KIND_XFS}, {p.Ext4, provisionv1.Kind_KIND_EXT4}} {
		if k.v != "" {
			set++
			p.kind = k.kind
		}
	}
	if set != 1 {
		return errors.New("name exactly one of zfs, btrfs, xfs and ext4")
	}
	switch p.kind {
	case provisionv1.Kind_KIND_ZFS:
		if err := checkDataset(p.ZFS); err != nil {
			return err
		}
		if p.Root == "" {
			return errors.New("a zfs parent needs root: the directory its volumes are mounted under")
		}
		p.root = p.Root
	default:
		if p.Root != "" {
			return fmt.Errorf("root is for a zfs parent; a %s parent's directory is its root", kindName(p.kind))
		}
		p.root = map[provisionv1.Kind]string{provisionv1.Kind_KIND_BTRFS: p.Btrfs,
			provisionv1.Kind_KIND_XFS: p.XFS, provisionv1.Kind_KIND_EXT4: p.Ext4}[p.kind]
	}
	if !filepath.IsAbs(p.root) || filepath.Clean(p.root) != p.root || p.root == "/" {
		return fmt.Errorf("%q is not an absolute, clean path below /", p.root)
	}
	projects := p.kind == provisionv1.Kind_KIND_XFS || p.kind == provisionv1.Kind_KIND_EXT4
	switch {
	case projects && p.ProjectIDs == "":
		return errors.New("an xfs or ext4 parent needs project_ids, the range of project ids it may give out")
	case !projects && p.ProjectIDs != "":
		return errors.New("project_ids is for an xfs or ext4 parent")
	case projects:
		var err error
		if p.lo, p.hi, err = parseRange(p.ProjectIDs); err != nil {
			return err
		}
	}
	if p.EnableQuota && p.kind != provisionv1.Kind_KIND_BTRFS {
		return errors.New("enable_quota is for a btrfs parent")
	}
	return nil
}

// checkDataset accepts a dataset name the ZFS kernel would, without the
// snapshot, bookmark and pool-only forms.
func checkDataset(ds string) error {
	if ds == "" || strings.HasPrefix(ds, "/") || strings.HasSuffix(ds, "/") || strings.Contains(ds, "//") {
		return fmt.Errorf("zfs = %q is not a dataset name", ds)
	}
	for _, c := range ds {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.ContainsRune("_-.:/", c)
		if !ok {
			return fmt.Errorf("zfs = %q: %q is not allowed in a dataset name here", ds, c)
		}
	}
	for _, part := range strings.Split(ds, "/") {
		if part == "." || part == ".." {
			return fmt.Errorf("zfs = %q is not a dataset name", ds)
		}
	}
	return nil
}

// parseRange reads "lo-hi". Project 0 is every project's default on XFS, and
// 4294967295 is the kernel's INVALID_PROJID: neither may be given out.
func parseRange(s string) (lo, hi uint32, err error) {
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return 0, 0, fmt.Errorf("project_ids = %q: want <first>-<last>", s)
	}
	l, err1 := strconv.ParseUint(strings.TrimSpace(a), 10, 32)
	h, err2 := strconv.ParseUint(strings.TrimSpace(b), 10, 32)
	if err1 != nil || err2 != nil {
		return 0, 0, fmt.Errorf("project_ids = %q: want two numbers", s)
	}
	if l == 0 || h >= math.MaxUint32 || l > h {
		return 0, 0, fmt.Errorf("project_ids = %q: want 1 <= first <= last < 4294967295", s)
	}
	return uint32(l), uint32(h), nil
}

// checkApart refuses parents that overlap: one root inside another would let
// a volume of one be a directory of the other, two datasets nested would put
// one parent's volumes among the other's children, and two project-id ranges
// that meet would make one parent's ids look like the other's.
func (c *Config) checkApart() error {
	for i := range c.Parents {
		a := &c.Parents[i]
		for _, f := range []string{c.StateFile, mustSocket(c.Listen)} {
			if pathWithin(a.root, f) {
				return fmt.Errorf("%s lies inside parent %q's root: a volume could be created over it", f, a.ID)
			}
		}
		for j := i + 1; j < len(c.Parents); j++ {
			b := &c.Parents[j]
			if pathWithin(a.root, b.root) || pathWithin(b.root, a.root) {
				return fmt.Errorf("parents %q and %q: %s and %s are one inside the other", a.ID, b.ID, a.root, b.root)
			}
			if a.ZFS != "" && b.ZFS != "" && (a.ZFS == b.ZFS || strings.HasPrefix(b.ZFS, a.ZFS+"/") || strings.HasPrefix(a.ZFS, b.ZFS+"/")) {
				return fmt.Errorf("parents %q and %q: datasets %s and %s are one inside the other", a.ID, b.ID, a.ZFS, b.ZFS)
			}
			if a.hi != 0 && b.hi != 0 && a.lo <= b.hi && b.lo <= a.hi {
				return fmt.Errorf("parents %q and %q: project ids %s and %s overlap", a.ID, b.ID, a.ProjectIDs, b.ProjectIDs)
			}
		}
	}
	return nil
}

// pathWithin reports whether path is dir itself or lies inside it.
func pathWithin(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))))
}

// socketPath is the path of a unix:// listen address.
func socketPath(listen string) (string, error) {
	p, ok := strings.CutPrefix(listen, "unix://")
	if !ok || !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return "", fmt.Errorf("listen = %q: the provisioner listens on a unix socket only, unix:///absolute/path", listen)
	}
	return p, nil
}

func mustSocket(listen string) string {
	p, _ := socketPath(listen)
	return p
}

func (c *Config) parent(id string) *ParentBlock {
	i := slices.IndexFunc(c.Parents, func(p ParentBlock) bool { return p.ID == id })
	if i < 0 {
		return nil
	}
	return &c.Parents[i]
}

func kindName(k provisionv1.Kind) string {
	return strings.ToLower(strings.TrimPrefix(k.String(), "KIND_"))
}

// ParseSize reads a size in bytes: a number, optionally followed by K, M, G,
// T, P or E -- powers of 1024, as zfs(8) and df(1) mean them -- with an
// optional "B" or "iB" after the letter.
func ParseSize(s string) (uint64, error) {
	t := strings.TrimSpace(s)
	t = strings.TrimSuffix(strings.TrimSuffix(t, "B"), "i")
	shift := 0
	if t != "" {
		if i := strings.IndexByte("KMGTPE", t[len(t)-1]); i >= 0 {
			shift = 10 * (i + 1)
			t = t[:len(t)-1]
		}
	}
	n, err := strconv.ParseUint(strings.TrimSpace(t), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a size: want a number of bytes, or one with K, M, G, T, P or E", s)
	}
	if shift > 0 && n > math.MaxUint64>>shift {
		return 0, fmt.Errorf("%q is too large", s)
	}
	return n << shift, nil
}
