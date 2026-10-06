// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"
	"unicode/utf8"
)

// The shares the admin API created, and who it granted them to.
//
// They are kept in a file of their own, not written back into the
// configuration: the configuration is a person's, with its comments and its
// order, and a program that rewrites it is a program that loses both. The
// state file is the API's, and a person reads it rather than edits it.
//
// ⛔ The two never define the same share. A name the configuration uses is
// refused by CreateShare, and a state file naming one the configuration now
// also defines is refused at startup, naming both -- which one should win is
// the kind of question that must be answered by a person, once.

const stateVersion = 1

type stateFile struct {
	Version int            `json:"version"`
	Shares  []managedShare `json:"shares"`
	// Disabled names the shares DisableShare took offline, whichever file
	// defines them. A name that no longer matches any share is kept: a share
	// taken offline and later written back into the configuration comes back
	// offline, which is what whoever took it offline asked for.
	Disabled []string `json:"disabled,omitempty"`
}

// isDisabled reports whether a share is taken offline, comparing names the
// way SMB does.
func (st *stateFile) isDisabled(name string) bool {
	return slices.ContainsFunc(st.Disabled, func(d string) bool { return strings.EqualFold(d, name) })
}

// split sorts blocks into the ones served and the ones taken offline.
func (st *stateFile) split(blocks []shareBlock) (serve, offline []shareBlock) {
	for _, b := range blocks {
		if st.isDisabled(b.Name) {
			offline = append(offline, b)
			continue
		}
		serve = append(serve, b)
	}
	return serve, offline
}

// A managedShare is a share block the API wrote, with its grants in place of
// the allow and writers lists.
type managedShare struct {
	Name           string   `json:"name"`
	Image          string   `json:"image,omitempty"`
	Directory      string   `json:"directory,omitempty"`
	ReadOnly       bool     `json:"read_only,omitempty"`
	Filesystem     string   `json:"filesystem,omitempty"`
	Partition      *int     `json:"partition,omitempty"`
	PartitionLabel string   `json:"partition_label,omitempty"`
	PartitionUUID  string   `json:"partition_uuid,omitempty"`
	Protocols      []string `json:"protocols,omitempty"`
	Grants         []grant  `json:"grants"`
	// Volume is the volume a share was made from. Directory is then where
	// the provisioner said it was when the share was created, for a person
	// reading the file: what is served is where it says it is NOW, asked
	// again at every start and checked again before it is served.
	Volume *volumeRef `json:"volume,omitempty"`
	// resolved is what asking for the volume found, in memory only.
	resolved *volumeResolution
}

// A grant is one subject, spelled the way the configuration spells it --
// alice, @staff, oidc:groups:X, oidc:user:bob -- and whether it may write.
type grant struct {
	Subject string `json:"subject"`
	Write   bool   `json:"write,omitempty"`
}

// block is the share block this is. Access is by grant, which the block's two
// lists say this way: everybody granted is allowed, the writers are the ones
// granted ACCESS_WRITE -- and when nobody is, the share is served read-only,
// because an empty writers list means "everybody allowed writes" and a grant
// of READ must not turn into one of WRITE.
func (m managedShare) block() shareBlock {
	b := shareBlock{Name: m.Name, Image: m.Image, Directory: m.Directory, ReadOnly: m.ReadOnly,
		Filesystem: m.Filesystem, Partition: m.Partition, PartitionLabel: m.PartitionLabel,
		PartitionUUID: m.PartitionUUID, Protocols: m.Protocols}
	if m.Volume != nil {
		b.volume = m.Volume.String()
		if m.resolved != nil && m.resolved.path != "" {
			b.Directory = m.resolved.path
		}
	}
	for _, g := range m.Grants {
		b.Allow = append(b.Allow, g.Subject)
		if g.Write {
			b.Writers = append(b.Writers, g.Subject)
		}
	}
	b.noWriters = len(b.Writers) == 0
	return b
}

func (m managedShare) clone() managedShare {
	m.Protocols = slices.Clone(m.Protocols)
	m.Grants = slices.Clone(m.Grants)
	if m.Volume != nil {
		v := *m.Volume
		m.Volume = &v
	}
	if m.Partition != nil {
		p := *m.Partition
		m.Partition = &p
	}
	return m
}

// readState reads the state file. One that does not exist yet is an empty
// state: that is what a server the API has never changed has.
func readState(path string) (*stateFile, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &stateFile{Version: stateVersion}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("the admin state file: %w", err)
	}
	var st stateFile
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("the admin state file %s: %w", path, err)
	}
	if st.Version != stateVersion {
		return nil, fmt.Errorf("the admin state file %s is version %d, and this fileshare reads version %d",
			path, st.Version, stateVersion)
	}
	return &st, nil
}

// writeState replaces the state file whole, or not at all: written beside it,
// synced, renamed over it, and the directory synced so the rename itself
// survives a power cut. A state file half written is a server that will not
// start, or worse, one that starts with half its shares.
func writeState(path string, st *stateFile) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomically(path, append(data, '\n'))
}

// writeFileAtomically writes data beside path, syncs it, renames it over
// path, and syncs the directory so the rename itself survives a power cut.
func writeFileAtomically(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // a no-op once renamed
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// withState adds the API's shares to a configuration read from files, takes
// out the ones DisableShare took offline, and remembers which are which.
//
// Every share is CHECKED, served or not: a disabled share must still be one
// that EnableShare can bring back, and a configuration that says two things
// at once is refused whether or not one of them is being served.
func withState(cfg *config) error {
	if cfg.Admin == nil {
		return nil
	}
	st, err := readState(cfg.Admin.StateFile)
	if err != nil {
		return err
	}
	cfg.fromFiles = slices.Clone(cfg.Shares)
	fromFiles := map[string]string{}
	for _, b := range cfg.Shares {
		fromFiles[strings.ToUpper(b.Name)] = b.Name
	}
	cfg.managed = map[string]bool{}
	// Every volume share's volume is asked for, and checked, before
	// anything is opened; see volume.go.
	cfg.volumes = resolveVolumes(cfg.Admin, st.Shares)
	all := slices.Clone(cfg.Shares)
	unavailable := map[string]string{}
	for _, m := range st.Shares {
		if other, taken := fromFiles[strings.ToUpper(m.Name)]; taken {
			return fmt.Errorf("share %q is in the admin state file %s and share %q is in the configuration: "+
				"one name, two definitions. Remove one of them", m.Name, cfg.Admin.StateFile, other)
		}
		if m.Volume != nil {
			// Its path was checked against the roots as it was resolved,
			// or it is not served and its old path does not matter.
			m.resolved = cfg.volumes[strings.ToUpper(m.Name)]
			if why := m.unavailable(); why != "" {
				unavailable[strings.ToUpper(m.Name)] = why
			}
			b := m.block()
			b.confine = cfg.Admin.SourceRoots
			all = append(all, b)
			cfg.managed[strings.ToUpper(m.Name)] = true
			continue
		}
		// ⛔ Checked again at every start: the roots may have been narrowed,
		// or the file edited, since the share was created -- and a state
		// file is not a way past source_roots.
		src := m.Image
		if src == "" {
			src = m.Directory
		}
		// Resolved as the API resolves it; a source that is gone is judged
		// by its spelling, and the share then waits offline as any other.
		if real, err := filepath.EvalSymlinks(src); err == nil {
			src = real
		} else {
			src = filepath.Clean(src)
		}
		if _, _, err := rootOf(cfg.Admin.SourceRoots, src); err != nil {
			return fmt.Errorf("share %q in the admin state file %s: %v; remove it there, or widen source_roots",
				m.Name, cfg.Admin.StateFile, err)
		}
		b := m.block()
		b.confine = cfg.Admin.SourceRoots
		all = append(all, b)
		cfg.managed[strings.ToUpper(m.Name)] = true
	}
	cfg.Shares = all
	if err := cfg.check(); err != nil {
		return err
	}
	var serve []shareBlock
	serve, cfg.offline = st.split(all)
	cfg.Shares = nil
	for _, b := range serve {
		if why, out := unavailable[strings.ToUpper(b.Name)]; out {
			cfg.unavailable = append(cfg.unavailable, unavailableShare{block: b, why: why})
			continue
		}
		cfg.Shares = append(cfg.Shares, b)
	}
	return nil
}

// A manager applies the admin API's changes: one at a time, each one checked
// the way a configuration is checked, opened before anything is stopped, and
// written down before it is served.
type manager struct {
	mu  sync.Mutex
	srv *server
	// files is the configuration as the files said it, without the API's
	// shares: every change is that plus the state, never an edit of what
	// was served last.
	files *config
	state *stateFile
	path  string
	roots []string
	audit io.Writer
	// vols is the provisioner, when the admin block names one; see
	// volume_grpc.go.
	vols volumeService
	// servedAPI and offline count the API's shares being served and the
	// shares taken offline, readable without waiting for a change in
	// progress -- a scrape must not stall behind a swap.
	servedAPI atomic.Int64
	offline   atomic.Int64
}

// recount sets the counts a scrape reads, from a state.
func (m *manager) recount(st *stateFile) {
	_, serve := m.blocks(st)
	var api int64
	for _, b := range serve {
		if indexOf(st, b.Name) >= 0 {
			api++
		}
	}
	m.servedAPI.Store(api)
	var offline int64
	for _, b := range m.files.Shares {
		if st.isDisabled(b.Name) {
			offline++
		}
	}
	for _, s := range st.Shares {
		if st.isDisabled(s.Name) {
			offline++
		}
	}
	m.offline.Store(offline)
}

func newManager(srv *server, cfg *config) (*manager, error) {
	st, err := readState(cfg.Admin.StateFile)
	if err != nil {
		return nil, err
	}
	files := *cfg
	files.Shares = slices.Clone(cfg.fromFiles)
	// What withState found for each volume share is what is served now.
	for i := range st.Shares {
		if st.Shares[i].Volume != nil {
			st.Shares[i].resolved = cfg.volumes[strings.ToUpper(st.Shares[i].Name)]
		}
	}
	m := &manager{srv: srv, files: &files, state: st, path: cfg.Admin.StateFile,
		roots: cfg.Admin.SourceRoots, audit: srv.out}
	m.recount(st)
	return m, nil
}

// A refusal is a change the server will not make, and why; the gRPC layer
// maps its kind onto a status code.
type refusal struct {
	kind refusalKind
	msg  string
}

type refusalKind int

const (
	refusedInvalid refusalKind = iota
	refusedNotFound
	refusedExists
	refusedPrecondition
	// refusedUnavailable is a provisioner that did not answer.
	refusedUnavailable
)

func (r *refusal) Error() string { return r.msg }

func refuse(kind refusalKind, format string, args ...any) error {
	return &refusal{kind, fmt.Sprintf(format, args...)}
}

// indexOf is where a share is in a state, or -1.
func indexOf(st *stateFile, name string) int {
	return slices.IndexFunc(st.Shares, func(s managedShare) bool { return strings.EqualFold(s.Name, name) })
}

// changedBlocks are the API shares next defines differently from the state
// being served: new, or altered.
func (m *manager) changedBlocks(next *stateFile) []shareBlock {
	var out []shareBlock
	for _, ms := range next.Shares {
		i := indexOf(m.state, ms.Name)
		if i < 0 || !reflect.DeepEqual(m.state.Shares[i], ms) {
			out = append(out, ms.block())
		}
	}
	return out
}

// exists reports whether a state, with the files, defines a share.
func (m *manager) exists(st *stateFile, name string) bool {
	return m.fromFiles(name) || indexOf(st, name) >= 0
}

func (m *manager) fromFiles(name string) bool {
	return slices.ContainsFunc(m.files.Shares, func(b shareBlock) bool { return strings.EqualFold(b.Name, name) })
}

// applied is what serving a change did, for the caller to be told.
type applied struct {
	generation uint64
	closed     uint64
}

// change applies edit to a copy of the state and, when the server can honour
// the result, serves it. who is the caller, for the audit line; what says what
// was done, in words.
func (m *manager) change(who, what string, edit func(st *stateFile) error) (applied, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	next := &stateFile{Version: stateVersion, Disabled: slices.Clone(m.state.Disabled)}
	for _, s := range m.state.Shares {
		next.Shares = append(next.Shares, s.clone())
	}
	// Refusals are audited too: a caller probing what it may do is what an
	// audit log is read for.
	if err := edit(next); err != nil {
		m.srv.stats.refused.Add(1)
		fmt.Fprintf(m.audit, "admin (%s): refused, nothing changed -- would have %s: %s\n", logSafe(who), logSafe(what), logSafe(err.Error()))
		return applied{}, err
	}
	a, err := m.apply(next)
	if err != nil {
		m.srv.stats.refused.Add(1)
		fmt.Fprintf(m.audit, "admin (%s): refused, nothing changed -- would have %s: %s\n", logSafe(who), logSafe(what), logSafe(err.Error()))
		return applied{}, err
	}
	m.state = next
	m.recount(next)
	m.srv.stats.applied.Add(1)
	fmt.Fprintf(m.audit, "admin (%s): %s -- generation %d, %d connection(s) closed\n",
		logSafe(who), logSafe(what), a.generation, a.closed)
	return a, nil
}

// blocks is every share a state defines together with the files, and the
// ones to serve: not taken offline, and -- a volume share -- with its volume
// found and checked.
func (m *manager) blocks(st *stateFile) (all, serve []shareBlock) {
	all = slices.Clone(m.files.Shares)
	out := map[string]bool{}
	for _, s := range st.Shares {
		b := s.block()
		b.confine = m.roots
		all = append(all, b)
		if s.unavailable() != "" {
			out[strings.ToUpper(s.Name)] = true
		}
	}
	serve, _ = st.split(all)
	serve = slices.DeleteFunc(serve, func(b shareBlock) bool { return out[strings.ToUpper(b.Name)] })
	return all, serve
}

// apply checks a state against the configuration, opens what it needs,
// writes it down, and serves it -- in that order, so that every way it can
// fail leaves what was served, and what was written, as they were.
//
// Every share is checked and resolved, offline or not; only the ones served
// are opened.
func (m *manager) apply(next *stateFile) (applied, error) {
	all, serve := m.blocks(next)
	cfg := *m.files
	cfg.Shares = all
	if err := cfg.check(); err != nil {
		return applied{}, refuse(refusedInvalid, "%v", err)
	}
	// Against the people who exist -- but only what this change WRITES: the
	// API shares it creates or alters. Everything else was checked when it
	// was written, and the directory may have moved since (a group emptied,
	// somebody deleted); a strict check of it here would refuse every change,
	// the revocations included, until somebody edited the file. What the
	// rest expands to now is what a reload would make of it.
	changed := *m.files
	changed.Groups = nil
	changed.Shares = m.changedBlocks(next)
	if err := m.files.checkNoShareHoldsSecrets(changed.Shares); err != nil {
		return applied{}, refuse(refusedPrecondition, "%v", err)
	}
	if err := checkNoShareHoldsShare(all, changed.Shares); err != nil {
		return applied{}, refuse(refusedPrecondition, "%v", err)
	}
	if err := changed.resolve(m.srv.dir, m.srv.people()); err != nil {
		return applied{}, refuse(refusedInvalid, "%v", err)
	}
	m.srv.changeMu.Lock()
	defer m.srv.changeMu.Unlock()
	prev := m.srv.currentShares()
	var notes []string
	shares, err := m.srv.openSharesExpanding(serve, prev, tolerantExpand(m.srv.dir, m.srv.people(), &notes))
	if err != nil {
		return applied{}, refuse(refusedPrecondition, "%v", err)
	}
	if err := writeState(m.path, next); err != nil {
		release(shares, prev)
		return applied{}, fmt.Errorf("writing %s: %w", m.path, err)
	}
	closed, err := m.srv.swap(shares)
	if err != nil {
		release(shares, prev)
		// The file now says what is not served. Put it back, so the next
		// start does not serve what this call said it refused.
		writeState(m.path, m.state)
		return applied{}, err
	}
	return applied{generation: m.srv.generationNumber(), closed: closed}, nil
}

// withinRoots refuses a source outside every source root, and returns the
// path to keep. It is resolved -- symbolic links followed, `..` taken out --
// before it is compared, because "/srv/images/../../etc" starts with
// "/srv/images". And it is the RESOLVED path that is kept: keeping the one
// that was given would let a link swapped after this check move the share
// somewhere this check never looked.
func (m *manager) withinRoots(path string) (string, error) {
	if len(m.roots) == 0 {
		return "", refuse(refusedPrecondition, "the admin block names no source_roots, so this server cannot create shares: "+
			"say where images and directories may be taken from")
	}
	if !filepath.IsAbs(path) {
		return "", refuse(refusedInvalid, "%q is not an absolute path", path)
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", refuse(refusedPrecondition, "%s: %v", path, err)
	}
	if _, _, err := rootOf(m.roots, real); err != nil {
		return "", refuse(refusedPrecondition, "%v", err)
	}
	return real, nil
}

// rootOf is the source root a resolved path lies under, resolved itself,
// and the path relative to it -- what an os.Root is opened on and asked for,
// so that the KERNEL confines the open to the root: a link swapped in after
// any check made here leads nowhere outside it.
func rootOf(roots []string, real string) (root, rel string, err error) {
	for _, r := range roots {
		// The root as resolved, then as spelled: a path kept before the
		// root's own spelling resolved differently is still under it, and
		// what is opened from it is confined by an os.Root either way.
		spellings := []string{filepath.Clean(r)}
		if resolved, err := filepath.EvalSymlinks(r); err == nil {
			spellings = []string{resolved, filepath.Clean(r)}
		}
		for _, root := range spellings {
			rel, err := filepath.Rel(root, real)
			if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
				return root, rel, nil
			}
		}
	}
	return "", "", fmt.Errorf("%s is not under any of the source roots (%s)", real, strings.Join(roots, ", "))
}

// logSafe is s as one line of an audit log: a name, a subject, a caller or
// an error carrying a line break or an escape sequence would otherwise write
// a line of its own -- "admin (uid=0): deleted share payroll" -- that nobody
// wrote. Such a string is quoted, Go-escaped; any other is left as it is.
func logSafe(s string) string {
	if !utf8.ValidString(s) || strings.ContainsFunc(s, notPrintable) {
		return strconv.Quote(s)
	}
	return s
}

// notPrintable is a character a log line or a listing would not show as
// itself: a control character, and also a line or paragraph separator
// (U+2028, U+2029), which unicode.IsControl does not count.
func notPrintable(r rune) bool { return !unicode.IsPrint(r) }
