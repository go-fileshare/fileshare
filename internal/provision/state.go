// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package provision

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"golang.org/x/sys/unix"
)

// A record is one volume this provisioner created.
//
// The state file is the provisioner's memory of what is its own, and for two
// kinds it IS the ownership mark: a btrfs subvolume carries nothing a caller
// could not also create, so it is ours when its id and uuid are the ones
// recorded here; an XFS/ext4 project id is ours when it lies in the parent's
// range AND is recorded here. A ZFS dataset carries its own mark (a LOCAL
// fileshare:volume property), and the record is there to list it and to
// mount it again at the start.
type record struct {
	Parent  string    `json:"parent"`
	Name    string    `json:"name"`
	Kind    string    `json:"kind"`
	Quota   uint64    `json:"quota_bytes"`
	Created time.Time `json:"created"`
	// Pending is set before anything is created and cleared once all of it
	// is: a crash in between leaves a record that says "this was being
	// made", which a CreateVolume with the same parameters finishes and a
	// DeleteVolume removes. Without it a half-made subvolume would be
	// something nobody recorded -- not ours, and never cleaned up.
	Pending bool `json:"pending,omitempty"`

	ProjectID  uint32   `json:"project_id,omitempty"`  // xfs, ext4
	SubvolID   uint64   `json:"subvol_id,omitempty"`   // btrfs
	SubvolUUID string   `json:"subvol_uuid,omitempty"` // btrfs, hex
	Snapshots  []string `json:"snapshots,omitempty"`   // btrfs; ZFS asks the pool
}

type stateFile struct {
	Version int       `json:"version"`
	Volumes []*record `json:"volumes"`
}

const stateVersion = 1

// state is the state file, held open and locked for the life of the process.
type state struct {
	path string
	lock *os.File
	vols []*record
}

// openState reads the state file, creating nothing but its lock: a missing
// file is an empty state. ⛔ It takes an exclusive lock, so two provisioners
// on one state file -- two allocators of one range of project ids -- refuse
// to run side by side.
func openState(path string) (*state, error) {
	lock, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("%s is locked by another provisioner: %w", path, err)
	}
	st := &state{path: path, lock: lock}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return st, nil
	case err != nil:
		lock.Close()
		return nil, err
	}
	var f stateFile
	if err := json.Unmarshal(data, &f); err != nil {
		lock.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if f.Version != stateVersion {
		lock.Close()
		return nil, fmt.Errorf("%s: version %d, this provisioner reads %d", path, f.Version, stateVersion)
	}
	for _, r := range f.Volumes {
		if r == nil || checkName("a parent", r.Parent) != nil || checkName("a volume", r.Name) != nil {
			lock.Close()
			return nil, fmt.Errorf("%s: a record names no valid volume: %+v", path, r)
		}
	}
	st.vols = f.Volumes
	return st, nil
}

func (s *state) close() error { return s.lock.Close() }

func (s *state) get(parent, name string) *record {
	for _, r := range s.vols {
		if r.Parent == parent && r.Name == name {
			return r
		}
	}
	return nil
}

func (s *state) put(r *record) {
	if s.get(r.Parent, r.Name) == nil {
		s.vols = append(s.vols, r)
	}
}

func (s *state) remove(parent, name string) {
	s.vols = slices.DeleteFunc(s.vols, func(r *record) bool { return r.Parent == parent && r.Name == name })
}

// save writes the whole state to a new file and renames it over the old one,
// syncing both the file and the directory: a crash leaves the old state or
// the new one, never half of either.
func (s *state) save() error {
	data, err := json.MarshalIndent(stateFile{Version: stateVersion, Volumes: s.vols}, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
