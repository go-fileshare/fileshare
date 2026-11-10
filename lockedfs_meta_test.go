// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	ext4 "github.com/go-filesystems/ext4"
	fat32 "github.com/go-filesystems/fat32"
	filesystem "github.com/go-filesystems/interface"
	ufs "github.com/go-filesystems/ufs"
)

// newUFS is an image of a driver that has MetadataSetter (ufs v0.5.0
// metadata.go:63), holding /a.txt.
func newUFS(t *testing.T) filesystem.Filesystem {
	t.Helper()
	file, err := os.Create(filepath.Join(t.TempDir(), "ufs.img"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	if err := file.Truncate(16 << 20); err != nil {
		t.Fatal(err)
	}
	u, err := ufs.Mkfs(file, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.WriteFile("/a.txt", []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	return u
}

// lockFS carries MetadataSetter when, and only when, the driver has it: smb
// v0.10.0 calls Chtimes, and a wrapper that hid it made every image drop a
// client's access and write times.
func TestLockFSCarriesMetadataSetterOnlyWhenTheDriverHasIt(t *testing.T) {
	has := newUFS(t)
	if _, ok := has.(filesystem.MetadataSetter); !ok {
		t.Skip("ufs lost MetadataSetter: pick another driver for this control")
	}
	if _, ok := lockFS(has).(filesystem.MetadataSetter); !ok {
		t.Error("lockFS hid MetadataSetter from a driver that has it")
	}
	// The other capabilities are still there beside it.
	if _, ok := lockFS(has).(filesystem.TimesReader); !ok {
		if _, driver := has.(filesystem.TimesReader); driver {
			t.Error("lockFS lost TimesReader beside MetadataSetter")
		}
	}

	if _, ok := lockFS(plainFS{}).(filesystem.MetadataSetter); ok {
		t.Error("lockFS invented MetadataSetter for a driver without it")
	}
	// A real driver without it: fat32 v0.12.0 has no Chtimes.
	fat, err := fat32.Format(filepath.Join(t.TempDir(), "fat.img"), 64<<20, fat32.FormatConfig{Label: "TEST"})
	if err != nil {
		t.Fatal(err)
	}
	defer fat.Close()
	if _, ok := fat.(filesystem.MetadataSetter); ok {
		t.Skip("fat32 gained MetadataSetter: pick another driver for this control")
	}
	if _, ok := lockFS(fat).(filesystem.MetadataSetter); ok {
		t.Error("lockFS invented MetadataSetter for fat32")
	}
}

func TestLockedChtimesReachesTheDriver(t *testing.T) {
	e, err := ext4.Format(filepath.Join(t.TempDir(), "ext4.img"), 64<<20, ext4.FormatConfig{Label: "TEST"})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := e.WriteFile("/a.txt", []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	fsys := lockFS(e)
	ms, ok := fsys.(filesystem.MetadataSetter)
	if !ok {
		t.Fatal("lockFS hid MetadataSetter from ext4")
	}
	tr, ok := fsys.(filesystem.TimesReader)
	if !ok {
		t.Fatal("lockFS hid TimesReader from ext4")
	}
	want := time.Date(2020, 5, 17, 10, 30, 0, 0, time.UTC)
	if err := ms.Chtimes("/a.txt", want, want); err != nil {
		t.Fatal(err)
	}
	ft, err := tr.Times("/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := ft.Mtime.Get(); !m.Equal(want) {
		t.Errorf("mtime %v after Chtimes, want %v", m, want)
	}
}

// Chtimes writes: it runs under the exclusive lock, beside readers.
func TestLockedChtimesRunsBesideReaders(t *testing.T) {
	fsys := lockFS(newUFS(t))
	ms, ok := fsys.(filesystem.MetadataSetter)
	if !ok {
		t.Skip("no MetadataSetter")
	}
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := range 50 {
				at := time.Unix(int64(1_600_000_000+i*1000+j), 0)
				if err := ms.Chtimes("/a.txt", at, at); err != nil {
					t.Error(err)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for range 50 {
				if _, err := fsys.ReadFile("/a.txt"); err != nil {
					t.Error(err)
					return
				}
				if _, err := fsys.Stat("/a.txt"); err != nil {
					t.Error(err)
					return
				}
				if _, err := fsys.ListDir("/"); err != nil {
					t.Error(fmt.Errorf("ListDir: %w", err))
					return
				}
			}
		}()
	}
	wg.Wait()
}
