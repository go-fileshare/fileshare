// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A share must not be another share's source, nor lie inside another share's
// directory, nor be a directory holding one: the outer share would be a way
// into the inner one, with the outer one's rules. The audit that found it read
// an alice-only image, anonymously over NFS, as a file of an open directory
// share -- and bob, refused the share over SMB, overwrote its image.
//
// Every overlap is refused at start, whichever share comes first in the file;
// the controls are the same shares side by side, which start.
func TestAShareInsideAnotherShareIsRefusedAtStart(t *testing.T) {
	for _, tc := range []struct {
		name   string
		shares func(dir string) string
		refuse string // "" = must start
	}{
		{"an image inside a directory share", func(dir string) string {
			pub := mkdir(t, dir, "pub")
			img := image(t, pub, "photos.img", map[string]string{"/diary.txt": "secret"})
			return fmt.Sprintf("share \"pub\" { directory = %q }\nshare \"photos\" { image = %q }\n", hclPath(pub), hclPath(img))
		}, "holds share"},
		{"a directory inside a directory share", func(dir string) string {
			pub := mkdir(t, dir, "pub")
			priv := mkdir(t, pub, "private")
			return fmt.Sprintf("share \"pub\" { directory = %q }\nshare \"private\" { directory = %q }\n", hclPath(pub), hclPath(priv))
		}, "holds share"},
		{"the inner share written first", func(dir string) string {
			pub := mkdir(t, dir, "pub")
			priv := mkdir(t, pub, "private")
			return fmt.Sprintf("share \"private\" { directory = %q }\nshare \"pub\" { directory = %q }\n", hclPath(priv), hclPath(pub))
		}, "lies inside share"},
		{"one directory, two shares", func(dir string) string {
			pub := mkdir(t, dir, "pub")
			return fmt.Sprintf("share \"a\" { directory = %q }\nshare \"b\" { directory = %q }\n", hclPath(pub), hclPath(pub))
		}, "same source"},
		{"one image spelled through a symlink", func(dir string) string {
			img := image(t, dir, "disk.img", map[string]string{"/x.txt": "x"})
			link := filepath.Join(dir, "link.img")
			if err := os.Symlink(img, link); err != nil {
				t.Skip(err)
			}
			return fmt.Sprintf("share \"a\" { image = %q }\nshare \"b\" { image = %q }\n", hclPath(img), hclPath(link))
		}, "same source"},
		{"CONTROL: two sibling directories", func(dir string) string {
			return fmt.Sprintf("share \"a\" { directory = %q }\nshare \"b\" { directory = %q }\n",
				hclPath(mkdir(t, dir, "a")), hclPath(mkdir(t, dir, "b")))
		}, ""},
		{"CONTROL: a directory and an image beside it", func(dir string) string {
			pub := mkdir(t, dir, "pub")
			img := image(t, dir, "photos.img", map[string]string{"/x.txt": "x"})
			return fmt.Sprintf("share \"pub\" { directory = %q }\nshare \"photos\" { image = %q }\n", hclPath(pub), hclPath(img))
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := write(t, dir, "test.hcl", configFor(t, dir, tc.shares(dir)))
			cfg, err := loadConfig([]string{path})
			if err != nil {
				t.Fatalf("loading: %v", err)
			}
			srv, err := open(cfg, io.Discard)
			if err == nil {
				srv.Close()
			}
			switch {
			case tc.refuse == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case tc.refuse != "" && err == nil:
				t.Fatal("started: one share is a way into the other")
			case tc.refuse != "" && !strings.Contains(err.Error(), tc.refuse):
				t.Fatalf("refused for another reason: %v", err)
			}
		})
	}
}

// The one overlap allowed: two shares choosing DIFFERENT partitions of one
// disk image, each driver confined to its own. The same partition twice, or
// one share taking the whole image, is the same source again.
func TestOnlyDifferentPartitionsMayShareAnImage(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "disk.img")
	one, two := 1, 2
	for _, tc := range []struct {
		name string
		a, b shareBlock
		ok   bool
	}{
		{"partitions 1 and 2", shareBlock{Name: "a", Image: img, Partition: &one}, shareBlock{Name: "b", Image: img, Partition: &two}, true},
		{"a label and a uuid", shareBlock{Name: "a", Image: img, PartitionLabel: "x"}, shareBlock{Name: "b", Image: img, PartitionUUID: "u"}, true},
		{"partition 1 twice", shareBlock{Name: "a", Image: img, Partition: &one}, shareBlock{Name: "b", Image: img, Partition: &one}, false},
		{"one label twice", shareBlock{Name: "a", Image: img, PartitionLabel: "x"}, shareBlock{Name: "b", Image: img, PartitionLabel: "x"}, false},
		{"the whole image and a partition", shareBlock{Name: "a", Image: img}, shareBlock{Name: "b", Image: img, Partition: &one}, false},
	} {
		all := []shareBlock{tc.a, tc.b}
		if err := checkNoShareHoldsShare(all, all); (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want allowed = %v", tc.name, err, tc.ok)
		}
	}
}

func mkdir(t *testing.T, parent, name string) string {
	t.Helper()
	p := filepath.Join(parent, name)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}
