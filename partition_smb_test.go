//go:build !nosmb

// The SMB half of the partition tests.
//
// ⛔ It is a file of its own because mountSMB lives behind !nosmb, and a
// `t.Skip` for a protocol this binary lacks runs long after the compiler has
// already failed. The same mistake, in the same week, in the same package.
package main

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/go-volumes/gpt"
)

// The partition, read over SMB — the whole path, from a table at offset zero
// to a client that never hears the word "partition".
func TestAPartitionIsReadOverSMB(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	img, _ := partitionedImage(t, dir)
	open := image(t, dir, "open.img", map[string]string{"/b.txt": "b"})
	r := start(t, people(t, dir)+fmt.Sprintf(`
share "photos" {
  image           = %q
  partition_label = "photos"
  allow           = ["alice"]
}

share "open" { image = %q }
`, hclPath(img), hclPath(open))+serveBlocks())

	fs := mountSMB(t, r, "alice", "hunter2", "photos")
	got, err := fs.ReadFile("greeting.txt")
	if err != nil {
		t.Fatalf("reading over smb: %v", err)
	}
	if string(got) != "hello from a partition" {
		t.Errorf("smb read %q", got)
	}
}

// ⛔ A share that chose a partition is read-only, and SAYS so at startup.
//
// The refusal itself has two possible causes, which is why the announcement
// matters: the view handed to a sniffable driver has no WriteAt at all, and
// the block adapter the four partition-aware drivers get refuses writes
// explicitly. Either way a write would otherwise land at the partition's
// offset measured from the start of the whole IMAGE -- on the table, as often
// as not -- so the test checks the table is still readable afterwards.
func TestWritingIntoAChosenPartitionIsRefused(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	img, _ := partitionedImage(t, dir)
	open := image(t, dir, "open.img", map[string]string{"/b.txt": "b"})
	r := start(t, people(t, dir)+fmt.Sprintf(`
share "photos" {
  image           = %q
  partition_label = "photos"
  allow           = ["alice"]
}

share "open" { image = %q }
`, hclPath(img), hclPath(open))+serveBlocks())

	if said := r.out.String(); !strings.Contains(said, "so it is read-only") {
		t.Errorf("the server did not say the share is read-only:\n%s", said)
	}
	fs := mountSMB(t, r, "alice", "hunter2", "photos")
	if err := fs.WriteFile("new.txt", []byte("mine"), 0o644); err == nil {
		t.Error("a write into a chosen partition was accepted")
	}
	// The disk's own partition table is what a misaimed write would have
	// destroyed, so it is what the test checks is still there.
	f, err := os.Open(img)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	parts, err := gpt.List(f, fileSize(t, img))
	if err != nil || len(parts) != 2 {
		t.Errorf("the partition table reads %v, %v", parts, err)
	}
}
