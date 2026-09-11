package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	fat32 "github.com/go-filesystems/fat32"
	"github.com/go-volumes/gpt"
)

// A partitioned disk image holding FAT32, which is the ordinary case.
//
// Detection reads offset zero, and on a partitioned image that is the table
// rather than a filesystem -- so before this, the only way to serve such an
// image was to carve the partition out with dd first. The share says which
// partition instead, three ways, and the least fragile of them is not the
// index.
func TestAPartitionedDiskHoldingFAT32(t *testing.T) {
	dir := t.TempDir()
	img, want := partitionedImage(t, dir)

	for _, tc := range []struct{ name, setting string }{
		{"by index", "partition = 2"},
		{"by label", `partition_label = "photos"`},
		{"by uuid", fmt.Sprintf("partition_uuid = %q", want)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`
share "disk" {
  image = %q
  %s
}
`, hclPath(img), tc.setting) + serveBlocks()
			out, err := execute(t, "check", write(t, dir, tc.name+".hcl", body))
			if err != nil {
				t.Fatalf("check: %v\n%s", err, out)
			}
			// The filesystem INSIDE the partition was found, which is the
			// whole point: offset zero holds a partition table.
			if !strings.Contains(out, "fat32") {
				t.Errorf("the fat32 inside the partition was not found:\n%s", out)
			}
			// And the report says which partition, since the image path
			// alone cannot.
			if !strings.Contains(out, "photos") {
				t.Errorf("check does not say which partition it took:\n%s", out)
			}
		})
	}
}

// The three ways disagree about nothing, because only one may be given.
func TestOnlyOneWayToNameAPartition(t *testing.T) {
	dir := t.TempDir()
	img, uuid := partitionedImage(t, dir)
	body := fmt.Sprintf(`
share "disk" {
  image           = %q
  partition       = 2
  partition_label = "photos"
  partition_uuid  = %q
}
`, hclPath(img), uuid) + serveBlocks()
	_, err := loadConfig([]string{write(t, dir, "c.hcl", body)})
	if err == nil || !strings.Contains(err.Error(), "3 ways") {
		t.Errorf("error = %v, want one about choosing a partition several ways", err)
	}
}

// What a partition setting cannot do, said rather than guessed at.
func TestPartitionSettingsThatCannotWork(t *testing.T) {
	dir := t.TempDir()
	img, _ := partitionedImage(t, dir)
	bare := image(t, dir, "bare.img", map[string]string{"/a.txt": "a"})

	for _, tc := range []struct{ name, share, want string }{
		{
			"a label nothing has",
			fmt.Sprintf("image = %q\n  partition_label = \"absent\"", hclPath(img)),
			"no partition named",
		},
		{
			"a uuid nothing has",
			fmt.Sprintf("image = %q\n  partition_uuid = \"00000000-0000-0000-0000-000000000000\"", hclPath(img)),
			"no partition with UUID",
		},
		{
			"an index past the end",
			fmt.Sprintf("image = %q\n  partition = 9", hclPath(img)),
			"this image has 2",
		},
		{
			// ⛔ The one that would otherwise be silent: a partition asked
			// for on an image that has no table at all.
			"a partition on an image with no table",
			fmt.Sprintf("image = %q\n  partition = 1", hclPath(bare)),
			"no partition table",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf("share \"disk\" {\n  %s\n}\n", tc.share) + serveBlocks()
			_, err := execute(t, "check", write(t, dir, strings.ReplaceAll(tc.name, " ", "_")+".hcl", body))
			if err == nil {
				t.Fatal("the configuration was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want one mentioning %q", err, tc.want)
			}
		})
	}

	// A UUID that is not one is refused at load, before anything is opened.
	body := fmt.Sprintf("share \"disk\" {\n  image = %q\n  partition_uuid = \"not-a-uuid\"\n}\n", hclPath(img)) + serveBlocks()
	if _, err := loadConfig([]string{write(t, dir, "baduuid.hcl", body)}); err == nil ||
		!strings.Contains(err.Error(), "not a GUID") {
		t.Errorf("a malformed uuid gave %v", err)
	}
	// And an index that counts from zero is a misunderstanding worth naming.
	body = fmt.Sprintf("share \"disk\" {\n  image = %q\n  partition = 0\n}\n", hclPath(img)) + serveBlocks()
	if _, err := loadConfig([]string{write(t, dir, "zero.hcl", body)}); err == nil ||
		!strings.Contains(err.Error(), "count from 1") {
		t.Errorf("partition 0 gave %v", err)
	}
}

// partitionedImage builds a GPT disk with two partitions: a small empty one
// first, so an index of 1 would be wrong, and a FAT32 one named "photos".
// It returns the path and the second partition's UUID.
func partitionedImage(t *testing.T, dir string) (string, string) {
	t.Helper()
	const (
		sector    = 512
		size      = 96 << 20
		firstLBA  = 2048
		firstEnd  = 4095 // 1 MiB, empty
		secondLBA = 4096 // where the fat32 goes
		// A whole number of 4 KiB clusters, which is eight sectors: it is the
		// COUNT that has to divide, not the end sector -- fat32.Format
		// refuses a size that does not, and a partition ending mid-cluster is
		// not one to serve.
		secondCount = ((size/sector - 34) - secondLBA + 1) &^ 7
		secondEnd   = secondLBA + secondCount - 1
	)
	path := filepath.Join(dir, "disk.img")

	// The FAT32 filesystem, made on its own and then poured into the
	// partition: fat32.Format wants a file it owns.
	inner := filepath.Join(dir, "inner.img")
	fsys, err := fat32.Format(inner, (secondEnd-secondLBA+1)*sector, fat32.FormatConfig{Label: "PHOTOS"})
	if err != nil {
		t.Fatal(err)
	}
	if err := fsys.WriteFile("/greeting.txt", []byte("hello from a partition"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fsys.Close(); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(inner)
	if err != nil {
		t.Fatal(err)
	}

	disk := make([]byte, size)
	// A protective MBR, so anything reading the first sector sees a disk that
	// is partitioned rather than one that is empty.
	disk[510], disk[511] = 0x55, 0xAA
	disk[446+4] = 0xEE
	binary.LittleEndian.PutUint32(disk[446+8:], 1)
	binary.LittleEndian.PutUint32(disk[446+12:], uint32(size/sector-1))

	uuid := [16]byte{0x78, 0x56, 0x34, 0x12, 0xBC, 0x9A, 0xF0, 0xDE, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	entries := make([]byte, 128*128)
	copy(entries[0:], gptEntry(gpt.LinuxFilesystemGUID, [16]byte{1}, firstLBA, firstEnd, "spare"))
	copy(entries[128:], gptEntry(gpt.LinuxFilesystemGUID, uuid, secondLBA, secondEnd, "photos"))
	copy(disk[2*sector:], entries)

	header := make([]byte, sector)
	copy(header[0:], []byte("EFI PART"))
	binary.LittleEndian.PutUint32(header[8:], 0x00010000)
	binary.LittleEndian.PutUint32(header[12:], 92)
	binary.LittleEndian.PutUint64(header[24:], 1)                     // this header
	binary.LittleEndian.PutUint64(header[32:], uint64(size/sector-1)) // the backup
	binary.LittleEndian.PutUint64(header[40:], firstLBA)
	binary.LittleEndian.PutUint64(header[48:], uint64(size/sector-34))
	binary.LittleEndian.PutUint64(header[72:], 2) // the entries
	binary.LittleEndian.PutUint32(header[80:], 128)
	binary.LittleEndian.PutUint32(header[84:], 128)
	copy(disk[sector:], header)

	copy(disk[secondLBA*sector:], payload)
	if err := os.WriteFile(path, disk, 0o644); err != nil {
		t.Fatal(err)
	}
	return path, "12345678-9abc-def0-1122-334455667788"
}

// gptEntry is one 128-byte GPT entry.
func gptEntry(typeGUID, uniqueGUID [16]byte, startLBA, endLBA uint64, name string) []byte {
	e := make([]byte, 128)
	copy(e[0:16], typeGUID[:])
	copy(e[16:32], uniqueGUID[:])
	binary.LittleEndian.PutUint64(e[32:], startLBA)
	binary.LittleEndian.PutUint64(e[40:], endLBA)
	for i, c := range utf16.Encode([]rune(name)) {
		binary.LittleEndian.PutUint16(e[56+i*2:], c)
	}
	return e
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}
