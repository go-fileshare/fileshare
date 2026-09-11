// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/go-volumes/gpt"
)

// Choosing a partition, for every filesystem rather than for four of them.
//
// A disk image holding FAT32, ext4 or exFAT has a partition table in front of
// it just as often as one holding XFS does -- and detection reads offset zero,
// where a partitioned image has a table rather than a filesystem. So the
// partition is chosen HERE, and what the driver receives is a view of the
// bytes between that partition's start and end:
//
//	share "photos" {
//	  image           = "/srv/disk.img"
//	  partition_label = "data"        # a GPT name, what lsblk calls PARTLABEL
//	}
//
// ⛔ An INDEX moves. A disk repartitioned, a tool that writes entries in a
// different order, an image restored from a backup with one partition fewer --
// and `partition = 2` now names something else, silently, because a filesystem
// is still found there. A label or a UUID names the partition itself, which is
// why Linux fstabs stopped using indexes years ago. The index is here because
// somebody will have an MBR image, which has neither.

// errNoPartitions is a table that parsed and holds nothing.
var errNoPartitions = errors.New("no partitions")

// A partitionChoice is what the configuration said, resolved once.
type partitionChoice struct {
	index int    // 1-based; 0 means "not by index"
	label string // a GPT partition name
	uuid  string // a GPT unique partition GUID, as people write it
}

func (c partitionChoice) empty() bool { return c.index == 0 && c.label == "" && c.uuid == "" }

// String says what was asked for, for a message that repeats it back.
func (c partitionChoice) String() string {
	switch {
	case c.uuid != "":
		return "the partition with UUID " + c.uuid
	case c.label != "":
		return fmt.Sprintf("the partition labelled %q", c.label)
	case c.index > 0:
		return fmt.Sprintf("partition %d", c.index)
	}
	return "the whole image"
}

// selectPartition finds the partition a share asked for and returns a view of
// it, or the image itself when nothing was asked for and there is no table.
func selectPartition(r io.ReaderAt, size int64, c partitionChoice) (io.ReaderAt, int64, string, error) {
	if c.empty() {
		return r, size, "", nil
	}
	var p gpt.Partition
	var err error
	switch {
	case c.uuid != "":
		p, err = gpt.ByUUID(r, size, c.uuid)
		err = orNoPartitions(r, size, err)
	case c.label != "":
		p, err = gpt.ByName(r, size, c.label)
		err = orNoPartitions(r, size, err)
	default:
		// The configuration counts from 1, the way every partitioning tool
		// prints them; the table's own Index is a slot number that skips
		// empty entries, so this counts the partitions that are THERE.
		var parts []gpt.Partition
		if parts, err = gpt.List(r, size); err == nil {
			switch {
			case len(parts) == 0:
				// ⛔ Not the same as ErrNoTable, and it reads the same to
				// somebody: a FAT32 boot sector ends with 0x55AA, so a plain
				// filesystem image looks exactly like an MBR whose four
				// entries are empty. Both mean "there is no partition here".
				err = errNoPartitions
			case c.index > len(parts):
				err = fmt.Errorf("%w: %s, and this image has %d",
					gpt.ErrNotFound, c.String(), len(parts))
			default:
				p = parts[c.index-1]
			}
		}
	}
	if err != nil {
		if errors.Is(err, gpt.ErrNoTable) || errors.Is(err, errNoPartitions) {
			return nil, 0, "", fmt.Errorf("%s was asked for, and this image has no partition table "+
				"(or an empty one -- a filesystem image's own boot sector can look like one): "+
				"remove the partition setting to use the image itself", c.String())
		}
		return nil, 0, "", err
	}
	if p.Length <= 0 {
		return nil, 0, "", fmt.Errorf("%s is empty", c.String())
	}
	return io.NewSectionReader(r, p.StartOffset, p.Length), p.Length, describe(p), nil
}

// orNoPartitions turns "not found" into "there are none" when that is what
// happened: a person who asked for a label on an image with no partitions
// should be told the image has none, not that the label is wrong.
func orNoPartitions(r io.ReaderAt, size int64, err error) error {
	if err == nil || !errors.Is(err, gpt.ErrNotFound) {
		return err
	}
	if parts, listErr := gpt.List(r, size); listErr == nil && len(parts) == 0 {
		return errNoPartitions
	}
	return err
}

// describe says which partition was taken, in the words the configuration
// could have used to ask for it.
func describe(p gpt.Partition) string {
	var parts []string
	if p.Name != "" {
		parts = append(parts, fmt.Sprintf("%q", p.Name))
	}
	if u := p.UUID(); u != "" {
		parts = append(parts, u)
	}
	where := fmt.Sprintf("%s slot %d at %d bytes", p.Scheme, p.Index, p.StartOffset)
	if len(parts) == 0 {
		return where
	}
	return strings.Join(parts, ", ") + " (" + where + ")"
}
