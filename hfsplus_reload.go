// SPDX-License-Identifier: BSD-3-Clause

package main

import "github.com/go-filesystems/detect"

// hfsplusOptsIn is whether an HFS+ image of this size is opened for writing under
// this hfsplus_writable_max: the share's opt-in, before any journal or lock
// check. It is the answer a reload compares (see hfsplusReopens).
func hfsplusOptsIn(max, size int64) bool { return max > 0 && size > 0 && size <= max }

// hfsplusReopens is whether a reload must open an HFS+ image again instead of
// adopting the driver prev has open: the share's opt-in changed whether the
// image is written (go-fileshare/fileshare#129). A writable driver kept after the
// opt-in is removed would keep writing until a restart; a read-only one kept
// after it is added would ignore it.
//
// What is compared is the setting against the image's size, not the open driver,
// so a share that fell back for another reason (a journal, a lock) and keeps the
// same answer is adopted as before, and a size changed from one writable value to
// another does not open a second writer, which could not take the image lock.
func hfsplusReopens(prev *share, b shareBlock) bool {
	if prev.kind != detect.HFSPlus || prev.openedReadOnly || !prev.askedWrite || b.ReadOnly {
		return false
	}
	size := int64(prev.size)
	return hfsplusOptsIn(hfsplusWritableMax(prev.block), size) != hfsplusOptsIn(hfsplusWritableMax(b), size)
}
