// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux && !darwin

package main

import (
	"context"
	"os"
)

// platformMountedBy cannot tell here. FreeBSD (mdconfig / mdmfs), the other
// BSDs (vnconfig), Windows (Mount-DiskImage) and wasip1 each have their own way
// to attach an image and none is queried: a share is served writable, and the
// README says that nothing here keeps the OS from mounting the same image.
func platformMountedBy(context.Context, os.FileInfo) (string, error) {
	return "", errMountUnsupported
}
