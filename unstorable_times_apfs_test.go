// SPDX-License-Identifier: BSD-3-Clause

//go:build !nopartitioned

package main

// withAPFS: this binary can serve an apfs image (a share has to name it, and
// -tags nopartitioned leaves apfs out).
const withAPFS = true
