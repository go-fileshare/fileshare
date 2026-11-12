// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosmb

package main

import (
	"strings"
	"testing"
)

// The two parsers read another program's output inside a server: they must not
// panic or loop on anything. Seeds are in testdata/fuzz/<name>, committed.

func FuzzParseMountinfo(f *testing.F) {
	f.Add("36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue\n")
	f.Add("40 36 0:5 / /a\\040b\\134c rw - tmpfs none rw\n")
	f.Add("1 2 3:4 / /x - \n- - - - - - - - -\n\\\\\\0\\77")
	f.Fuzz(func(t *testing.T, in string) {
		ents, err := parseMountinfo(strings.NewReader(in))
		if err != nil {
			return
		}
		for _, e := range ents {
			_ = isPartitionOf(e.Source, "/dev/loop1")
		}
	})
}

func FuzzParseHdiutilInfo(f *testing.F) {
	f.Add(hdiutilSample)
	f.Add(`<plist version="1.0"><dict><key>images</key><array/></dict></plist>`)
	f.Add(`<plist><dict><key>images</key><array><dict><key>image-path</key><string>/x</string>` +
		`<key>system-entities</key><array><dict><key>dev-entry</key><string>/dev/disk1</string></dict></array></dict></array></dict></plist>`)
	f.Add(`<plist>` + strings.Repeat("<array>", 50))
	f.Fuzz(func(t *testing.T, in string) {
		_, _ = parseHdiutilInfo(strings.NewReader(in))
	})
}
