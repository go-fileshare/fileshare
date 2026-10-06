// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
)

// Root, or CAP_SYS_RESOURCE (bit 24) in CapEff, would write past an ext4
// project quota; a status that cannot be read is judged the same way.
func TestQuotaExemption(t *testing.T) {
	status := func(capEff string) []byte {
		return []byte("Name:\tfileshare\nCapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t" + capEff + "\nCapBnd:\t000001ffffffffff\n")
	}
	for _, c := range []struct {
		name   string
		euid   int
		status []byte
		err    error
		want   string
	}{
		{"an unprivileged user", 990, status("0000000000000000"), nil, ""},
		{"root", 0, status("0000000000000000"), nil, "root"},
		{"CAP_SYS_RESOURCE alone", 990, status("0000000001000000"), nil, "CAP_SYS_RESOURCE in its effective set"},
		{"everything", 990, status("000001ffffffffff"), nil, "CAP_SYS_RESOURCE in its effective set"},
		{"CAP_SYS_ADMIN but not RESOURCE", 990, status("0000000000200000"), nil, ""},
		{"no CapEff", 990, []byte("Name:\tx\n"), nil, "cannot tell"},
		{"garbage", 990, status("zz"), nil, "cannot tell"},
		{"unreadable", 990, nil, errors.New("EACCES"), "cannot tell"},
	} {
		got := quotaExemptFrom(c.euid, c.status, c.err)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// The real questions, asked of a directory that is no volume: on Linux the
// kernel answers, elsewhere every one refuses.
func TestTheKernelsAnswers(t *testing.T) {
	dir := t.TempDir()
	_, magicErr := statfsMagic(dir)
	_, ino, isDir, devErr := pathDevIno(dir)
	_, _, projErr := pathProject(dir)
	if runtime.GOOS != "linux" {
		if magicErr == nil || devErr == nil || projErr == nil {
			t.Errorf("volumes off Linux: %v %v %v", magicErr, devErr, projErr)
		}
		if os.Geteuid() != 0 && processQuotaExempt() != "" {
			t.Errorf("an unprivileged process judged exempt: %s", processQuotaExempt())
		}
		return
	}
	if magicErr != nil || devErr != nil || !isDir || ino == 0 {
		t.Errorf("statfs %v, stat %v (dir %t, ino %d)", magicErr, devErr, isDir, ino)
	}
	if _, _, _, err := pathDevIno(dir + "/nope"); err == nil {
		t.Error("stat of nothing succeeded")
	}
	if _, err := statfsMagic(dir + "/nope"); err == nil {
		t.Error("statfs of nothing succeeded")
	}
	// What /proc says about this process, whatever it is: a judgement,
	// never a failure to read.
	if why := processQuotaExempt(); strings.Contains(why, "cannot tell") {
		t.Errorf("/proc/self/status: %s", why)
	}
}
