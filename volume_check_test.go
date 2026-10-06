// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
)

// Root, or CAP_SYS_RESOURCE (bit 24) in CapEff OR CapPrm, would write past an
// ext4 project quota -- a permitted capability is one capset(2) away from
// effective; a status that cannot be read is judged the same way.
func TestQuotaExemption(t *testing.T) {
	status := func(capPrm, capEff string) []byte {
		return []byte("Name:\tfileshare\nCapInh:\t0000000000000000\nCapPrm:\t" + capPrm + "\nCapEff:\t" + capEff + "\nCapBnd:\t000001ffffffffff\n")
	}
	const none, resource, admin, all = "0000000000000000", "0000000001000000", "0000000000200000", "000001ffffffffff"
	for _, c := range []struct {
		name   string
		euid   int
		status []byte
		err    error
		want   string
	}{
		{"an unprivileged user", 990, status(none, none), nil, ""},
		{"root", 0, status(none, none), nil, "root"},
		{"CAP_SYS_RESOURCE effective", 990, status(resource, resource), nil, "effective set"},
		{"CAP_SYS_RESOURCE permitted, not effective", 990, status(resource, none), nil, "permitted set"},
		{"everything permitted, nothing effective", 990, status(all, none), nil, "permitted set"},
		{"everything", 990, status(all, all), nil, "effective set"},
		{"CAP_SYS_ADMIN but not RESOURCE", 990, status(admin, admin), nil, ""},
		{"no CapEff", 990, []byte("Name:\tx\nCapPrm:\t" + none + "\n"), nil, "no CapEff"},
		{"no CapPrm", 990, []byte("Name:\tx\nCapEff:\t" + none + "\n"), nil, "no CapPrm"},
		{"garbage", 990, status(none, "zz"), nil, "cannot tell"},
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
