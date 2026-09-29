// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"strings"
	"testing"
	"time"
)

func TestReloadInterval(t *testing.T) {
	for in, want := range map[string]string{"": "", "5m": "", "1s": "", "soon": "not a duration", "500ms": "at most once a second"} {
		c := &config{Reload: in}
		d, err := c.reloadEvery()
		switch {
		case want == "" && err != nil:
			t.Errorf("%q refused: %v", in, err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
			t.Errorf("%q: %v, want a refusal saying %q", in, err, want)
		}
		if in == "5m" && d != 5*time.Minute {
			t.Errorf("5m read as %v", d)
		}
	}
}
