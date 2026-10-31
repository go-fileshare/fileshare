// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"go/build"
	"os"
	"strings"
	"testing"
)

// TestNoSignalSubscriptionOnWasip1 keeps signal.Notify out of every file of
// this package that a wasip1 build compiles. On wasip1 the runtime waits for a
// signal by yielding in a loop, so one subscription starves the network
// poller: the server listened and never accepted (signals_wasip1.go).
func TestNoSignalSubscriptionOnWasip1(t *testing.T) {
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH = "wasip1", "wasm"
	// The tags the playground image is built with, and the fuller set.
	for _, tags := range [][]string{
		{"nosql", "noopenpubkey"},
		{"nosql", "noopenpubkey", "nosmb", "nonfs", "nos3", "nosftp", "nogrpc", "nopartitioned", "noprovisioner"},
	} {
		ctx.BuildTags = tags
		ents, err := os.ReadDir(".")
		if err != nil {
			t.Fatal(err)
		}
		compiled := 0
		for _, e := range ents {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			ok, err := ctx.MatchFile(".", name)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				continue
			}
			compiled++
			b, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			// The calls, not their mention in a comment (signals_wasip1.go
			// explains the defect by naming the function).
			if strings.Contains(string(b), "signal.Notify(") || strings.Contains(string(b), "signal.NotifyContext(") {
				t.Errorf("tags %v: %s is compiled for wasip1 and calls signal.Notify", tags, name)
			}
		}
		// The control: the files the wasip1 build depends on are seen.
		if compiled < 20 {
			t.Fatalf("tags %v: only %d files match wasip1, the scan cannot be trusted", tags, compiled)
		}
		for _, must := range []string{"signals_wasip1.go", "listen_wasip1.go", "worker_other.go", "device_other.go"} {
			if ok, _ := ctx.MatchFile(".", must); !ok {
				t.Errorf("tags %v: %s is not compiled for wasip1", tags, must)
			}
		}
		for _, mustNot := range []string{"signals.go", "listen.go", "hangup_unix.go"} {
			if ok, _ := ctx.MatchFile(".", mustNot); ok {
				t.Errorf("tags %v: %s is compiled for wasip1", tags, mustNot)
			}
		}
	}
}
