// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package main

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// SMB over QUIC binds UDP itself, so the two ways of serving that hand a child
// a TCP socket refuse it, and say so, rather than serve TCP in its place.
func TestQUICIsRefusedWhereTCPSocketsAreHandedOver(t *testing.T) {
	// An identity block, so that a refusal that went missing falls through to the
	// root check and fails the assertion below instead of a nil dereference.
	cfg := &config{
		Identity: &identityBlock{ServiceUser: "fs"},
		Serves:   []serveBlock{{Protocol: "smb", Addr: "127.0.0.1:0", TLS: true, Transport: "quic"}},
	}

	t.Run("identity = system", func(t *testing.T) {
		// Before the check for root, so it holds for every uid.
		err := serveWithLauncher(cfg, nil, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "binds UDP itself") {
			t.Fatalf("serveWithLauncher: %v", err)
		}
	})

	t.Run("isolated children", func(t *testing.T) {
		out, err := os.CreateTemp(t.TempDir(), "announce")
		if err != nil {
			t.Fatal(err)
		}
		defer out.Close()
		// A bound, so that a refusal that went missing is a failure and not a hang.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err = runIsolated(ctx, cfg, out, nil)
		if err == nil || !strings.Contains(err.Error(), "binds UDP itself") {
			t.Fatalf("runIsolated: %v", err)
		}
	})
}
