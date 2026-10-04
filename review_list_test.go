// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosftp

package main

// Written by the adversarial review of v0.15.0 (go-authn/revocation's
// stack), each proving a defect it found; kept as the regression tests of
// the fixes.

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-authn/revocation"
)

// PROTOCOL.md rule 2: the copy held survives a restart. With
// ssh_krl_state_file, a replayed older list -- signed, unexpired -- is
// refused after a restart; without it (the control), it is taken.
func TestFoundRollbackAcrossRestart(t *testing.T) {
	for _, keep := range []bool{true, false} {
		ca := newTestSSHCA(t)
		now := time.Now()
		is := &krlIssuer{}
		v1raw, v1sig := ca.issue(t, 1, now.Add(-10*time.Minute), time.Hour, revocation.Namespace)
		is.set(ca.issue(t, 2, now.Add(-time.Minute), time.Hour, revocation.Namespace, 7))
		srv := httptest.NewTLSServer(is)
		var state []string
		if keep {
			state = []string{filepath.Join(t.TempDir(), "krl.state")}
		}
		l := signedKRLList(t, srv, ca, state...)
		if _, err := l.fetch(context.Background()); err != nil {
			t.Fatal(err)
		}
		// A restart; a mirror replays v1.
		is.set(v1raw, v1sig)
		l2 := signedKRLList(t, srv, ca, state...)
		_, err := l2.fetch(context.Background())
		cur, gerr := l2.get()
		replayed := err == nil && gerr == nil && !cur.(sshKRL).k.IsRevoked(ca.cert(t, 7))
		if replayed == keep {
			t.Errorf("with a state file = %v: a replayed v1 taken after a restart = %v (fetch %v, get %v)", keep, replayed, err, gerr)
		}
		srv.Close()
	}
}

// Same version, earlier issue: an issuer re-issues a list unchanged with a
// later expiry, and the earlier issue replayed would shorten it.
func TestFoundSameVersionEarlierIssueIsRefused(t *testing.T) {
	ca := newTestSSHCA(t)
	now := time.Now()
	is := &krlIssuer{}
	is.set(ca.issue(t, 2, now.Add(-time.Minute), time.Hour, revocation.Namespace, 7))
	srv := httptest.NewTLSServer(is)
	defer srv.Close()
	l := signedKRLList(t, srv, ca)
	if _, err := l.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	is.set(ca.issue(t, 2, now.Add(-50*time.Minute), time.Hour, revocation.Namespace))
	if changed, err := l.fetch(context.Background()); err == nil || changed {
		t.Errorf("an earlier issue of the same version replaced the held one (changed=%v, err=%v)", changed, err)
	}
	// Control: a later issue of the same version replaces it.
	is.set(ca.issue(t, 2, now, time.Hour, revocation.Namespace, 7))
	if changed, err := l.fetch(context.Background()); err != nil || !changed {
		t.Errorf("control: a later issue of the same version: changed=%v err=%v", changed, err)
	}
}

// A copy read back orders what comes next, but is not current until a list
// is fetched: its fetch time is not known. A tampered copy is not used.
func TestARestoredListOrdersButIsNotCurrent(t *testing.T) {
	ca := newTestSSHCA(t)
	now := time.Now()
	is := &krlIssuer{}
	is.set(ca.issue(t, 2, now, time.Hour, revocation.Namespace, 7))
	srv := httptest.NewTLSServer(is)
	defer srv.Close()
	state := filepath.Join(t.TempDir(), "krl.state")
	l := signedKRLList(t, srv, ca, state)
	if _, err := l.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	again := signedKRLList(t, srv, ca, state)
	if _, err := again.get(); !errors.Is(err, errRevocationUnknown) {
		t.Errorf("a restored list is current before any fetch: %v", err)
	}
	if again.current == nil {
		t.Fatal("the state was not read back")
	}
	// Tampered: not used.
	data, _ := os.ReadFile(state)
	data[len(data)-10] ^= 1
	os.WriteFile(state, data, 0o600)
	if tampered := signedKRLList(t, srv, ca, state); tampered.current != nil {
		t.Error("a tampered state was used")
	}
	os.WriteFile(state, []byte("not a state"), 0o600)
	if foreign := signedKRLList(t, srv, ca, state); foreign.current != nil {
		t.Error("a foreign file was used as state")
	}
}
