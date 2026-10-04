// SPDX-License-Identifier: BSD-3-Clause

//go:build !nonfs

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"testing"
	"time"
)

// A CRL is current until its nextUpdate (RFC 5280 6.3.3: past it, the
// relying party "MUST consider the CRL to be invalid"), however recently
// it was fetched: an issuer that keeps answering with the same expired CRL
// -- or a 304 for it -- does not keep it alive. go-authn/bridge before
// v0.10.0 did that for an hour after the last revocation, through an ETag
// that named the version while the body changed.
func TestACRLPastItsNextUpdateIsNotCurrent(t *testing.T) {
	dir := t.TempDir()
	ca := newBridgeCA(t, dir) // publishes a CRL with nextUpdate an hour on
	l, err := newRevocationList("x509_crl", "", ca.crlFile, "", time.Minute, 24*time.Hour,
		crlParser([]*x509.Certificate{ca.cert}), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := l.get(); err != nil {
		t.Fatalf("control: a fresh CRL is not current: %v", err)
	}
	// Past nextUpdate, fetched again a moment ago (the same file: nothing
	// new), and well within max_age: still refused.
	at := time.Now().Add(61 * time.Minute)
	l.now = func() time.Time { return at }
	if _, err := l.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := l.get(); !errors.Is(err, errRevocationUnknown) {
		t.Errorf("a CRL past its nextUpdate, fetched a moment ago: %v", err)
	}
}
