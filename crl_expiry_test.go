// SPDX-License-Identifier: BSD-3-Clause

//go:build !nonfs

package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"
)

// A CRL is current until its nextUpdate -- RFC 5280's validation does not
// use one past it: "If the current time is after the value of the CRL next
// update field, then do one of the following" (6.3.3, step (a)(1)): a delta
// or a new complete CRL -- however recently it was fetched: an issuer that keeps answering with the same expired CRL
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

// Same CRL number, earlier thisUpdate: refused, as a lower number is
// (RFC 5280 5.2.3 gives such CRLs different numbers; go-authn/bridge before
// v0.10.1 did not).
func TestASameNumberCRLIssuedEarlierIsRefused(t *testing.T) {
	ca := newBridgeCA(t, t.TempDir())
	parse := crlParser([]*x509.Certificate{ca.cert})
	mk := func(this time.Time) revoked {
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(9),
			ThisUpdate: this, NextUpdate: this.Add(time.Hour)}, ca.cert, ca.key)
		if err != nil {
			t.Fatal(err)
		}
		l, err := parse(der)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	now := time.Now()
	later, earlier := mk(now), mk(now.Add(-30*time.Minute))
	if !earlier.older(later) {
		t.Error("the same number issued earlier is not older")
	}
	if later.older(earlier) {
		t.Error("control: the later issue is older")
	}
}
