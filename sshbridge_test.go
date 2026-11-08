// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosftp

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"reflect"
	"testing"
	"time"

	"github.com/go-authn/sshcert"
	fork "github.com/go-filesystems/ssh"
	xssh "golang.org/x/crypto/ssh"
)

// The bridge between go-filesystems/ssh (the fork the SFTP server speaks) and
// golang.org/x/crypto/ssh (what the judges take): a value crosses by its wire
// encoding, and everything a judge reads must come out the same.

func bridgeSigner(t *testing.T) xssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := xssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// bridgeCert is a certificate with every field the wire format has: critical
// options, extensions (one with a newline, one empty), Reserved bytes, two
// principals and a NUL inside the KeyId.
func bridgeCert(t *testing.T, ca xssh.Signer, key xssh.PublicKey) *xssh.Certificate {
	t.Helper()
	c := &xssh.Certificate{
		Key: key, Serial: 7, CertType: xssh.UserCert, KeyId: "alice\x00tail",
		ValidPrincipals: []string{"alice", "bob"},
		ValidAfter:      uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
		Permissions: xssh.Permissions{
			CriticalOptions: map[string]string{"source-address": "127.0.0.1/32", "force-command": "/bin/true"},
			Extensions: map[string]string{sshcert.DomainGrantExtension: `["files.example.org"]`,
				"groups@go-authn.org": "a\nb", "permit-pty": ""},
		},
		Reserved: []byte("reserved-bytes"),
	}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTheBridgeKeepsACertificateByteForByte(t *testing.T) {
	ca := bridgeSigner(t)
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ukey, err := xssh.NewPublicKey(&ek.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	orig := bridgeCert(t, ca, ukey)

	pk, err := fork.ParsePublicKey(orig.Marshal())
	if err != nil {
		t.Fatalf("the fork does not parse it: %v", err)
	}
	fc := pk.(*fork.Certificate)
	got, err := upstreamCert(fc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Marshal(), orig.Marshal()) {
		t.Error("the bridged certificate is not byte-identical")
	}
	if !bytes.Equal(got.Key.Marshal(), orig.Key.Marshal()) || !bytes.Equal(got.SignatureKey.Marshal(), orig.SignatureKey.Marshal()) {
		t.Error("Key or SignatureKey differs")
	}
	if !reflect.DeepEqual(got.ValidPrincipals, orig.ValidPrincipals) {
		t.Errorf("principals %v, want %v", got.ValidPrincipals, orig.ValidPrincipals)
	}
	if got.ValidAfter != orig.ValidAfter || got.ValidBefore != orig.ValidBefore {
		t.Errorf("validity %d-%d, want %d-%d", got.ValidAfter, got.ValidBefore, orig.ValidAfter, orig.ValidBefore)
	}
	if !reflect.DeepEqual(got.CriticalOptions, orig.CriticalOptions) {
		t.Errorf("critical options %v, want %v", got.CriticalOptions, orig.CriticalOptions)
	}
	if !reflect.DeepEqual(got.Extensions, orig.Extensions) {
		t.Errorf("extensions %v, want %v", got.Extensions, orig.Extensions)
	}
	if got.Serial != orig.Serial || got.KeyId != orig.KeyId || got.CertType != orig.CertType {
		t.Errorf("serial/keyid/type %d %q %d, want %d %q %d", got.Serial, got.KeyId, got.CertType, orig.Serial, orig.KeyId, orig.CertType)
	}
	if !bytes.Equal(got.Reserved, orig.Reserved) {
		t.Errorf("Reserved %q, want %q", got.Reserved, orig.Reserved)
	}
	if got.KeyId != "alice\x00tail" {
		t.Errorf("the NUL in the KeyId did not survive: %q", got.KeyId)
	}
	if !bytes.Equal(got.Signature.Blob, orig.Signature.Blob) || got.Signature.Format != orig.Signature.Format {
		t.Error("the signature changed")
	}

	// A plain key crosses as a key.
	fk, err := fork.ParsePublicKey(ukey.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	k, err := upstreamKey(fk)
	if err != nil || !bytes.Equal(k.Marshal(), ukey.Marshal()) {
		t.Errorf("a plain key through the bridge: %v", err)
	}
}

// badWire is a key whose wire encoding is not a key at all.
type badWire struct{ fork.PublicKey }

func (badWire) Marshal() []byte { return []byte{0, 0, 0, 3, 'x', 'y', 'z'} }

// The refusal of sshbridge.go's first branch, reached through upstreamKey and
// through upstreamCert: bytes the upstream does not parse. (The second branch,
// "parsed as a key that is not a certificate", cannot be reached from a
// *fork.Certificate: its wire type is always a -cert- type, which x/crypto
// parses only as a *Certificate or refuses -- so it is a guard, not a path.)
func TestTheBridgeRefuses(t *testing.T) {
	if k, err := upstreamKey(badWire{}); err == nil || k != nil {
		t.Errorf("a key that is not one crossed the bridge: %v, %v", k, err)
	}
	ca := bridgeSigner(t)
	ukey := bridgeSigner(t).PublicKey()
	pk, err := fork.ParsePublicKey(bridgeCert(t, ca, ukey).Marshal())
	if err != nil {
		t.Fatal(err)
	}
	fc := pk.(*fork.Certificate)
	// A certificate whose signature key is damaged after the fork read it.
	damaged := *fc
	damaged.SignatureKey = badWire{fc.SignatureKey}
	if c, err := upstreamCert(&damaged); err == nil || c != nil {
		t.Errorf("a certificate with a damaged signature key crossed the bridge: %v, %v", c, err)
	}
	// The control: the undamaged one crosses.
	if c, err := upstreamCert(fc); err != nil || c == nil {
		t.Errorf("control: %v", err)
	}
}
