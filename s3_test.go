// SPDX-License-Identifier: BSD-3-Clause

//go:build !nos3

package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/go-volumes/s3/sigv4"
)

// S3, end to end, against the running server.
//
// The requests are signed by the same package a client signs with, not by a
// string this test wrote: a hand-built Authorization header would only prove
// that the server agrees with the test's idea of SigV4.

// s3Do signs a request as user and runs it against the running server.
func s3Do(t *testing.T, r *running, user, password, method, path string) (*http.Response, []byte) {
	t.Helper()
	addr, ok := r.addrs["s3"]
	if !ok {
		t.Skip("this binary was built without s3")
	}
	req, err := http.NewRequest(method, "http://"+addr+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := sigv4.HashSHA256(nil)
	req.Header.Set("x-amz-content-sha256", payload)
	sigv4.New("eu-west-1", "s3", sigv4.Credentials{
		AccessKeyID: user, SecretAccessKey: password,
	}).SignRaw(req, payload, time.Now().UTC())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func s3Config(t *testing.T, dir string) string {
	t.Helper()
	photos := image(t, dir, "photos.img", map[string]string{
		"/holiday.txt": "a beach",
	})
	scratch := image(t, dir, "scratch.img", map[string]string{
		"/notes.txt": "anyone may read this",
	})
	return configFor(t, dir, fmt.Sprintf(`
share "photos" {
  image   = %q
  allow   = ["alice"]
}

share "scratch" {
  image = %q
}`, hclPath(photos), hclPath(scratch)))
}

// A share is a bucket, and the buckets are the ones this person may use.
func TestS3_SharesAreBuckets(t *testing.T) {
	r := start(t, s3Config(t, t.TempDir()))

	resp, body := s3Do(t, r, "alice", "hunter2", http.MethodGet, "/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	var got struct {
		Buckets []struct{ Name string } `xml:"Buckets>Bucket"`
	}
	if err := xml.Unmarshal(body, &got); err != nil {
		t.Fatalf("parsing: %v\n%s", err, body)
	}
	var names []string
	for _, b := range got.Buckets {
		names = append(names, b.Name)
	}
	if strings.Join(names, ",") != "photos,scratch" {
		t.Errorf("alice sees %v, want [photos scratch]", names)
	}
}

// ⛔ The access rules, THROUGH the protocol rather than in the configuration.
// bob is not allowed photos, so he must not see the bucket and must not read
// through it either -- checked separately, because a listing that hides a
// bucket while GET still serves it is the worse of the two failures.
func TestS3_ASharePersonMayNotUseIsNotThere(t *testing.T) {
	r := start(t, s3Config(t, t.TempDir()))

	_, body := s3Do(t, r, "bob", "swordfish", http.MethodGet, "/")
	if strings.Contains(string(body), "photos") {
		t.Errorf("bob was shown the photos bucket:\n%s", body)
	}
	if !strings.Contains(string(body), "scratch") {
		t.Errorf("bob was not shown scratch, which he may use:\n%s", body)
	}

	resp, body := s3Do(t, r, "bob", "swordfish", http.MethodGet, "/photos/holiday.txt")
	if resp.StatusCode == http.StatusOK {
		t.Errorf("bob read through a share he may not use: %s", body)
	}
	if strings.Contains(string(body), "a beach") {
		t.Errorf("bob got the contents of a share he may not use")
	}
}

func TestS3_GetObject(t *testing.T) {
	r := start(t, s3Config(t, t.TempDir()))

	resp, body := s3Do(t, r, "alice", "hunter2", http.MethodGet, "/photos/holiday.txt")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if string(body) != "a beach" {
		t.Errorf("body = %q, want %q", body, "a beach")
	}
}

func TestS3_WrongPasswordIsRefused(t *testing.T) {
	r := start(t, s3Config(t, t.TempDir()))

	resp, body := s3Do(t, r, "alice", "not-her-password", http.MethodGet, "/")
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("a wrong secret was accepted: %s", body)
	}
	if !strings.Contains(string(body), "SignatureDoesNotMatch") {
		t.Errorf("want SignatureDoesNotMatch, got: %s", body)
	}
}

// ⛔⛔ Naming somebody else in the credential must buy nothing. The access key
// chooses WHICH tree to serve, and it is read from an unsigned header -- so a
// request signed with alice's secret while claiming to be bob has to fail,
// or the tree would be chosen by an attacker.
func TestS3_SigningAsOneUserWhileClaimingAnotherFails(t *testing.T) {
	r := start(t, s3Config(t, t.TempDir()))
	addr, ok := r.addrs["s3"]
	if !ok {
		t.Skip("built without s3")
	}
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/photos/holiday.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := sigv4.HashSHA256(nil)
	req.Header.Set("x-amz-content-sha256", payload)
	// Signed with ALICE's secret, but claiming to be BOB.
	sigv4.New("eu-west-1", "s3", sigv4.Credentials{
		AccessKeyID: "bob", SecretAccessKey: "hunter2",
	}).SignRaw(req, payload, time.Now().UTC())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("a mismatched credential was accepted: %s", body)
	}
	if strings.Contains(string(body), "a beach") {
		t.Fatal("a mismatched credential read a share it may not use")
	}
}

func TestS3_UnsignedIsRefusedInTheShapeAClientParses(t *testing.T) {
	r := start(t, s3Config(t, t.TempDir()))
	addr, ok := r.addrs["s3"]
	if !ok {
		t.Skip("built without s3")
	}
	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status %d, want 403", resp.StatusCode)
	}
	var e struct {
		Code string `xml:"Code"`
	}
	if err := xml.Unmarshal(body, &e); err != nil {
		t.Fatalf("the refusal is not XML a client can read: %v\n%s", err, body)
	}
	if e.Code != "AccessDenied" {
		t.Errorf("code = %q, want AccessDenied", e.Code)
	}
}

// Writes are off for now, and a refusal is better than a half-written object.
func TestS3_WritesAreRefused(t *testing.T) {
	r := start(t, s3Config(t, t.TempDir()))
	resp, _ := s3Do(t, r, "alice", "hunter2", http.MethodPut, "/photos/new.txt")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("PUT got %d, want 403", resp.StatusCode)
	}
}

// ⛔ The capability rule, tested directly. S3 and SMB are NEIGHBOURS, not
// copies: an identity holding only an NT hash serves SMB and cannot serve S3,
// because an HMAC cannot be computed from MD4.
//
// Driven through canServeUser rather than through `check`'s output, because an
// NT hash arrives from SQL or LDAP and cannot be written in an HCL user block
// at all -- so a config-driven test could not build the case that matters.
func TestS3_NeedsThePasswordNotAHash(t *testing.T) {
	for _, tc := range []struct {
		what     string
		id       *directory.Identity
		smb, s3v bool
	}{
		{"a password", directory.NewIdentity("alice", directory.WithPassword("hunter2")), true, true},
		{"only an NT hash", directory.NewIdentity("dora", directory.WithNTHash(make([]byte, 16))), true, false},
		{"only a verifier", directory.NewIdentity("eli", directory.WithVerifier(func(string) error { return nil })), false, false},
	} {
		if got := canServeUser("smb", tc.id, nil); got != tc.smb {
			t.Errorf("%s: smb = %v, want %v", tc.what, got, tc.smb)
		}
		if got := canServeUser("s3", tc.id, nil); got != tc.s3v {
			t.Errorf("%s: s3 = %v, want %v", tc.what, got, tc.s3v)
		}
	}
}
