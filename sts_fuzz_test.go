// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"net/http"
	"strings"
	"testing"
)

// signedHeadersOf reads a header an attacker writes: it must never panic, and
// what it returns is always lower-case, without a separator.
func FuzzSignedHeadersOf(f *testing.F) {
	for _, s := range []string{
		"AWS4-HMAC-SHA256 Credential=ASIA/20260101/eu-west-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=00",
		"AWS4-HMAC-SHA256 SignedHeaders=",
		"AWS4-HMAC-SHA256 SignedHeaders=;;;, SignedHeaders=host",
		"AWS4-HMAC-SHA256 ,,,",
		"AWS4-HMAC-SHA256 ",
		"Bearer abc",
		"",
		"AWS4-HMAC-SHA256 SignedHeaders=X-AMZ-SECURITY-TOKEN",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, auth string) {
		r := &http.Request{Header: http.Header{}}
		r.Header.Set("Authorization", auth)
		for _, h := range signedHeadersOf(r) {
			if h != strings.ToLower(h) || strings.Contains(h, ";") {
				t.Fatalf("%q: header %q", auth, h)
			}
		}
	})
}

// The same, for the form that decides whether x-amz-security-token is signed.
func TestSignedHeadersOf(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=A/x, SignedHeaders=Host;X-Amz-Security-Token, Signature=0")
	got := strings.Join(signedHeadersOf(r), ",")
	if got != "host,x-amz-security-token" {
		t.Errorf("got %q", got)
	}
	r.Header.Set("Authorization", "Bearer x")
	if signedHeadersOf(r) != nil {
		t.Error("a Bearer header has signed headers")
	}
}
