// SPDX-License-Identifier: BSD-3-Clause

//go:build !nos3

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

// The access key S3 reads before checking any signature is a claim, and an
// unverified claim must not grow anything: only somebody the directory knows
// gets a server of their own, and those are bounded. The audit sent 200
// requests with fresh 512 KiB keys and none of them signed; 101 MiB stayed on
// the heap after GC. Here, a thousand strangers leave the cache empty and get
// the same refusal as one; known people fill it up to its limit and no
// further.
func TestS3BuildsNothingForAnAccessKeyNobodyHas(t *testing.T) {
	r := start(t, s3Config(t, t.TempDir()))
	h := &s3ByUser{server: r.srv, proto: protocolByName("s3"), byUser: map[string]http.Handler{}, limit: 1}
	ask := func(key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+key+
			"/20260101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=00")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	// The request id differs for every answer (go-filesystems/s3 v0.3.0);
	// everything else must not depend on the key.
	reqID := regexp.MustCompile(`<RequestId>[^<]*</RequestId>`)
	body := func(w *httptest.ResponseRecorder) string { return reqID.ReplaceAllString(w.Body.String(), "") }
	first := ask("stranger-0")
	for i := 1; i < 1000; i++ {
		w := ask(fmt.Sprintf("stranger-%d", i))
		if w.Code != first.Code || body(w) != body(first) {
			t.Fatalf("stranger %d answered %d %q, the first %d %q: the answer depends on the key",
				i, w.Code, w.Body, first.Code, first.Body)
		}
	}
	// A refusal: 400 for a request with no date, as for a known key since
	// go-filesystems/s3 v0.3.0, which no longer answers an unknown key first.
	if first.Code < 400 || first.Code >= 500 {
		t.Errorf("an unsigned request from a stranger answered %d", first.Code)
	}
	if n := len(h.byUser); n != 0 {
		t.Fatalf("1000 unknown access keys left %d servers cached", n)
	}
	// Known people are cached -- the control that the cache is used at all --
	// and the limit holds.
	for _, who := range []string{"alice", "bob", "alice"} {
		if w := ask(who); w.Code < 400 {
			t.Errorf("%s, unsigned, answered %d", who, w.Code)
		}
		if n := len(h.byUser); n != 1 {
			t.Fatalf("after %s: %d servers cached, limit 1", who, n)
		}
	}
}
