// SPDX-License-Identifier: BSD-3-Clause

//go:build !nowebdav

package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// The root is the collection of the shares a person may open, to a WebDAV
// client as to a browser: a file manager mounting the server, or the
// go-fileshare explorer listing it, asks with PROPFIND and once got the
// browser's page with a 200 -- nothing it could read.
func TestWebDAVRootListsTheShares(t *testing.T) {
	dir := t.TempDir()
	shares := fmt.Sprintf(`
share "mine" {
  directory = %q
  allow     = ["alice"]
}
share "a b" {
  directory = %q
}
share "bobs" {
  directory = %q
  allow     = ["bob"]
}`, hclPath(t.TempDir()), hclPath(t.TempDir()), hclPath(t.TempDir()))
	r := start(t, onlyProtocol(t, dir, "webdav", shares))
	ask := func(user, method, depth, body string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(method, "http://"+r.addrs["webdav"]+"/", strings.NewReader(body))
		if user != "" {
			req.SetBasicAuth(user, map[string]string{"alice": "hunter2", "bob": "swordfish"}[user])
		}
		if depth != "" {
			req.Header.Set("Depth", depth)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return res, string(b)
	}
	type propstat struct {
		Status string `xml:"status"`
		Prop   struct {
			Inner string `xml:",innerxml"`
			Coll  *struct {
				C *struct{} `xml:"collection"`
			} `xml:"resourcetype"`
			Name string `xml:"displayname"`
		} `xml:"prop"`
	}
	type ms struct {
		R []struct {
			Href string     `xml:"href"`
			PS   []propstat `xml:"propstat"`
		} `xml:"response"`
	}
	parse := func(body string) ms {
		t.Helper()
		var m ms
		if err := xml.Unmarshal([]byte(body), &m); err != nil {
			t.Fatalf("not XML: %v\n%s", err, body)
		}
		return m
	}
	hrefs := func(m ms) []string {
		var out []string
		for _, x := range m.R {
			out = append(out, x.Href)
		}
		return out
	}

	res, body := ask("alice", "PROPFIND", "1", "")
	if res.StatusCode != http.StatusMultiStatus {
		t.Fatalf("PROPFIND Depth 1: %d %s", res.StatusCode, body)
	}
	m := parse(body)
	if got := hrefs(m); !slices.Equal(got, []string{"/", "/mine/", "/a%20b/"}) {
		t.Fatalf("alice sees %v", got)
	}
	for _, x := range m.R {
		if len(x.PS) != 1 || !strings.Contains(x.PS[0].Status, " 200 ") || x.PS[0].Prop.Coll == nil || x.PS[0].Prop.Coll.C == nil {
			t.Errorf("%s is not listed as a collection: %+v", x.Href, x.PS)
		}
	}
	if m.R[2].PS[0].Prop.Name != "a b" {
		t.Errorf("displayname %q", m.R[2].PS[0].Prop.Name)
	}
	// bob sees his own, not alice's.
	if _, body := ask("bob", "PROPFIND", "1", ""); !slices.Equal(hrefs(parse(body)), []string{"/", "/a%20b/", "/bobs/"}) {
		t.Errorf("bob sees %v", hrefs(parse(body)))
	}
	// Depth 0: the root alone.
	if _, body := ask("alice", "PROPFIND", "0", ""); !slices.Equal(hrefs(parse(body)), []string{"/"}) {
		t.Errorf("Depth 0: %v", hrefs(parse(body)))
	}
	// Infinity, and no Depth (which means it), refused as RFC 4918 allows.
	for _, d := range []string{"infinity", ""} {
		if res, body := ask("alice", "PROPFIND", d, ""); res.StatusCode != http.StatusForbidden || !strings.Contains(body, "propfind-finite-depth") {
			t.Errorf("Depth %q: %d %s", d, res.StatusCode, body)
		}
	}
	// Named properties: the known ones 200, the others 404 -- in a body that
	// is still XML with a property in no namespace among them.
	res, body = ask("alice", "PROPFIND", "0", `<?xml version="1.0"?><D:propfind xmlns:D="DAV:" xmlns:A="http://apple.com/ns"><D:prop>
<D:resourcetype/><D:getcontentlength/><A:quota/><plain xmlns=""/></D:prop></D:propfind>`)
	m = parse(body)
	if res.StatusCode != http.StatusMultiStatus || len(m.R) != 1 || len(m.R[0].PS) != 2 {
		t.Fatalf("named: %d %s", res.StatusCode, body)
	}
	ok, missing := m.R[0].PS[0], m.R[0].PS[1]
	if !strings.Contains(ok.Status, " 200 ") || ok.Prop.Coll == nil || ok.Prop.Name != "" {
		t.Errorf("found: %+v", ok)
	}
	for _, want := range []string{"getcontentlength", "quota", "<plain/>"} {
		if !strings.Contains(missing.Status, " 404 ") || !strings.Contains(missing.Prop.Inner, want) {
			t.Errorf("missing %s: %+v", want, missing)
		}
	}
	if _, body := ask("alice", "PROPFIND", "0", `<D:propfind xmlns:D="DAV:"><D:propname/></D:propfind>`); !strings.Contains(body, "<D:displayname/>") {
		t.Errorf("propname: %s", body)
	}
	if res, _ := ask("alice", "PROPFIND", "1", "<not xml"); res.StatusCode != http.StatusBadRequest {
		t.Errorf("a broken body: %d", res.StatusCode)
	}
	// OPTIONS says it is WebDAV; nothing is written at the root.
	if res, _ := ask("alice", http.MethodOptions, "", ""); res.Header.Get("DAV") != "1" || !strings.Contains(res.Header.Get("Allow"), "PROPFIND") {
		t.Errorf("OPTIONS: %d %v", res.StatusCode, res.Header)
	}
	for _, method := range []string{http.MethodPut, "MKCOL", http.MethodDelete, "MOVE"} {
		if res, _ := ask("alice", method, "", "x"); res.StatusCode != http.StatusMethodNotAllowed || res.Header.Get("Allow") == "" {
			t.Errorf("%s /: %d", method, res.StatusCode)
		}
	}
	// Anonymous: the challenge, before anything is listed.
	if res, body := ask("", "PROPFIND", "1", ""); res.StatusCode != http.StatusUnauthorized || strings.Contains(body, "mine") {
		t.Errorf("anonymous: %d %s", res.StatusCode, body)
	}
	// CONTROL: a browser still gets the page.
	if res, body := ask("alice", http.MethodGet, "", ""); res.StatusCode != http.StatusOK || !strings.Contains(body, `<a href="/mine/">`) || strings.Contains(body, "bobs") {
		t.Errorf("GET: %d %s", res.StatusCode, body)
	}
}
