// SPDX-License-Identifier: BSD-3-Clause

//go:build !nogrpc && !nowebdav

package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/grpc-transports/control"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	adminv1 "github.com/go-fileshare/fileshare/proto/fileshare/admin/v1"
)

// managed is a server started the way `fileshare serve` starts one -- through
// run, so every change goes through a real generation swap -- with the admin
// API and the metrics endpoints on unix sockets.
type managed struct {
	srv     *server
	cfg     *config
	webdav  string
	client  adminv1.AdminServiceClient
	health  healthpb.HealthClient
	metrics *http.Client
	state   string
	roots   string
	out     *safeBuffer
	stop    func()
}

// socketDir is short on purpose: a unix socket path is limited to about a
// hundred bytes, and a test's TempDir on macOS is most of that already.
func socketDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "fsadm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// managedConfig writes and loads the configuration startManaged runs,
// without the state file applied: what withState makes of it is the
// caller's to see.
func managedConfig(t *testing.T, dir, extra string) (cfg *config, sock, state, roots string) {
	t.Helper()
	sock = socketDir(t)
	roots = filepath.Join(dir, "roots")
	if err := os.MkdirAll(roots, 0o755); err != nil {
		t.Fatal(err)
	}
	state = filepath.Join(dir, "shares.json")
	body := fmt.Sprintf(`name = "TESTFS"
%s
%s
serve "webdav" { addr = "127.0.0.1:0" }
admin {
  listen       = "unix://%s/admin.sock"
  state_file   = %q
  source_roots = [%q]
}
metrics { listen = "unix://%s/metrics.sock" }
`, people(t, dir)+"group \"staff\" { members = [\"bob\"] }\n", extra, sock, hclPath(state), hclPath(roots), sock)
	path := write(t, dir, "test.hcl", body)
	cfg, err := loadConfig([]string{path})
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	return cfg, sock, state, roots
}

func startManaged(t *testing.T, dir, extra string) *managed {
	t.Helper()
	if runtime.GOOS == "windows" {
		// The admin API is on a unix socket here, named by a unix path. Its
		// other listener, TCP with mutual TLS, is tested on Windows where it
		// lives: grpc-transports/control.
		t.Skip("the admin tests use unix socket paths")
	}
	cfg, sock, state, roots := managedConfig(t, dir, extra)
	if err := withState(cfg); err != nil {
		t.Fatalf("state: %v", err)
	}
	out := &safeBuffer{}
	srv, err := open(cfg, out)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.run(ctx, cfg) }()
	m := &managed{srv: srv, cfg: cfg, state: state, roots: roots, out: out}
	m.stop = func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("run: %v", err)
		}
		srv.Close()
	}
	t.Cleanup(func() {
		if m.stop != nil {
			m.stop()
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for srv.mgr.Load() == nil || !srv.ready.Load() {
		if time.Now().After(deadline) {
			t.Fatalf("the server never became ready:\n%s", out)
		}
		time.Sleep(10 * time.Millisecond)
	}
	srv.runMu.Lock()
	m.webdav = srv.feeds[0].ln.Addr().String()
	srv.runMu.Unlock()
	conn, err := control.Dial(control.ClientConfig{Target: "unix://" + sock + "/admin.sock"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	m.client = adminv1.NewAdminServiceClient(conn)
	m.health = healthpb.NewHealthClient(conn)
	m.metrics = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock+"/metrics.sock")
		}}}
	return m
}

func (m *managed) get(user, password, path string) (int, string) {
	req, _ := http.NewRequest(http.MethodGet, "http://"+m.webdav+path, nil)
	req.SetBasicAuth(user, password)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func (m *managed) put(user, password, path, body string) int {
	req, _ := http.NewRequest(http.MethodPut, "http://"+m.webdav+path, strings.NewReader(body))
	req.SetBasicAuth(user, password)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0
	}
	res.Body.Close()
	return res.StatusCode
}

func (m *managed) scrape(t *testing.T, path string) (int, string) {
	t.Helper()
	res, err := m.metrics.Get("http://metrics" + path)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func userSubject(name string) *adminv1.Subject {
	return &adminv1.Subject{Kind: &adminv1.Subject_User{User: name}}
}

func groupSubject(name string) *adminv1.Subject {
	return &adminv1.Subject{Kind: &adminv1.Subject_Group{Group: name}}
}

func grantOf(s *adminv1.Subject, a adminv1.Access) *adminv1.Grant {
	return &adminv1.Grant{Subject: s, Access: a}
}

func wantCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if got := status.Code(err); got != want {
		t.Fatalf("got %v (%v), want %v", got, err, want)
	}
}

// The whole life of a share the API manages: created from a host directory,
// read, granted write, revoked -- each checked where a client sees it, over
// WebDAV, not by asking the server what it thinks it did.
func TestAdminManagesADirectoryShare(t *testing.T) {
	dir := t.TempDir()
	m := startManaged(t, dir, "")
	ctx := context.Background()
	tree := filepath.Join(m.roots, "photos")
	os.MkdirAll(tree, 0o755)
	write(t, tree, "a.txt", "from the host")

	// Before: nobody can reach it, because it does not exist.
	if code, _ := m.get("alice", "hunter2", "/photos/a.txt"); code != http.StatusNotFound {
		t.Fatalf("before creation: %d", code)
	}
	created, err := m.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: "photos",
		Source: &adminv1.CreateShareRequest_Directory{Directory: tree},
		Grants: []*adminv1.Grant{grantOf(userSubject("alice"), adminv1.Access_ACCESS_READ)}})
	if err != nil {
		t.Fatal(err)
	}
	sh := created.GetShare()
	if !sh.GetEnabled() || created.GetApplied().GetGeneration() != 2 {
		t.Fatalf("applied: %v", created.GetApplied())
	}
	if sh.GetOrigin() != adminv1.Origin_ORIGIN_API || !sh.GetEffectiveReadOnly() || sh.GetFilesystem() != "directory" {
		t.Fatalf("created: %v", sh)
	}
	if code, body := m.get("alice", "hunter2", "/photos/a.txt"); code != http.StatusOK || body != "from the host" {
		t.Fatalf("alice reads: %d %q", code, body)
	}
	// Positive control for everything that follows: bob is somebody who
	// authenticates and was granted nothing.
	if code, _ := m.get("bob", "swordfish", "/photos/a.txt"); code != http.StatusNotFound {
		t.Fatalf("bob, granted nothing, got %d", code)
	}
	if code := m.put("alice", "hunter2", "/photos/b.txt", "x"); code < 400 {
		t.Fatalf("alice wrote with a READ grant: %d", code)
	}

	if _, err := m.client.Grant(ctx, &adminv1.GrantRequest{Share: "photos",
		Grant: grantOf(userSubject("alice"), adminv1.Access_ACCESS_WRITE)}); err != nil {
		t.Fatal(err)
	}
	if code := m.put("alice", "hunter2", "/photos/b.txt", "written"); code >= 300 {
		t.Fatalf("alice, granted write, got %d", code)
	}
	if b, err := os.ReadFile(filepath.Join(tree, "b.txt")); err != nil || string(b) != "written" {
		t.Fatalf("on the host: %q %v", b, err)
	}

	// The last grant cannot be revoked: the share would be open to anyone.
	_, err = m.client.Revoke(ctx, &adminv1.RevokeRequest{Share: "photos", Subject: userSubject("alice")})
	wantCode(t, err, codes.FailedPrecondition)
	if code, _ := m.get("alice", "hunter2", "/photos/a.txt"); code != http.StatusOK {
		t.Fatalf("a refused revoke changed something: %d", code)
	}

	if _, err := m.client.Grant(ctx, &adminv1.GrantRequest{Share: "photos",
		Grant: grantOf(groupSubject("staff"), adminv1.Access_ACCESS_READ)}); err != nil {
		t.Fatal(err)
	}
	if code, _ := m.get("bob", "swordfish", "/photos/a.txt"); code != http.StatusOK {
		t.Fatalf("bob, in @staff, got %d", code)
	}
	if _, err := m.client.Revoke(ctx, &adminv1.RevokeRequest{Share: "photos", Subject: userSubject("alice")}); err != nil {
		t.Fatal(err)
	}
	if code, _ := m.get("alice", "hunter2", "/photos/a.txt"); code != http.StatusNotFound {
		t.Fatalf("alice, revoked, got %d", code)
	}

	// It survives a restart: the state file is what the next start reads.
	var st stateFile
	data, _ := os.ReadFile(m.state)
	if err := json.Unmarshal(data, &st); err != nil || len(st.Shares) != 1 || len(st.Shares[0].Grants) != 1 {
		t.Fatalf("state file: %s", data)
	}
	if !strings.Contains(m.out.String(), "admin (") {
		t.Fatalf("no audit line:\n%s", m.out)
	}

	if _, err := m.client.DeleteShare(ctx, &adminv1.DeleteShareRequest{Name: "photos"}); err != nil {
		t.Fatal(err)
	}
	if code, _ := m.get("bob", "swordfish", "/photos/a.txt"); code != http.StatusNotFound {
		t.Fatalf("deleted, got %d", code)
	}
	if _, err := os.Stat(filepath.Join(tree, "a.txt")); err != nil {
		t.Fatalf("deleting a share deleted its files: %v", err)
	}
}

// A share created through the API is served again after a restart.
func TestAdminStateSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	m := startManaged(t, dir, "")
	tree := filepath.Join(m.roots, "docs")
	os.MkdirAll(tree, 0o755)
	write(t, tree, "a.txt", "kept")
	if _, err := m.client.CreateShare(context.Background(), &adminv1.CreateShareRequest{Name: "docs",
		Source: &adminv1.CreateShareRequest_Directory{Directory: tree},
		Grants: []*adminv1.Grant{grantOf(userSubject("carol"), adminv1.Access_ACCESS_READ)}}); err != nil {
		t.Fatal(err)
	}
	m.stop()
	m.stop = nil

	again := startManaged(t, dir, "")
	if code, body := again.get("carol", "correct horse", "/docs/a.txt"); code != http.StatusOK || body != "kept" {
		t.Fatalf("after a restart: %d %q", code, body)
	}
}

// ⛔ A revocation reaches a connection that was already open. Without the
// generation swap closing it, a keep-alive WebDAV connection would go on
// serving alice after she was revoked.
func TestARevocationClosesOpenConnections(t *testing.T) {
	dir := t.TempDir()
	m := startManaged(t, dir, "")
	ctx := context.Background()
	tree := filepath.Join(m.roots, "t")
	os.MkdirAll(tree, 0o755)
	write(t, tree, "a.txt", "secret")
	if _, err := m.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: "t",
		Source: &adminv1.CreateShareRequest_Directory{Directory: tree},
		Grants: []*adminv1.Grant{grantOf(userSubject("alice"), adminv1.Access_ACCESS_READ),
			grantOf(userSubject("bob"), adminv1.Access_ACCESS_READ)}}); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", m.webdav)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := bufio.NewReader(c)
	ask := func() (*http.Response, error) {
		auth := base64.StdEncoding.EncodeToString([]byte("alice:hunter2"))
		fmt.Fprintf(c, "GET /t/a.txt HTTP/1.1\r\nHost: x\r\nAuthorization: Basic %s\r\n\r\n", auth)
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		res, err := http.ReadResponse(r, nil)
		if err == nil {
			io.ReadAll(res.Body)
			res.Body.Close()
		}
		return res, err
	}
	// Control: the connection works, and stays open.
	if res, err := ask(); err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("before: %v %v", res, err)
	}
	if _, err := m.client.Revoke(ctx, &adminv1.RevokeRequest{Share: "t", Subject: userSubject("alice")}); err != nil {
		t.Fatal(err)
	}
	if res, err := ask(); err == nil {
		t.Fatalf("the connection opened before the revocation still answers: %d", res.StatusCode)
	}
}

// What the API refuses, each with the call that is allowed beside it.
func TestAdminRefusals(t *testing.T) {
	dir := t.TempDir()
	img := image(t, dir, "cfg.img", map[string]string{"/x.txt": "x"})
	m := startManaged(t, dir, fmt.Sprintf("share \"configured\" {\n  image = %q\n  allow = [\"alice\"]\n}\n", hclPath(img)))
	ctx := context.Background()
	inside := filepath.Join(m.roots, "in")
	os.MkdirAll(inside, 0o755)
	outside := filepath.Join(dir, "out")
	os.MkdirAll(outside, 0o755)
	// A link inside the roots that leads out of them.
	if err := os.Symlink(outside, filepath.Join(m.roots, "escape")); err != nil {
		t.Skip("no symbolic links here:", err)
	}
	alice := []*adminv1.Grant{grantOf(userSubject("alice"), adminv1.Access_ACCESS_READ)}
	create := func(name, dir string, g []*adminv1.Grant) error {
		_, err := m.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: name,
			Source: &adminv1.CreateShareRequest_Directory{Directory: dir}, Grants: g})
		return err
	}

	wantCode(t, create("o", outside, alice), codes.FailedPrecondition)
	wantCode(t, create("o", filepath.Join(m.roots, "escape"), alice), codes.FailedPrecondition)
	wantCode(t, create("o", filepath.Join(m.roots, "in", "..", "..", "out"), alice), codes.FailedPrecondition)
	wantCode(t, create("o", inside, nil), codes.InvalidArgument)
	wantCode(t, create("o", inside, []*adminv1.Grant{grantOf(userSubject("nobody"), adminv1.Access_ACCESS_READ)}), codes.InvalidArgument)
	wantCode(t, create("o", inside, []*adminv1.Grant{grantOf(userSubject("alice"), adminv1.Access_ACCESS_UNSPECIFIED)}), codes.InvalidArgument)
	wantCode(t, create("CONFIGURED", inside, alice), codes.AlreadyExists)
	// The control: the same call, inside the roots, with a real person.
	if err := create("o", inside, alice); err != nil {
		t.Fatalf("the allowed call: %v", err)
	}
	wantCode(t, create("O", inside, alice), codes.AlreadyExists)

	// A share of the configuration is listed, and not changed here.
	got, err := m.client.GetShare(ctx, &adminv1.GetShareRequest{Name: "configured"})
	sh := got.GetShare()
	if err != nil || sh.GetOrigin() != adminv1.Origin_ORIGIN_CONFIG || len(sh.GetGrants()) != 1 {
		t.Fatalf("configured: %v %v", sh, err)
	}
	_, err = m.client.Grant(ctx, &adminv1.GrantRequest{Share: "configured", Grant: grantOf(userSubject("bob"), adminv1.Access_ACCESS_READ)})
	wantCode(t, err, codes.FailedPrecondition)
	_, err = m.client.DeleteShare(ctx, &adminv1.DeleteShareRequest{Name: "configured"})
	wantCode(t, err, codes.FailedPrecondition)
	_, err = m.client.DeleteShare(ctx, &adminv1.DeleteShareRequest{Name: "ghost"})
	wantCode(t, err, codes.NotFound)

	// Read-only and write do not go together, whichever is said first.
	_, err = m.client.UpdateShare(ctx, &adminv1.UpdateShareRequest{Name: "o", ReadOnly: ptr(true)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.client.Grant(ctx, &adminv1.GrantRequest{Share: "o", Grant: grantOf(userSubject("bob"), adminv1.Access_ACCESS_WRITE)})
	wantCode(t, err, codes.FailedPrecondition)

	// After every refusal, what is served is what was: one change applied.
	res, err := m.client.GetServerInfo(ctx, &adminv1.GetServerInfoRequest{})
	info := res.GetInfo()
	if err != nil || info.GetGeneration() != 3 {
		t.Fatalf("generation %d (%v): the refusals were served", info.GetGeneration(), err)
	}
}

func ptr[T any](v T) *T { return &v }

// The endpoints a supervisor reads, and what they must not say.
func TestHealthAndMetrics(t *testing.T) {
	dir := t.TempDir()
	m := startManaged(t, dir, "")
	ctx := context.Background()

	if code, body := m.scrape(t, "/healthz"); code != http.StatusOK {
		t.Fatalf("/healthz: %d %s", code, body)
	}
	if code, body := m.scrape(t, "/readyz"); code != http.StatusOK {
		t.Fatalf("/readyz: %d %s", code, body)
	}
	res, err := m.health.Check(ctx, &healthpb.HealthCheckRequest{Service: "fileshare.admin.v1.AdminService"})
	if err != nil || res.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("grpc health: %v %v", res, err)
	}

	tree := filepath.Join(m.roots, "confidential-project")
	os.MkdirAll(tree, 0o755)
	if _, err := m.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: "confidential-project",
		Source: &adminv1.CreateShareRequest_Directory{Directory: tree},
		Grants: []*adminv1.Grant{grantOf(userSubject("alice"), adminv1.Access_ACCESS_READ)}}); err != nil {
		t.Fatal(err)
	}
	m.get("alice", "hunter2", "/")
	_, body := m.scrape(t, "/metrics")
	for _, want := range []string{
		"fileshare_generation 2",
		`fileshare_shares{origin="api"} 1`,
		`fileshare_admin_changes_total{result="applied"} 1`,
		`fileshare_connections_accepted_total{protocol="webdav"}`,
		`fileshare_admin_requests_total{method="CreateShare",code="OK"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics has no %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "confidential") || strings.Contains(body, "alice") {
		t.Errorf("/metrics names a share or a person:\n%s", body)
	}

	// Not ready while not serving: asked of the flag a swap and a stop clear.
	m.srv.ready.Store(false)
	if code, body := m.scrape(t, "/readyz"); code != http.StatusServiceUnavailable || !strings.Contains(body, "not serving") {
		t.Fatalf("/readyz while not serving: %d %q", code, body)
	}
	m.srv.ready.Store(true)
}

// ⛔ A share whose image did not change keeps its DRIVER across a change: the
// same one, never a second opened over the same bytes while the first may
// still be writing. And a change the server cannot honour leaves what was
// served, and what was written, exactly as they were.
func TestAChangeKeepsUnchangedDriversAndARefusalChangesNothing(t *testing.T) {
	dir := t.TempDir()
	img := image(t, dir, "cfg.img", map[string]string{"/x.txt": "in the image"})
	m := startManaged(t, dir, fmt.Sprintf("share \"configured\" {\n  image = %q\n  allow = [\"alice\"]\n}\n", hclPath(img)))
	ctx := context.Background()
	before := m.srv.shareByName("configured").fsys

	tree := filepath.Join(m.roots, "t")
	os.MkdirAll(tree, 0o755)
	if _, err := m.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: "t",
		Source: &adminv1.CreateShareRequest_Directory{Directory: tree},
		Grants: []*adminv1.Grant{grantOf(userSubject("alice"), adminv1.Access_ACCESS_READ)}}); err != nil {
		t.Fatal(err)
	}
	if after := m.srv.shareByName("configured").fsys; after != before {
		t.Fatal("the configured image was opened a second time by a change that did not touch it")
	}
	if code, body := m.get("alice", "hunter2", "/configured/x.txt"); code != http.StatusOK || body != "in the image" {
		t.Fatalf("the carried-over driver after the swap: %d %q", code, body)
	}

	stateBefore, _ := os.ReadFile(m.state)
	generation := m.srv.generationNumber()
	// Inside the roots, and not an image of anything this server can open.
	junk := write(t, m.roots, "junk.img", "not a filesystem")
	_, err := m.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: "junk",
		Source: &adminv1.CreateShareRequest_Image{Image: junk},
		Grants: []*adminv1.Grant{grantOf(userSubject("alice"), adminv1.Access_ACCESS_READ)}})
	wantCode(t, err, codes.FailedPrecondition)
	if got, _ := os.ReadFile(m.state); string(got) != string(stateBefore) {
		t.Fatalf("a refused change was written down:\n%s", got)
	}
	if m.srv.generationNumber() != generation {
		t.Fatal("a refused change was served")
	}
	if code, _ := m.get("alice", "hunter2", "/t/"); code >= 400 {
		t.Fatalf("after a refusal, the API share: %d", code)
	}
	if code, body := m.get("alice", "hunter2", "/configured/x.txt"); code != http.StatusOK || body != "in the image" {
		t.Fatalf("after a refusal, the configured share: %d %q", code, body)
	}
	if !strings.Contains(m.out.String(), "admin (") || strings.Contains(m.out.String(), "junk from") {
		t.Fatalf("audit:\n%s", m.out)
	}
}

// What the listing calls say, and the subjects only an identity provider can
// answer for, which a server without one refuses.
func TestAdminListings(t *testing.T) {
	dir := t.TempDir()
	m := startManaged(t, dir, "")
	ctx := context.Background()

	res, err := m.client.GetServerInfo(ctx, &adminv1.GetServerInfoRequest{})
	info := res.GetInfo()
	if err != nil || info.GetName() != "TESTFS" || len(info.GetListeners()) != 1 ||
		info.GetListeners()[0].GetProtocol() != "webdav" || info.GetGeneration() != 1 {
		t.Fatalf("server info: %v %v", info, err)
	}
	users, err := m.client.ListUsers(ctx, &adminv1.ListUsersRequest{})
	if err != nil || len(users.GetUsers()) != 3 || users.GetUsers()[0].GetName() != "alice" ||
		!slices.Contains(users.GetUsers()[0].GetCanUse(), "webdav") {
		t.Fatalf("users: %v %v", users, err)
	}
	groups, err := m.client.ListGroups(ctx, &adminv1.ListGroupsRequest{})
	if err != nil || len(groups.GetGroups()) != 1 || groups.GetGroups()[0].GetName() != "staff" ||
		!slices.Equal(groups.GetGroups()[0].GetMembers(), []string{"bob"}) {
		t.Fatalf("groups: %v %v", groups, err)
	}

	tree := filepath.Join(m.roots, "t")
	os.MkdirAll(tree, 0o755)
	create := func(s *adminv1.Subject) error {
		_, err := m.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: "t",
			Source: &adminv1.CreateShareRequest_Directory{Directory: tree},
			Grants: []*adminv1.Grant{grantOf(s, adminv1.Access_ACCESS_READ)}})
		return err
	}
	for _, s := range []*adminv1.Subject{
		{Kind: &adminv1.Subject_OidcGroup{OidcGroup: "urn:x:photos"}},
		{Kind: &adminv1.Subject_OidcUser{OidcUser: "dora"}},
	} {
		// Well-formed, and refused: no identity provider here could say
		// who that is.
		wantCode(t, create(s), codes.InvalidArgument)
	}
	for _, s := range []*adminv1.Subject{
		{},
		{Kind: &adminv1.Subject_User{User: "@staff"}},
		{Kind: &adminv1.Subject_User{User: "oidc:user:x"}},
		{Kind: &adminv1.Subject_Group{Group: "@staff"}},
		{Kind: &adminv1.Subject_OidcGroup{}},
		{Kind: &adminv1.Subject_OidcUser{}},
	} {
		wantCode(t, create(s), codes.InvalidArgument)
	}
	if err := create(groupSubject("staff")); err != nil {
		t.Fatalf("the control: %v", err)
	}
	list, err := m.client.ListShares(ctx, &adminv1.ListSharesRequest{})
	if err != nil || len(list.GetShares()) != 1 {
		t.Fatalf("list: %v %v", list, err)
	}
	sh := list.GetShares()[0]
	if sh.GetDirectory() != tree && sh.GetDirectory() != mustEval(t, tree) {
		t.Fatalf("source: %v", sh.GetSource())
	}
	if sh.GetGrants()[0].GetSubject().GetGroup() != "staff" || !slices.Equal(sh.GetServedOver(), []string{"webdav"}) {
		t.Fatalf("share: %v", sh)
	}
	if _, err := m.client.GetShare(ctx, &adminv1.GetShareRequest{Name: "T"}); err != nil {
		t.Fatalf("names compare without case, as SMB's do: %v", err)
	}
	_, err = m.client.GetShare(ctx, &adminv1.GetShareRequest{Name: "ghost"})
	wantCode(t, err, codes.NotFound)
	_, err = m.client.UpdateShare(ctx, &adminv1.UpdateShareRequest{Name: "t"})
	wantCode(t, err, codes.InvalidArgument)
	if _, err := m.client.UpdateShare(ctx, &adminv1.UpdateShareRequest{Name: "t",
		Protocols: &adminv1.ProtocolList{Names: []string{"webdav"}}}); err != nil {
		t.Fatal(err)
	}
	_, err = m.client.UpdateShare(ctx, &adminv1.UpdateShareRequest{Name: "t",
		Protocols: &adminv1.ProtocolList{Names: []string{"gopher"}}})
	wantCode(t, err, codes.InvalidArgument)
}

func mustEval(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// DisableShare takes a share offline -- one the API created, or one of the
// configuration -- and EnableShare brings it back; each checked where a client
// sees it.
func TestDisableAndEnableAShare(t *testing.T) {
	dir := t.TempDir()
	img := image(t, dir, "cfg.img", map[string]string{"/x.txt": "first image"})
	extra := fmt.Sprintf("share \"configured\" {\n  image = %q\n  allow = [\"alice\"]\n}\n", hclPath(img))
	m := startManaged(t, dir, extra)
	ctx := context.Background()
	tree := filepath.Join(m.roots, "t")
	os.MkdirAll(tree, 0o755)
	write(t, tree, "a.txt", "in the tree")
	if _, err := m.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: "t",
		Source: &adminv1.CreateShareRequest_Directory{Directory: tree},
		Grants: []*adminv1.Grant{grantOf(userSubject("alice"), adminv1.Access_ACCESS_READ)}}); err != nil {
		t.Fatal(err)
	}

	// A connection open before the share is taken offline.
	c, err := net.Dial("tcp", m.webdav)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	auth := base64.StdEncoding.EncodeToString([]byte("alice:hunter2"))
	fmt.Fprintf(c, "GET /t/a.txt HTTP/1.1\r\nHost: x\r\nAuthorization: Basic %s\r\n\r\n", auth)
	r := bufio.NewReader(c)
	if res, err := http.ReadResponse(r, nil); err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("control: %v %v", res, err)
	} else {
		io.ReadAll(res.Body)
	}

	off, err := m.client.DisableShare(ctx, &adminv1.DisableShareRequest{Name: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if off.GetShare().GetEnabled() || len(off.GetShare().GetServedOver()) != 0 || off.GetApplied().GetConnectionsClosed() < 1 {
		t.Fatalf("disabled: %v %v", off.GetShare(), off.GetApplied())
	}
	fmt.Fprintf(c, "GET /t/a.txt HTTP/1.1\r\nHost: x\r\nAuthorization: Basic %s\r\n\r\n", auth)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := http.ReadResponse(r, nil); err == nil {
		t.Fatal("a connection opened before DisableShare still answers")
	}
	if code, _ := m.get("alice", "hunter2", "/t/a.txt"); code != http.StatusNotFound {
		t.Fatalf("a disabled share answered %d", code)
	}
	_, err = m.client.DisableShare(ctx, &adminv1.DisableShareRequest{Name: "t"})
	wantCode(t, err, codes.FailedPrecondition)
	_, err = m.client.EnableShare(ctx, &adminv1.EnableShareRequest{Name: "ghost"})
	wantCode(t, err, codes.NotFound)

	// A share of the configuration can be taken offline too, and its image
	// is LET GO OF -- its driver and file closed, which is asked of the share
	// itself, since a reopen alone would serve a replaced file even if the
	// old descriptor leaked -- and, replaced while it is offline, the new one
	// is what comes back.
	was := m.srv.shareByName("configured")
	if _, err := m.client.DisableShare(ctx, &adminv1.DisableShareRequest{Name: "configured"}); err != nil {
		t.Fatal(err)
	}
	m.srv.runMu.Lock() // the swap released it under this lock
	leaked := was.closers != nil
	m.srv.runMu.Unlock()
	if leaked {
		t.Fatal("the image of a disabled share is still open")
	}
	if code, _ := m.get("alice", "hunter2", "/configured/x.txt"); code != http.StatusNotFound {
		t.Fatalf("a disabled configured share answered %d", code)
	}
	os.Remove(img)
	image(t, dir, "cfg.img", map[string]string{"/x.txt": "second image"})

	list, err := m.client.ListShares(ctx, &adminv1.ListSharesRequest{})
	if err != nil || len(list.GetShares()) != 2 {
		t.Fatalf("list: %v %v", list, err)
	}
	for _, sh := range list.GetShares() {
		if sh.GetEnabled() {
			t.Fatalf("listed as enabled: %v", sh)
		}
	}
	_, body := m.scrape(t, "/metrics")
	if !strings.Contains(body, "fileshare_shares_disabled 2") ||
		!strings.Contains(body, `fileshare_shares{origin="api"} 0`) ||
		!strings.Contains(body, `fileshare_shares{origin="config"} 0`) {
		t.Fatalf("metrics:\n%s", body)
	}

	// It survives a restart, and `check` says so.
	m.stop()
	m.stop = nil
	cfgPath := filepath.Join(dir, "test.hcl")
	cfg, err := loadConfig([]string{cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := withState(cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Shares) != 0 || len(cfg.offline) != 2 {
		t.Fatalf("after a restart: served %v, offline %v", cfg.Shares, cfg.offline)
	}
	m = startManaged(t, dir, extra)
	if code, _ := m.get("alice", "hunter2", "/t/a.txt"); code != http.StatusNotFound {
		t.Fatalf("a restart brought a disabled share back: %d", code)
	}

	on, err := m.client.EnableShare(ctx, &adminv1.EnableShareRequest{Name: "configured"})
	if err != nil || !on.GetShare().GetEnabled() {
		t.Fatalf("enable: %v %v", on, err)
	}
	if code, body := m.get("alice", "hunter2", "/configured/x.txt"); code != http.StatusOK || body != "second image" {
		t.Fatalf("after EnableShare: %d %q", code, body)
	}

	// Enabling a share whose source is gone is refused, and changes nothing.
	os.RemoveAll(tree)
	stateBefore, _ := os.ReadFile(m.state)
	_, err = m.client.EnableShare(ctx, &adminv1.EnableShareRequest{Name: "t"})
	wantCode(t, err, codes.FailedPrecondition)
	if got, _ := os.ReadFile(m.state); string(got) != string(stateBefore) {
		t.Fatal("a refused EnableShare was written down")
	}
	if code, _ := m.get("alice", "hunter2", "/configured/x.txt"); code != http.StatusOK {
		t.Fatalf("a refused EnableShare disturbed another share: %d", code)
	}

	// Created disabled: defined, listed, not served. Deleted: forgotten.
	os.MkdirAll(tree, 0o755)
	created, err := m.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: "later",
		Source: &adminv1.CreateShareRequest_Directory{Directory: tree}, Disabled: true,
		Grants: []*adminv1.Grant{grantOf(userSubject("alice"), adminv1.Access_ACCESS_READ)}})
	if err != nil || created.GetShare().GetEnabled() {
		t.Fatalf("created disabled: %v %v", created, err)
	}
	if code, _ := m.get("alice", "hunter2", "/later/"); code != http.StatusNotFound {
		t.Fatalf("a share created disabled answered %d", code)
	}
	for _, n := range []string{"later", "t"} {
		if _, err := m.client.DeleteShare(ctx, &adminv1.DeleteShareRequest{Name: n}); err != nil {
			t.Fatal(err)
		}
	}
	var st stateFile
	data, _ := os.ReadFile(m.state)
	json.Unmarshal(data, &st)
	if len(st.Shares) != 0 || len(st.Disabled) != 0 {
		t.Fatalf("state after deleting: %s", data)
	}
}

// ReloadDirectory over the API: an unchanged directory is not an error, and
// says it changed nothing.
func TestAdminReloadDirectory(t *testing.T) {
	m := startManaged(t, t.TempDir(), "")
	res, err := m.client.ReloadDirectory(context.Background(), &adminv1.ReloadDirectoryRequest{})
	if err != nil || res.GetNewGeneration() || len(res.GetAdded())+len(res.GetRemoved())+len(res.GetChanged()) != 0 ||
		res.GetApplied().GetGeneration() != 1 {
		t.Fatalf("an unchanged directory: %v %v", res, err)
	}
	_, body := m.scrape(t, "/metrics")
	if !strings.Contains(body, `fileshare_directory_reloads_total{result="unchanged"} 1`) ||
		!strings.Contains(body, "fileshare_directory_people 3") {
		t.Fatalf("metrics:\n%s", body)
	}
}
