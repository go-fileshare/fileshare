package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func execute(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestHelpSaysWhatItIsFor(t *testing.T) {
	out, err := execute(t, "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--config", "check", "serve", "AUTH_UNIX", "NOT exported over NFS"} {
		if !strings.Contains(out, want) {
			t.Errorf("the help does not mention %q", want)
		}
	}
}

func TestTheDashesAreExplained(t *testing.T) {
	_, err := execute(t, "-config", "/etc/fileshare.d")
	if err == nil || !strings.Contains(err.Error(), "two dashes") {
		t.Errorf("-config gave %v", err)
	}
	_, err = execute(t, "chekc")
	if err == nil || !strings.Contains(err.Error(), "check") {
		t.Errorf("a typo was not answered with the command meant: %v", err)
	}
	_, err = execute(t)
	if err == nil || !strings.Contains(err.Error(), "nothing to serve") {
		t.Errorf("no arguments gave %v", err)
	}
}

// check prints the matrix: every share against every protocol.
func TestCheckPrintsTheWholeMatrix(t *testing.T) {
	dir := t.TempDir()
	img := image(t, dir, "photos.img", map[string]string{"/a.txt": "a"})
	open := image(t, dir, "open.img", map[string]string{"/b.txt": "b"})
	body := configFor(t, dir, fmt.Sprintf(`
share "photos" {
  image   = %q
  allow   = ["alice", "bob"]
  writers = ["alice"]
}

share "open" {
  image = %q
}`, hclPath(img), hclPath(open)))
	path := write(t, dir, "c.hcl", body)

	out, err := execute(t, "check", path)
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	for _, want := range []string{
		"SMB", "WEBDAV", "NFS",
		"fat32",
		"alice and bob", // who may connect to photos
		"alice",         // who may write it
		"NO",            // photos over nfs
		"photos is not served over nfs",
		"AUTH_UNIX",
		"this configuration can be served",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("check did not say %q:\n%s", want, out)
		}
	}
	// Never the password, only where it comes from.
	if strings.Contains(out, "hunter2") {
		t.Error("check printed a password")
	}
	if !strings.Contains(out, "alice.pw") {
		t.Error("check did not say where the password comes from")
	}
}

// An image no driver owns is a refusal, not a server that starts and fails
// later.
func TestCheckRefusesAnImageNobodyCanOpen(t *testing.T) {
	dir := t.TempDir()
	junk := write(t, dir, "junk.img", strings.Repeat("x", 4096))
	path := write(t, dir, "c.hcl", fmt.Sprintf(`
share "junk" { image = %q }
serve "smb" { addr = "127.0.0.1:0" }
`, hclPath(junk)))
	if _, err := execute(t, "check", path); err == nil {
		t.Error("check accepted an image no driver can open")
	}
}

func TestVersionIsThere(t *testing.T) {
	out, err := execute(t, "--version")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "fileshare version") {
		t.Errorf("--version printed %q", out)
	}
}

func TestAListReadsAsASentence(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"alice"}, "alice"},
		{[]string{"alice", "bob"}, "alice and bob"},
		{[]string{"alice", "bob", "carol"}, "alice, bob and carol"},
	} {
		if got := list(tc.in); got != tc.want {
			t.Errorf("list(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
