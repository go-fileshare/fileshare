// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-authn/directory"
)

// ⛔ THE CASE THAT IS FILESHARE'S AND NOT authnd's. A user block here may carry
// a password AND an nt_hash -- authnd refuses that pairing, fileshare allows
// it. A password change that left the hash alone would have WebDAV, SFTP and
// S3 take the new password while SMB went on accepting the old one, because
// NTLMv2 works from the hash and nothing else. Nothing would report it.
func TestChangingAPasswordKeepsTheNTHashInStep(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "c.hcl", `
user "alice" {
  password = "hunter2"
  nt_hash  = "`+ntHex("hunter2")+`"
}

share "photos" {
  image = "`+filepath.ToSlash(image(t, dir, "photos.img", map[string]string{"/a.txt": "hello"}))+`"
  allow = ["alice"]
}
`)
	pw := filepath.Join(dir, "new.pw")
	if err := os.WriteFile(pw, []byte("correct horse\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := execute(t, "passwd", "alice", path, "-p", pw); err != nil {
		t.Fatalf("passwd: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `password = "correct horse"`) {
		t.Errorf("the password did not change:\n%s", got)
	}
	if !strings.Contains(string(got), ntHex("correct horse")) {
		t.Errorf("the nt_hash was not recomputed, so SMB would keep the old password:\n%s", got)
	}
	if strings.Contains(string(got), ntHex("hunter2")) {
		t.Errorf("the OLD nt_hash is still there:\n%s", got)
	}
}

func TestPasswdReadsTheNewPasswordFromStandardInput(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "c.hcl", `
user "alice" { password = "hunter2" }

share "photos" {
  image = "`+filepath.ToSlash(image(t, dir, "photos.img", map[string]string{"/a.txt": "hello"}))+`"
  allow = ["alice"]
}
`)
	out, err := executeStdin(t, "correct horse\n", "passwd", "alice", path, "-p", "-")
	if err != nil {
		t.Fatalf("passwd: %v\n%s", err, out)
	}
	got, _ := os.ReadFile(path)
	if !strings.Contains(string(got), `password = "correct horse"`) {
		t.Errorf("the password did not change:\n%s", got)
	}
	// ⛔ A running server read the configuration once. Saying "done" without
	// saying that would leave somebody wondering why the new password is
	// refused by the server they are looking at.
	if !strings.Contains(out, "until it is restarted") {
		t.Errorf("the answer does not say a running server still holds the old one:\n%s", out)
	}
}

func TestWhatPasswdRefuses(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "c.hcl", `
user "alice" { password = "hunter2" }

share "photos" {
  image = "`+filepath.ToSlash(image(t, dir, "photos.img", map[string]string{"/a.txt": "hello"}))+`"
  allow = ["alice"]
}
`)
	empty := filepath.Join(dir, "empty.pw")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pw := filepath.Join(dir, "new.pw")
	if err := os.WriteFile(pw, []byte("correct horse\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no password file at all", []string{"passwd", "alice", path}, "comes from a file"},
		{"an empty password", []string{"passwd", "alice", path, "-p", empty},
			"would let anybody in"},
		{"a password file that is not there",
			[]string{"passwd", "alice", path, "-p", filepath.Join(dir, "gone")},
			"reading the new password"},
		{"somebody served from somewhere else",
			[]string{"passwd", "carol", path, "-p", pw}, "changed where they live"},
	} {
		if _, err := execute(t, tc.args...); err == nil ||
			!strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

// ⛔ A password may legitimately end in spaces. Trimming them would let
// somebody set one they can never type back, and the failure would look like
// a wrong password rather than like a trim.
func TestOnlyTheTrailingNewlineIsRemoved(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct{ raw, want string }{
		{"correct horse\n", "correct horse"},
		{"correct horse\r\n", "correct horse"},
		{"correct horse", "correct horse"},
		{"two spaces  \n", "two spaces  "},
	} {
		path := filepath.Join(dir, "p")
		if err := os.WriteFile(path, []byte(tc.raw), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := readPassword(nil, path)
		if err != nil || got != tc.want {
			t.Errorf("%q -> %q, wanted %q (%v)", tc.raw, got, tc.want, err)
		}
	}
}

func ntHex(password string) string {
	return fmt.Sprintf("%x", directory.NTHashOf(password))
}

// executeStdin runs the command with something on standard input.
func executeStdin(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}
