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
	needUsers(t)
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
	want := []string{
		"fat32",
		"alice and bob", // who may connect to photos
		"alice",         // who may write it
		"this configuration can be served",
	}
	// One column per protocol THIS BINARY has, and the refusal only from one
	// that cannot authenticate.
	for _, p := range protocols {
		want = append(want, strings.ToUpper(p.name))
		if !p.authenticates {
			want = append(want, "NO", "photos is not served over "+p.name, "AUTH_UNIX")
		}
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("check did not say %q:\n%s", w, out)
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
	path := write(t, dir, "c.hcl", fmt.Sprintf("share \"junk\" { image = %q }\n%s", hclPath(junk), serveBlocks()))
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

// The flag form: one image, one user, no configuration file. It is what the
// command this product replaced was for, so it has to be here.
func TestTheOneImageForm(t *testing.T) {
	needUsers(t)
	dir := t.TempDir()
	img := image(t, dir, "holiday.img", map[string]string{"/a.txt": "a"})
	pw := write(t, dir, "pw", "hunter2\n")

	out, err := execute(t, "check", "--image", img, "--user", "alice", "--password-file", pw)
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	// The share is named after the image, and every protocol this binary has
	// is in the table.
	if !strings.Contains(out, "holiday") {
		t.Errorf("the share was not named after the image:\n%s", out)
	}
	for _, p := range protocols {
		if !strings.Contains(out, strings.ToUpper(p.name)) {
			t.Errorf("the flag form left out %s:\n%s", p.name, out)
		}
	}
	if strings.Contains(out, "hunter2") {
		t.Error("check printed a password")
	}

	// One protocol, by name. It has to be one that can authenticate: a
	// configuration with users and only NFS is refused, and rightly.
	var one *protocol
	for _, p := range protocols {
		if p.authenticates {
			one = p
			break
		}
	}
	out, err = execute(t, "check", "--image", img, "--user", "alice", "--password-file", pw,
		"--protocol", one.name)
	if err != nil {
		t.Fatalf("check --protocol: %v\n%s", err, out)
	}
	for _, p := range protocols {
		if p == one {
			continue
		}
		if strings.Contains(out, strings.ToUpper(p.name)) {
			t.Errorf("--protocol %s served %s as well:\n%s", one.name, p.name, out)
		}
	}

	// What it refuses.
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"an image with nobody named on it", []string{"--image", img}, "a share with nobody named on it"},
		{"a protocol this binary has not", []string{"--image", img, "--user", "alice",
			"--password-file", pw, "--protocol", "gopher"}, "names none this binary has"},
		{"both a file and the flags", []string{"--config", dir, "--image", img},
			"do not go with it"},
	} {
		if _, err := execute(t, append([]string{"check"}, tc.args...)...); err == nil ||
			!strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestAShareIsNamedAfterItsImage(t *testing.T) {
	for _, tc := range []struct{ path, want string }{
		{"/srv/photos.img", "photos"},
		{"holiday.dmg", "holiday"},
		{`C:\images\backup.raw`, "backup"},
		{"noextension", "noextension"},
		{"", "disk"},
		{"/srv/.hidden", ".hidden"},
	} {
		if got := defaultShareName(tc.path); got != tc.want {
			t.Errorf("defaultShareName(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}
