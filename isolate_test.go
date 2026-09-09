package main

import (
	"fmt"
	"strings"
	"testing"
)

// The rule that makes one process per protocol honest: a writable image
// reached by two protocols would be two drivers over one file.
func TestWhatCannotBeIsolated(t *testing.T) {
	two := []serveBlock{{Protocol: "smb"}, {Protocol: "webdav"}}
	for _, tc := range []struct {
		name   string
		share  *share
		serves []serveBlock
		refuse bool
	}{
		{"writable over two protocols", &share{name: "scratch"}, two, true},
		{"read-only over two protocols", &share{name: "photos", readOnly: true}, two, false},
		{"writable, but named to one", &share{name: "scratch", protocols: []string{"smb"}}, two, false},
		{"writable over one protocol", &share{name: "scratch"}, two[:1], false},
		{
			"restricted and writable, over one that cannot authenticate",
			&share{name: "photos", allow: []string{"alice"}},
			[]serveBlock{{Protocol: "smb"}, {Protocol: "nfs"}},
			false, // nfs is refused it anyway, so only smb writes
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, b := range tc.serves {
				if protocolByName(b.Protocol) == nil {
					t.Skipf("this binary has no %s", b.Protocol)
				}
			}
			why := isolationRefusal([]*share{tc.share}, tc.serves)
			if (why != "") != tc.refuse {
				t.Errorf("refusal = %q, want refused = %v", why, tc.refuse)
			}
			if tc.refuse && !strings.Contains(why, "protocols = ") {
				t.Errorf("the refusal does not say how to fix it: %q", why)
			}
		})
	}
}

// A child is told the shares it may open and no others. This is the whole
// least-privilege claim, and it is decided here.
func TestAChildIsToldOnlyItsOwnShares(t *testing.T) {
	needUsers(t)
	var auth, blind *protocol
	for _, p := range protocols {
		if p.authenticates && auth == nil {
			auth = p
		}
		if !p.authenticates && blind == nil {
			blind = p
		}
	}
	if auth == nil {
		t.Skip("this binary has no protocol that authenticates")
	}
	cfg := &config{Shares: []shareBlock{
		{Name: "public", Image: "/i"},
		{Name: "restricted", Image: "/i", Allow: []string{"alice"}},
		{Name: "smbonly", Image: "/i", Protocols: []string{auth.name}},
	}}
	got := strings.Join(sharesForChild(cfg, auth), ",")
	if got != "public,restricted,smbonly" {
		t.Errorf("%s was given %q", auth.name, got)
	}
	if blind != nil {
		got := strings.Join(sharesForChild(cfg, blind), ",")
		// Not the restricted one -- it cannot tell who is asking -- and not
		// the one that named another protocol.
		if got != "public" {
			t.Errorf("%s was given %q, want only the public share", blind.name, got)
		}
	}
}

// A serve block that would carry nothing is refused before anything opens.
func TestAProtocolThatWouldCarryNothing(t *testing.T) {
	needUsers(t)
	var auth, blind *protocol
	for _, p := range protocols {
		if !p.authenticates && blind == nil {
			blind = p
		}
		if p.authenticates && auth == nil {
			auth = p
		}
	}
	if blind == nil || auth == nil {
		t.Skip("this needs one protocol that authenticates and one that cannot")
	}
	dir := t.TempDir()
	pw := write(t, dir, "pw", "hunter2\n")
	path := write(t, dir, "c.hcl", fmt.Sprintf(`
user "alice" { password_file = %q }
share "photos" {
  image = "/i"
  allow = ["alice"]
}
serve %q {}
serve %q {}
`, hclPath(pw), auth.name, blind.name))
	_, err := loadConfig([]string{path})
	if err == nil || !strings.Contains(err.Error(), "would carry nothing") {
		t.Errorf("error = %v, want one about carrying nothing", err)
	}
	if err != nil && !strings.Contains(err.Error(), "restricted to alice") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

// A share can name the protocols that carry it, and a name that is not one is
// refused.
func TestAShareCanNameItsProtocols(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "c.hcl", fmt.Sprintf(`
share "s" {
  image     = "/i"
  protocols = ["gopher"]
}
serve %q {}
`, protocols[0].name))
	_, err := loadConfig([]string{path})
	if err == nil || !strings.Contains(err.Error(), "not a protocol here") {
		t.Errorf("error = %v", err)
	}
}
