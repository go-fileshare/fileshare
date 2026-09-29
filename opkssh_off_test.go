//go:build !nosftp && noopenpubkey

package main

import (
	"fmt"
	"strings"
	"testing"
)

// A binary without OpenPubkey refuses a configuration that asks for opkssh
// logins, rather than starting without them -- which is how an sftp client
// was once left waiting on a server whose SFTP never came up.
func TestOpksshRefusedWithoutOpenPubkey(t *testing.T) {
	dir := t.TempDir()
	img := image(t, dir, "x.img", map[string]string{"/a.txt": "a"})
	body := fmt.Sprintf(`
oidc {
  issuer           = "https://login.example.test"
  audience         = "fileshare"
  opkssh_client_id = "opkssh"
}
share "x" { image = %q }
serve "sftp" { addr = "127.0.0.1:0" }
`, hclPath(img))
	if _, err := loadConfig([]string{write(t, dir, "c.hcl", body)}); err == nil || !strings.Contains(err.Error(), "noopenpubkey") {
		t.Fatalf("err = %v", err)
	}
}
