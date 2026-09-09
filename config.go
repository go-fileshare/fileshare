// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/go-filesystems/sftp/sshd"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"golang.org/x/crypto/ssh"
)

// A config is what the HCL files say.
//
//	name = "ATTIC"
//
//	user "alice" {
//	  password_file = "/etc/fileshare/alice.pw"
//	}
//
//	share "photos" {
//	  image   = "/srv/photos.img"
//	  allow   = ["alice", "bob"]
//	  writers = ["alice"]
//	}
//
//	serve "smb"    { addr = "0.0.0.0:445" }
//	serve "webdav" { addr = "0.0.0.0:8080" }
//	serve "nfs"    { addr = "127.0.0.1:2049" }
type config struct {
	Name string `hcl:"name,optional"`
	// HostKeyFile is the SFTP server's own identity. Without one a fresh key
	// is generated at every start, and every client that has seen the server
	// before warns about it.
	HostKeyFile string `hcl:"host_key_file,optional"`
	// TrustedUserCAFile holds the public keys of the certificate authorities
	// whose user certificates are accepted, the way OpenSSH's
	// TrustedUserCAKeys does. With one, a person's access is issued and
	// expires elsewhere and no file here is edited when somebody joins or
	// leaves.
	TrustedUserCAFile string       `hcl:"trusted_user_ca_file,optional"`
	Users             []userBlock  `hcl:"user,block"`
	Shares            []shareBlock `hcl:"share,block"`
	Serves            []serveBlock `hcl:"serve,block"`
}

// A userBlock is a set of credentials. The password comes from the file named
// here, or -- when it is written inline -- from the configuration itself,
// which is a choice about who may read that file.
type userBlock struct {
	Name         string `hcl:"name,label"`
	Password     string `hcl:"password,optional"`
	PasswordFile string `hcl:"password_file,optional"`
	// AuthorizedKeys are this person's SSH public keys, for SFTP. They are
	// written the way an authorized_keys file writes them ("ssh-ed25519 AAAA…
	// alice@laptop"), either inline or in a file of their own.
	//
	// SFTP authenticates by KEY, not by password: a password prompt is the
	// thing SSH clients exist to avoid, and a key proves who is asking
	// without the server ever holding the secret.
	AuthorizedKeys     []string `hcl:"authorized_keys,optional"`
	AuthorizedKeysFile string   `hcl:"authorized_keys_file,optional"`
}

// A shareBlock is one image, exported under a name, to some people.
type shareBlock struct {
	Name     string   `hcl:"name,label"`
	Image    string   `hcl:"image"`
	ReadOnly bool     `hcl:"read_only,optional"`
	Allow    []string `hcl:"allow,optional"`
	Writers  []string `hcl:"writers,optional"`
	// Protocols narrows which of them may carry this share. Empty means every
	// protocol that CAN honour it -- which is not the same as every protocol,
	// because one that cannot tell people apart is refused a restricted share
	// whatever this says.
	Protocols []string `hcl:"protocols,optional"`
}

// A serveBlock turns one protocol on. The label is the protocol's name.
type serveBlock struct {
	Protocol string `hcl:"protocol,label"`
	Addr     string `hcl:"addr,optional"`
}

// loadConfig reads every file named, and every .hcl file in every directory
// named, as ONE configuration.
//
// They are merged rather than read in turn, which is what makes an
// /etc/fileshare.d of small files work: a user in one file and a share in
// another are the same configuration, and a name defined twice is an error
// that names both places rather than the last one silently winning.
func loadConfig(paths []string) (*config, error) {
	parser := hclparse.NewParser()
	var files []*hcl.File
	for _, p := range expandConfigPaths(paths) {
		f, diags := parser.ParseHCLFile(p)
		if diags.HasErrors() {
			return nil, diagError(parser, diags)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no configuration files were found in %s", strings.Join(paths, ", "))
	}
	var cfg config
	if diags := gohcl.DecodeBody(hcl.MergeFiles(files), nil, &cfg); diags.HasErrors() {
		return nil, diagError(parser, diags)
	}
	if err := cfg.check(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// expandConfigPaths turns a directory into the .hcl files inside it, in a
// stable order: two runs of the same directory must serve the same thing.
func expandConfigPaths(paths []string) []string {
	var out []string
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			matches, _ := filepath.Glob(filepath.Join(p, "*.hcl"))
			sort.Strings(matches)
			out = append(out, matches...)
			continue
		}
		out = append(out, p)
	}
	return out
}

// check refuses a configuration that would start a server nobody can use, or
// one that says two things at once.
func (c *config) check() error {
	if len(c.Shares) == 0 {
		return fmt.Errorf("there are no shares: a server with nothing to serve is not one")
	}
	if len(c.Serves) == 0 {
		return fmt.Errorf("no serve block: name at least one of %s", protocolNames())
	}

	seen := map[string]string{}
	for _, s := range c.Shares {
		key := strings.ToUpper(s.Name)
		if where, taken := seen[key]; taken {
			return fmt.Errorf("two shares answer to %q (the other is %s): SMB compares names without case", s.Name, where)
		}
		seen[key] = s.Image
		if s.Image == "" {
			return fmt.Errorf("share %q has no image", s.Name)
		}
		if strings.ContainsAny(s.Name, `\/`) {
			return fmt.Errorf("share %q has a path separator in its name: it is a name, not a path", s.Name)
		}
		if s.ReadOnly && len(s.Writers) > 0 {
			return fmt.Errorf("share %q is read_only and also lists writers: read_only wins, so say one or the other", s.Name)
		}
		for _, name := range s.Protocols {
			if protocolByName(name) == nil {
				if missing(name) {
					return fmt.Errorf("share %q names %s, which this binary was built without", s.Name, name)
				}
				return fmt.Errorf("share %q names %q, which is not a protocol here: there are %s", s.Name, name, protocolNames())
			}
		}
	}

	users := map[string]bool{}
	for _, u := range c.Users {
		if users[u.Name] {
			return fmt.Errorf("user %q is defined twice", u.Name)
		}
		users[u.Name] = true
		switch {
		case u.Password != "" && u.PasswordFile != "":
			return fmt.Errorf("user %q has both a password and a password_file: say which one", u.Name)
		case len(u.AuthorizedKeys) > 0 && u.AuthorizedKeysFile != "":
			return fmt.Errorf("user %q has both authorized_keys and an authorized_keys_file: say which one", u.Name)
		case u.Password == "" && u.PasswordFile == "" && len(u.AuthorizedKeys) == 0 &&
			u.AuthorizedKeysFile == "" && c.TrustedUserCAFile == "":
			// With a trusted authority there is nothing to say here: the
			// certificate IS the credential, issued elsewhere and expiring on
			// its own. That is the whole reason to have one.
			return fmt.Errorf("user %q has no way to authenticate: a password, authorized keys, or a certificate from trusted_user_ca_file", u.Name)
		}
	}

	// A name in allow or writers that belongs to nobody is a typo, and a typo
	// here is silent in the worst way: "alise" in allow locks Alice out of her
	// own share and the server starts happily.
	for _, s := range c.Shares {
		for _, who := range s.Allow {
			if !users[who] {
				return fmt.Errorf("share %q allows %q, who is not a user here", s.Name, who)
			}
		}
		for _, who := range s.Writers {
			if !users[who] {
				return fmt.Errorf("share %q lets %q write, who is not a user here", s.Name, who)
			}
			if len(s.Allow) > 0 && !slices.Contains(s.Allow, who) {
				return fmt.Errorf("share %q lets %q write but does not allow them to connect", s.Name, who)
			}
		}
	}

	on := map[string]string{}
	authenticated := false
	for i := range c.Serves {
		s := &c.Serves[i]
		p := protocolByName(s.Protocol)
		if p == nil {
			if missing(s.Protocol) {
				return fmt.Errorf("this binary was built without %s: it has %s (see the build tags in the README)",
					s.Protocol, protocolNames())
			}
			return fmt.Errorf("there is no %q protocol here: the ones there are are %s", s.Protocol, protocolNames())
		}
		if where, taken := on[s.Protocol]; taken {
			return fmt.Errorf("%s is served twice (%s and %s): one listener each", s.Protocol, where, s.Addr)
		}
		on[s.Protocol] = s.Addr
		if s.Addr == "" {
			s.Addr = fmt.Sprintf("127.0.0.1:%d", p.defaultPort)
		}
		if _, _, err := net.SplitHostPort(s.Addr); err != nil {
			return fmt.Errorf("%s: %q is not an address to listen on: %w", s.Protocol, s.Addr, err)
		}
		if p.authenticates {
			authenticated = true
		}
	}
	// A protocol that would carry NOTHING is a serve block that cannot do
	// anything, and it is refused before an image is opened rather than at the
	// first client -- or, worse, at the moment the server it is part of dies
	// because one listener had no exports. The message says which shares were
	// kept from it and why, because that is the thing to change.
	for _, b := range c.Serves {
		p := protocolByName(b.Protocol)
		var carried bool
		var why []string
		for _, sb := range c.Shares {
			sh := &share{name: sb.Name, readOnly: sb.ReadOnly, allow: sb.Allow,
				writers: sb.Writers, protocols: sb.Protocols}
			served, refused := p.exports([]*share{sh})
			switch {
			case len(served) == 1:
				carried = true
			case len(refused) == 1:
				why = append(why, fmt.Sprintf("%s is restricted to %s", sh.name, sh.who()))
			default:
				why = append(why, fmt.Sprintf("%s names protocols = [%s]", sh.name, strings.Join(sb.Protocols, ", ")))
			}
		}
		if !carried {
			return fmt.Errorf("%s would carry nothing: %s. Remove the serve block, or let a share through",
				b.Protocol, strings.Join(why, "; "))
		}
	}

	// Users with nowhere to authenticate is a configuration that reads as
	// protected and is not. The message names what THIS configuration serves,
	// not every protocol the binary has: the reader is looking at their own
	// serve blocks.
	if len(c.Users) > 0 && !authenticated {
		named := make([]string, 0, len(c.Serves))
		for _, s := range c.Serves {
			named = append(named, s.Protocol)
		}
		return fmt.Errorf("there are users, and no protocol here can authenticate them: %s cannot tell people apart", list(named))
	}
	return nil
}

// servesProtocol reports whether this configuration turns one on.
func (c *config) servesProtocol(name string) bool {
	for _, b := range c.Serves {
		if b.Protocol == name {
			return true
		}
	}
	return false
}

// password reads what this user authenticates with.
func (u userBlock) password() (string, error) {
	if u.PasswordFile != "" {
		b, err := os.ReadFile(u.PasswordFile)
		if err != nil {
			return "", fmt.Errorf("user %q: %w", u.Name, err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return u.Password, nil
}

// authorizedKeys reads this person's SSH public keys, from the configuration
// or from a file written the way authorized_keys is.
func (u userBlock) authorizedKeys() ([]ssh.PublicKey, error) {
	text := strings.Join(u.AuthorizedKeys, "\n")
	if u.AuthorizedKeysFile != "" {
		b, err := os.ReadFile(u.AuthorizedKeysFile)
		if err != nil {
			return nil, fmt.Errorf("user %q: %w", u.Name, err)
		}
		text = string(b)
	}
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	keys, err := sshd.ParseAuthorizedKeys([]byte(text))
	if err != nil {
		// A line that does not parse is an error rather than a skip: silently
		// ignoring one is how a server ends up denying the person it was
		// configured for, with nothing to say why.
		return nil, fmt.Errorf("user %q: %w", u.Name, err)
	}
	return keys, nil
}

// diagError turns HCL's diagnostics into an error that keeps what makes them
// worth having: the file, the line, and the source snippet.
func diagError(parser *hclparse.Parser, diags hcl.Diagnostics) error {
	var sb strings.Builder
	w := hcl.NewDiagnosticTextWriter(&sb, parser.Files(), 78, false)
	if err := w.WriteDiagnostics(diags); err != nil {
		return diags
	}
	return fmt.Errorf("%s", strings.TrimSpace(sb.String()))
}
