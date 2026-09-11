// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/hcldir"
	"github.com/go-filesystems/sftp/sshd"
	"github.com/go-volumes/gpt"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
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
	Groups            []groupBlock `hcl:"group,block"`
	Directories       []usersBlock `hcl:"users,block"`
	// OIDC names an identity provider whose tokens this server accepts.
	// ⛔ Only WebDAV can carry a token: SMB authenticates with NTLMv2, SFTP
	// with a key, and NFS with nothing. `check` prints that per person.
	OIDC   *oidcBlock   `hcl:"oidc,block"`
	Shares []shareBlock `hcl:"share,block"`
	Serves []serveBlock `hcl:"serve,block"`
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

// A groupBlock is a name for several people, so a share can be given to a
// team rather than to a list that has to be edited every time somebody joins.
//
//	group "staff" { members = ["alice", "bob"] }
//	share "photos" { allow = ["@staff"] }
//
// The leading @ is Samba's spelling (`valid users = @staff`) and is what
// anybody administering a file server will type without being told.
type groupBlock struct {
	Name    string   `hcl:"name,label"`
	Members []string `hcl:"members"`
}

// An oidcBlock names an identity provider.
//
// There is no client secret here and no redirect: this server is the resource
// server, not the thing that talks a person through logging in. Something
// arrives with a token, and go-authn/oidc says who it is about.
type oidcBlock struct {
	// Issuer is the provider, exactly as its tokens spell "iss".
	Issuer string `hcl:"issuer"`
	// Audience is what this server is called at the provider. A token minted
	// for another service is a valid token that is simply not addressed here.
	Audience string `hcl:"audience"`
	// JWKSURL skips discovery, for a provider that publishes no
	// /.well-known/openid-configuration.
	JWKSURL string `hcl:"jwks_url,optional"`
	// UsernameClaim is which claim names the person, in the names the shares
	// are written with. Default preferred_username.
	UsernameClaim string `hcl:"username_claim,optional"`
	// GroupsClaim is which claim carries their groups. Default groups.
	GroupsClaim string `hcl:"groups_claim,optional"`
	// TrustAll accepts anybody the provider vouches for, rather than only
	// people this configuration also knows.
	//
	// ⛔ It is the difference between "these people" and "everybody that
	// provider has", and it is spelled out because a token proves who the
	// PROVIDER says somebody is -- not that this server has a share for them.
	TrustAll bool `hcl:"trust_all,optional"`
}

// The `users` block is go-authn/directory/hcldir's: a file server and an
// authentication server describing the same directory two ways would be two
// vocabularies for one idea, and a person administering both would have to
// learn it twice.
type usersBlock = hcldir.Block

type shareBlock struct {
	Name     string `hcl:"name,label"`
	Image    string `hcl:"image"`
	ReadOnly bool   `hcl:"read_only,optional"`
	// Filesystem names the driver instead of sniffing for it. It is needed
	// for apfs, btrfs, xfs and zfs -- which open a DISK image and pick a
	// partition, so there is no filesystem magic at offset zero to find --
	// and it is accepted for the others as an override.
	//
	// ⛔ Saying it turns detection OFF for this share.
	Filesystem string `hcl:"filesystem,optional"`
	// Partition is which one to open, counting from 1 the way every
	// partitioning tool prints them.
	//
	// ⛔ An index MOVES. A disk repartitioned, a tool that writes entries in
	// another order, an image restored with one partition fewer -- and this
	// names something else, silently, because a filesystem is still found
	// there. Prefer PartitionLabel or PartitionUUID, which name the partition
	// itself; the index is here for MBR images, which have neither.
	Partition *int `hcl:"partition,optional"`
	// PartitionLabel is the GPT partition name -- what lsblk calls PARTLABEL.
	PartitionLabel string `hcl:"partition_label,optional"`
	// PartitionUUID is the GPT unique partition GUID -- what Linux calls
	// PARTUUID -- as people write it: 8-4-4-4-12.
	PartitionUUID string   `hcl:"partition_uuid,optional"`
	Allow         []string `hcl:"allow,optional"`
	Writers       []string `hcl:"writers,optional"`
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
		if s.Filesystem != "" && !knownFilesystem(s.Filesystem) {
			return fmt.Errorf("share %q names filesystem %q, which is not one here: %s",
				s.Name, s.Filesystem, allFilesystems())
		}
		if n := chosenPartitionWays(s); n > 1 {
			// Two ways to name one partition can disagree, and then the share
			// serves whichever the code happened to try first.
			return fmt.Errorf("share %q chooses a partition %d ways: say one of "+
				"partition, partition_label or partition_uuid", s.Name, n)
		}
		if s.Partition != nil && *s.Partition < 1 {
			return fmt.Errorf("share %q asks for partition %d: they count from 1, "+
				"and a share with no partition setting uses the image itself", s.Name, *s.Partition)
		}
		if s.PartitionUUID != "" {
			if _, err := gpt.ParseUUID(s.PartitionUUID); err != nil {
				return fmt.Errorf("share %q: %w", s.Name, err)
			}
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

	groups := map[string]bool{}
	for _, g := range c.Groups {
		if _, twice := groups[g.Name]; twice {
			return fmt.Errorf("group %q is defined twice", g.Name)
		}
		if len(g.Members) == 0 {
			// A group with nobody in it grants nothing, and a configuration
			// that grants nothing to nobody reads exactly like one that works.
			return fmt.Errorf("group %q has no members", g.Name)
		}
		groups[g.Name] = true
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

	// A `users` block that cannot be what it says it is. These are checked
	// before anything connects, because a directory that is unreachable and a
	// directory that was described wrongly produce the same symptom -- a
	// server that will not start -- and only one of them is fixed by looking
	// at the network.
	for _, b := range c.Directories {
		if err := b.Check(); err != nil {
			return err
		}
	}

	if o := c.OIDC; o != nil {
		switch {
		case o.Issuer == "":
			return fmt.Errorf("the oidc block has no issuer")
		case o.Audience == "":
			return fmt.Errorf("the oidc block has no audience: a token minted for another service is a " +
				"valid token, and a server that does not check accepts every one that provider ever signed")
		case !c.servesProtocol("webdav"):
			// ⛔ Not a warning: a configuration that names a provider and
			// serves nothing that can carry a token does not do what it says.
			return fmt.Errorf("the oidc block is here and webdav is not served: a token can only arrive " +
				"over webdav, because SMB, SFTP and NFS have nowhere to put one")
		case o.TrustAll && len(c.Users) == 0 && len(c.Directories) == 0:
			// This is the legitimate shape for trust_all -- the provider IS
			// the directory -- and it is allowed. Named here so the reader
			// knows it was considered.
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

// resolve checks every name the configuration writes against the people and
// groups that actually EXIST, once the directories are open.
//
// It is separate from validate, and later, because the file stopped being the
// whole truth the day a `users` block could name a database: "@engineers" is
// not a typo when the group is in SQL, and "dora" is not a stranger when she
// is in LDAP. What has not changed is why the check is here at all -- a name
// that belongs to nobody is silent in the worst way, since "alise" in allow
// locks Alice out of her own share and the server starts happily.
func (c *config) resolve(dir *directory.Set, known map[string]*directory.Identity) error {
	// unknown says what is wrong with a name, in the same words whichever
	// list it was in. A name may be a person or a GROUP, spelled @name.
	unknown := func(who string) string {
		if directory.IsGroup(who) {
			if _, err := dir.Members(strings.TrimPrefix(who, directory.GroupPrefix)); err != nil {
				if errors.Is(err, directory.ErrNoSuchGroup) {
					return fmt.Sprintf("%s, and there is no such group in %s", who, dir.Describe())
				}
				// A directory that is BROKEN is not one that lacks the group,
				// and the two are fixed in different places.
				return fmt.Sprintf("%s, and the group could not be read: %v", who, err)
			}
			return ""
		}
		if _, ok := known[who]; !ok {
			return fmt.Sprintf("%q, who is %s", who, nobodyIn(dir))
		}
		return ""
	}
	for _, g := range c.Groups {
		for _, m := range g.Members {
			if _, ok := known[m]; !ok {
				return fmt.Errorf("group %q has %q in it, who is %s", g.Name, m, nobodyIn(dir))
			}
		}
	}
	for _, s := range c.Shares {
		for _, who := range s.Allow {
			if bad := unknown(who); bad != "" {
				return fmt.Errorf("share %q allows %s", s.Name, bad)
			}
		}
		for _, who := range s.Writers {
			if bad := unknown(who); bad != "" {
				return fmt.Errorf("share %q lets %s write", s.Name, bad)
			}
			// A writer who may not connect never writes. The comparison is
			// between the EXPANDED lists, because "@staff" and "alice" can be
			// the same people written two ways.
			ok, err := within(who, s.Allow, dir)
			if err != nil {
				return fmt.Errorf("share %q: %w", s.Name, err)
			}
			if len(s.Allow) > 0 && !ok {
				return fmt.Errorf("share %q lets %s write but does not allow them to connect", s.Name, who)
			}
		}
	}
	return nil
}

// nobodyIn says WHERE this server looked, so that a name belonging to nobody
// reads as the typo it usually is -- and, when there are directories, tells
// the reader which ones answered without the person in them.
func nobodyIn(dir *directory.Set) string {
	if len(dir.Sources()) == 1 {
		return "not in " + dir.Describe()
	}
	return "in none of " + dir.Describe()
}

// within reports whether everybody named by who is also named by allow, with
// both sides expanded through the directory.
func within(who string, allow []string, dir *directory.Set) (bool, error) {
	allowed, err := directory.Expand(allow, dir)
	if err != nil {
		return false, err
	}
	names, err := directory.Expand([]string{who}, dir)
	if err != nil {
		return false, err
	}
	for _, m := range names {
		if !slices.Contains(allowed, m) {
			return false, nil
		}
	}
	return true, nil
}

// detectedFilesystems are the ones detect sniffs for, which a share may also
// name to skip the sniffing.
var detectedFilesystems = []string{"fat32", "exfat", "ext4", "ntfs", "ufs", "iso9660", "squashfs", "hfsplus"}

// partitionAwareFilesystems open a disk image and pick a partition, which is
// why they cannot be sniffed at offset zero.
var partitionAwareFilesystems = []string{"apfs", "btrfs", "xfs", "zfs"}

func knownFilesystem(name string) bool {
	return slices.Contains(detectedFilesystems, name) || partitionAware(name)
}

func partitionAware(name string) bool { return slices.Contains(partitionAwareFilesystems, name) }

// allFilesystems is every name a share may use, for a message that lists what
// would have worked -- and says when this binary was built without half of it.
func allFilesystems() string {
	names := append([]string{}, detectedFilesystems...)
	if hasNamed() {
		names = append(names, partitionAwareFilesystems...)
	}
	slices.Sort(names)
	out := strings.Join(names, ", ")
	if !hasNamed() {
		out += " (this binary was built with -tags nopartitioned, which leaves out " +
			strings.Join(partitionAwareFilesystems, ", ") + ")"
	}
	return out
}

// chosenPartitionWays counts how many ways a share names its partition.
func chosenPartitionWays(s shareBlock) int {
	n := 0
	if s.Partition != nil {
		n++
	}
	if s.PartitionLabel != "" {
		n++
	}
	if s.PartitionUUID != "" {
		n++
	}
	return n
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
func (u userBlock) authorizedKeyLines() ([]string, error) {
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
	// Parsed here to REFUSE a line that does not parse -- silently ignoring
	// one is how a server ends up denying the person it was configured for,
	// with nothing to say why -- and handed on as text, because that is what
	// a directory holds and what the library takes.
	if _, err := sshd.ParseAuthorizedKeys([]byte(text)); err != nil {
		return nil, fmt.Errorf("user %q: %w", u.Name, err)
	}
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, nil
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
