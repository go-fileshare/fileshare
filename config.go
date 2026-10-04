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
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/hcldir"
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
//	tls {
//	  cert_file = "/etc/fileshare/tls/fullchain.pem"
//	  key_file  = "/etc/fileshare/tls/key.pem"
//	}
//
//	serve "smb"    { addr = "0.0.0.0:445" }
//	serve "webdav" {
//	  addr = "0.0.0.0:443"
//	  tls  = true
//	}
//	serve "nfs"    { addr = "127.0.0.1:2049" }
type config struct {
	Name string `hcl:"name,optional"`
	// Reload is how often the directory is read again, as a Go duration:
	// "5m". Empty, the default, reads it only at the start, on SIGHUP and on
	// the admin API's ReloadDirectory; see reload.go.
	Reload string `hcl:"reload,optional"`
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
	OIDC     *oidcBlock     `hcl:"oidc,block"`
	Kerberos *kerberosBlock `hcl:"kerberos,block"`
	Shares   []shareBlock   `hcl:"share,block"`
	Serves   []serveBlock   `hcl:"serve,block"`
	// Admin turns the gRPC admin API on; see admin.go. Metrics serves
	// /healthz, /readyz and /metrics; see metrics.go. Neither is on unless
	// its block is written.
	Admin   *adminBlock   `hcl:"admin,block"`
	Metrics *metricsBlock `hcl:"metrics,block"`
	// TLS is where the certificate of the protocols that speak TLS comes
	// from; see tls.go.
	TLS *tlsBlock `hcl:"tls,block"`
	// SSF is where revocations of federated people come from; see ssf.go.
	SSF *ssfBlock `hcl:"ssf,block"`

	// managed is the names of the shares that came from the admin API's
	// state file rather than from these files, upper-cased the way SMB
	// compares them. fromFiles is every share the files define, and offline
	// the shares DisableShare took offline, which are not in Shares. All
	// three are filled by withState.
	managed   map[string]bool
	fromFiles []shareBlock
	offline   []shareBlock
	// sources are the configuration files this was read from.
	sources []string
}

// An adminBlock turns on the gRPC admin API.
//
//	admin {
//	  listen       = "unix:///run/fileshare/admin.sock"
//	  state_file   = "/var/lib/fileshare/shares.json"
//	  source_roots = ["/srv/images", "/data"]
//	}
//
// ⛔ Over TCP it is mutual TLS or nothing: tls_cert_file, tls_key_file and
// client_ca_file together, loopback included, because every local user can
// reach loopback and the API decides who reads whose files. A unix socket is
// made 0600, and its permissions are its access control.
type adminBlock struct {
	Listen       string `hcl:"listen"`
	TLSCertFile  string `hcl:"tls_cert_file,optional"`
	TLSKeyFile   string `hcl:"tls_key_file,optional"`
	ClientCAFile string `hcl:"client_ca_file,optional"`
	// StateFile is where the shares the API created are kept, so a restart
	// serves them again.
	StateFile string `hcl:"state_file"`
	// SourceRoots is where a share the API creates may take its image or
	// directory from. Empty means the API cannot create one: the process
	// can read things -- /dev, /etc -- that nobody meant to hand to a
	// caller who may create shares.
	SourceRoots []string `hcl:"source_roots,optional"`
	// Reflection turns on gRPC server reflection, for grpcurl.
	Reflection bool `hcl:"reflection,optional"`
}

// A metricsBlock serves the endpoints a supervisor asks: whether the process
// is alive, whether it is serving, and what it has done. It is its own
// listener so that it never shares a port with a protocol the world reaches.
type metricsBlock struct {
	Listen string `hcl:"listen"`
}

// A userBlock is somebody written in this file rather than in a directory.
//
// ⛔ It used to be declared HERE, and go-authn/authnd declared its own, and
// the two had drifted: authnd's carried nt_hash and totp_secret and this one
// did not, so a person written inline here could never be served over SMB --
// NTLMv2 works from the password or its MD4 and nothing else, which is what
// canServeUser says. One definition now, in the package that exists to hold
// exactly this.
type userBlock = hcldir.UserBlock

// A groupBlock is a name for several people, so a share can be given to a
// team rather than to a list.
type groupBlock = hcldir.GroupBlock

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

	// Domains, when set, are the only institutions whose people are let in:
	// a federated name must be <something>@<one of these>. The rest of the
	// federation -- hundreds of IdPs in RENATER, thousands in eduGAIN -- is
	// refused at authentication, before any share is looked at.
	Domains []string `hcl:"domains,optional"`

	// SSHCAFile is the provider's SSH certificate authority -- go-authn/bridge's
	// ssh_ca -- whose certificates carry the provider's word over SFTP: the
	// principal is the person, and the groups extension their groups. It is
	// NOT trusted_user_ca_file, whose certificates are about local accounts.
	SSHCAFile string `hcl:"ssh_ca_file,optional"`

	// OpksshClientID accepts OpenPubkey (opkssh) certificates over SFTP: an
	// ID token from this provider, for this client ID, committing to the
	// SSH key. A client ID of its own, never another application's: the ID
	// token travels to every server the person logs into.
	OpksshClientID string `hcl:"opkssh_client_id,optional"`

	// OpksshMaxAge is how long after its issue a PK Token is accepted: 12h,
	// 24h (the default, as opkssh), 48h or 1week.
	OpksshMaxAge string `hcl:"opkssh_max_age,optional"`

	// SSHKRLURL, or SSHKRLFile, is where the provider publishes the SSH
	// certificates it has revoked, as an OpenSSH KRL: go-authn/bridge serves
	// it at /ssh/krl. With one, a revoked certificate is refused at login and
	// a session it opened stops being served; see revocation.go.
	//
	// ⛔ It fails closed: while the list cannot be fetched, or its last good
	// copy is older than ssh_krl_max_age, the provider's certificates are
	// refused. A list from SSHKRLURL must come with its signature by the
	// provider's SSH CA (SSHKRLURL + ".sig", against SSHCAFile) and say
	// when it expires: go-authn/revocation's protocol, served by
	// go-authn/bridge from v0.10.0. SSHKRLCAFile pins the authorities the list's HTTPS server is
	// checked against, instead of the system's.
	SSHKRLURL     string `hcl:"ssh_krl_url,optional"`
	SSHKRLFile    string `hcl:"ssh_krl_file,optional"`
	SSHKRLCAFile  string `hcl:"ssh_krl_ca_file,optional"`
	SSHKRLRefresh string `hcl:"ssh_krl_refresh,optional"` // default 1m
	SSHKRLMaxAge  string `hcl:"ssh_krl_max_age,optional"` // default 1h
	// SSHKRLStateFile keeps the last KRL that verified across a restart,
	// so that an older one is still refused after it.
	SSHKRLStateFile string `hcl:"ssh_krl_state_file,optional"`
}

// krlTiming is how often the KRL is fetched, and how old its last good copy
// may be before the certificates it governs are refused.
func (o *oidcBlock) krlTiming() (refresh, maxAge time.Duration, err error) {
	return listTiming("ssh_krl", o.SSHKRLRefresh, o.SSHKRLMaxAge)
}

// listTiming reads a revocation list's two durations, with their defaults.
func listTiming(name, refreshS, maxAgeS string) (refresh, maxAge time.Duration, err error) {
	refresh, maxAge = time.Minute, time.Hour
	if refreshS != "" {
		if refresh, err = time.ParseDuration(refreshS); err != nil || refresh < time.Second {
			return 0, 0, fmt.Errorf("%s_refresh = %q is not a duration of a second or more", name, refreshS)
		}
	}
	if maxAgeS != "" {
		if maxAge, err = time.ParseDuration(maxAgeS); err != nil {
			return 0, 0, fmt.Errorf("%s_max_age = %q is not a duration", name, maxAgeS)
		}
	}
	if maxAge < refresh {
		// Every copy would be stale before the next fetch, and every
		// certificate refused between two of them.
		return 0, 0, fmt.Errorf("%s_max_age (%s) is shorter than %s_refresh (%s)", name, maxAge, name, refresh)
	}
	return refresh, maxAge, nil
}

// checkListSource refuses a revocation list named twice, or fetched in the
// clear: a list an attacker on the path can replace revokes nothing.
func checkListSource(name, url, file string) error {
	switch {
	case url != "" && file != "":
		return fmt.Errorf("%s_url and %s_file: say where the list is once", name, name)
	case url != "" && !strings.HasPrefix(url, "https://"):
		return fmt.Errorf("%s_url = %q: a revocation list is fetched over https, or somebody on the path decides what is revoked", name, url)
	case file != "" && !filepath.IsAbs(file):
		return fmt.Errorf("%s_file = %q is not an absolute path", name, file)
	}
	return nil
}

// The `users` block is go-authn/directory/hcldir's: a file server and an
// authentication server describing the same directory two ways would be two
// vocabularies for one idea, and a person administering both would have to
// learn it twice.
type usersBlock = hcldir.Block

type shareBlock struct {
	Name string `hcl:"name,label"`
	// Image is a disk image or a device, and Directory a tree of the host --
	// a container's volume, say. A share has one or the other.
	Image     string `hcl:"image,optional"`
	Directory string `hcl:"directory,optional"`
	ReadOnly  bool   `hcl:"read_only,optional"`
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

	// noWriters is an admin API share that nobody was granted write on: it
	// is SERVED read-only, and still opened for writing unless ReadOnly
	// says otherwise, so that a later grant of write does not need the
	// image or the tree opened a second time.
	noWriters bool
	// confine is the source roots an admin API share must be opened
	// through, with the kernel enforcing it; empty for a share of the files.
	confine []string
}

// A serveBlock turns one protocol on. The label is the protocol's name.
type serveBlock struct {
	Protocol string `hcl:"protocol,label"`
	Addr     string `hcl:"addr,optional"`
	// TLS serves this protocol over TLS, with the tls block's certificate.
	TLS bool `hcl:"tls,optional"`
	// ClientCAFile makes NFS clients present a certificate signed by one of
	// these. It proves the MACHINE, not the person: see tls.go.
	ClientCAFile string `hcl:"client_ca_file,optional"`
	// Plaintext says WebDAV is served in the clear on purpose -- because TLS
	// is terminated in front of it. Without it, WebDAV with passwords on an
	// address other machines can reach is refused.
	Plaintext bool `hcl:"plaintext,optional"`

	// Identity = "certificate" makes NFS take the caller's identity from the
	// client certificate -- the FreeBSD / draft-cel-nfsv4-rpc-tls-othername
	// otherName user@domain, as go-authn/bridge issues after an identity
	// provider login -- so a share naming people can be served over NFS
	// without kerberos. See nfs_identity.go for what that promises, and the
	// one thing it cannot: a Linux client's certificate belongs to a MOUNT.
	Identity string `hcl:"identity,optional"`
	// The CRL of that client CA. REQUIRED with identity = "certificate": a
	// person's certificate that nothing can revoke outlives their removal by
	// its whole lifetime. Fetched and kept as revocation.go says, failing
	// closed.
	CRLURL     string `hcl:"crl_url,optional"`
	CRLFile    string `hcl:"crl_file,optional"`
	CRLCAFile  string `hcl:"crl_ca_file,optional"`
	CRLRefresh string `hcl:"crl_refresh,optional"`
	CRLMaxAge  string `hcl:"crl_max_age,optional"`
	// CRLStateFile keeps the last CRL that verified across a restart, so
	// that an older one is still refused after it.
	CRLStateFile string `hcl:"crl_state_file,optional"`
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
	cfg.sources = expandConfigPaths(paths)
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
	// A server the admin API manages may start with nothing and be given
	// its shares afterwards; every other must be given them here.
	managed := c.Admin != nil
	if len(c.Shares) == 0 && !managed {
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
		seen[key] = s.source()
		switch {
		case s.Image == "" && s.Directory == "":
			return fmt.Errorf("share %q has neither an image nor a directory", s.Name)
		case s.Image != "" && s.Directory != "":
			return fmt.Errorf("share %q has an image and a directory: it serves one or the other", s.Name)
		case s.Directory != "" && (s.Filesystem != "" || chosenPartitionWays(s) > 0):
			// A tree of the host has no filesystem to name and no partition
			// table to pick from; saying one means the share was meant to be
			// an image.
			return fmt.Errorf("share %q is a directory, and filesystem and partition are for an image", s.Name)
		}
		if strings.ContainsAny(s.Name, `\/`) {
			return fmt.Errorf("share %q has a path separator in its name: it is a name, not a path", s.Name)
		}
		if err := checkShareName(s.Name); err != nil {
			return err
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
		// Asked of the deployment, not only of the protocol: NFS tells
		// people apart with a kerberos block, or with identities from
		// certificates.
		if p.canAuthenticate(c) {
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
			served, refused := p.exports(c, []*share{sh})
			switch {
			case len(served) == 1:
				carried = true
			case len(refused) == 1:
				why = append(why, fmt.Sprintf("%s is restricted to %s", sh.name, sh.who()))
			default:
				why = append(why, fmt.Sprintf("%s names protocols = [%s]", sh.name, strings.Join(sb.Protocols, ", ")))
			}
		}
		if !carried && !managed {
			return fmt.Errorf("%s would carry nothing: %s. Remove the serve block, or let a share through",
				b.Protocol, strings.Join(why, "; "))
		}
	}

	if err := c.checkControl(); err != nil {
		return err
	}
	if err := c.checkTLS(); err != nil {
		return err
	}
	if c.SSF != nil {
		if err := c.SSF.check(c); err != nil {
			return err
		}
	}
	if _, err := c.reloadEvery(); err != nil {
		return err
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
		if err := checkListSource("ssh_krl", o.SSHKRLURL, o.SSHKRLFile); err != nil {
			return err
		}
		if o.SSHKRLURL != "" && o.SSHCAFile == "" {
			// The list fetched is verified against the CA whose
			// certificates it revokes: no CA, nothing to verify against.
			return fmt.Errorf("ssh_krl_url needs ssh_ca_file: the KRL's signature is checked against the provider's SSH CA")
		}
		if _, _, err := o.krlTiming(); err != nil {
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
		case !c.servesProtocol("webdav") && !(c.servesProtocol("sftp") && (o.SSHCAFile != "" || o.OpksshClientID != "")):
			// ⛔ Not a warning: a configuration that names a provider and
			// serves nothing that can carry its word does not do what it says.
			return fmt.Errorf("the oidc block is here and neither webdav nor a federated sftp is served: " +
				"a token arrives over webdav, the provider's SSH certificates (ssh_ca_file) and " +
				"opkssh ones (opkssh_client_id) over sftp, and SMB and NFS have nowhere to put either")
		case o.OpksshClientID != "" && !haveOpenPubkey:
			return fmt.Errorf("opkssh_client_id: this binary was built with -tags noopenpubkey, and would start without the way in the configuration asks for")
		case o.OpksshMaxAge != "" && !knownMaxAge(o.OpksshMaxAge):
			return fmt.Errorf("opkssh_max_age = %q: 12h, 24h, 48h or 1week", o.OpksshMaxAge)
		case (o.SSHKRLURL != "" || o.SSHKRLFile != "") && o.SSHCAFile == "":
			// The KRL governs the certificates the provider's SSH CA signs;
			// without that CA there are none for it to revoke.
			return fmt.Errorf("ssh_krl_url / ssh_krl_file revoke the provider's SSH certificates, and there is no ssh_ca_file")
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
			if isRule(who) {
				if err := c.checkRule(s.Name, who); err != nil {
					return err
				}
				continue
			}
			if bad := unknown(who); bad != "" {
				return fmt.Errorf("share %q allows %s", s.Name, bad)
			}
		}
		for _, who := range s.Writers {
			if isRule(who) {
				if err := c.checkRule(s.Name, who); err != nil {
					return err
				}
				// Membership of a provider's group cannot be compared with a
				// list of names here, so a rule that may write must be one that
				// may connect, spelled the same way.
				if len(s.Allow) > 0 && !slices.Contains(s.Allow, who) {
					return fmt.Errorf("share %q lets %s write but does not allow %s to connect", s.Name, who, who)
				}
				continue
			}
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

// reloadEvery is the reload interval; zero when there is none.
func (c *config) reloadEvery() (time.Duration, error) {
	if c.Reload == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(c.Reload)
	if err != nil {
		return 0, fmt.Errorf("reload = %q is not a duration like \"5m\": %w", c.Reload, err)
	}
	if d < time.Second {
		// A directory read many times a second is a load on somebody's
		// database, not a fresher server.
		return 0, fmt.Errorf("reload = %q: read the directory at most once a second", c.Reload)
	}
	return d, nil
}

// source is the image or the directory, whichever the share has.
func (b shareBlock) source() string {
	if b.Directory != "" {
		return b.Directory
	}
	return b.Image
}

// checkControl refuses an admin or metrics block that cannot be served safely.
func (c *config) checkControl() error {
	if a := c.Admin; a != nil {
		if a.StateFile == "" {
			return fmt.Errorf("the admin block has no state_file: the shares it creates would be lost at the next restart")
		}
		for _, r := range a.SourceRoots {
			if !filepath.IsAbs(r) {
				return fmt.Errorf("admin: source root %q is not an absolute path", r)
			}
		}
		if err := checkAdminListen(a); err != nil {
			return fmt.Errorf("admin: %w", err)
		}
	}
	if m := c.Metrics; m != nil {
		if _, _, err := metricsNetwork(m.Listen); err != nil {
			return fmt.Errorf("metrics: %w", err)
		}
	}
	return nil
}

// metricsNetwork is where the metrics block listens: "unix:///path" or
// host:port.
func metricsNetwork(listen string) (network, addr string, err error) {
	if p, ok := strings.CutPrefix(listen, "unix://"); ok {
		if !filepath.IsAbs(p) {
			return "", "", fmt.Errorf("%q: a unix socket is named by an absolute path, unix:///like/this", listen)
		}
		return "unix", p, nil
	}
	if _, _, err := net.SplitHostPort(listen); err != nil {
		return "", "", fmt.Errorf("%q is not an address to listen on: %w", listen, err)
	}
	return "tcp", listen, nil
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

// A kerberosBlock lets NFS tell people apart.
//
// ⛔ It is the only reason a restricted share can be served over NFS at all.
// Without it NFSv3 carries AUTH_UNIX, which is a claim the client makes about
// itself and the wire cannot disagree with -- so a share naming who may use it
// is refused rather than handed to whoever connects.
//
// The keytab holds the key for nfs/<host>@REALM. It is the same file a KDC
// writes with ktadd, and go-authn/kdc reads the other side of it.
type kerberosBlock struct {
	// Realm is the realm whose tickets this server accepts. Principals from
	// any other realm are refused even when the name before the @ matches:
	// alice@EXAMPLE.ORG and alice@PARTNER.ORG are different people.
	Realm string `hcl:"realm"`

	// Keytab is the file holding this service's key.
	Keytab string `hcl:"keytab"`
}

// userOf maps a Kerberos principal onto a name this configuration knows.
//
// It returns "" for a principal from another realm, and that is the whole
// point of the realm being configured rather than inferred: two realms can
// both have an alice, and only one of them is ours.
func (k *kerberosBlock) userOf(principal string) string {
	name, realm, ok := strings.Cut(principal, "@")
	if !ok || realm != k.Realm || name == "" {
		return ""
	}
	return name
}

func isRule(who string) bool { return strings.HasPrefix(who, "oidc:") }

// checkRule refuses an oidc: rule that is malformed, or that no identity
// provider here could ever satisfy.
func (c *config) checkRule(share, who string) error {
	if _, _, err := splitRules([]string{who}); err != nil {
		return fmt.Errorf("share %q: %w", share, err)
	}
	if c.OIDC == nil {
		return fmt.Errorf("share %q names %s, and there is no oidc block: no identity provider here could say who that is", share, who)
	}
	return nil
}

// checkShareName refuses a name some protocol cannot carry, or that would
// forge a line wherever a name is printed.
//
// ⛔ Measured by the security review: "my photos" was a ServeMux pattern
// WebDAV panicked on, ".." a prefix the WebDAV and NFS libraries refuse, "{x}"
// a wildcard route, and a name with a newline a forged audit line -- each
// accepted by the admin API, written to its state file, and then fatal at
// every start. A space is fine: "My Photos" is an ordinary SMB share.
func checkShareName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("a share needs a name")
	case name == "." || name == "..":
		return fmt.Errorf("share %q: . and .. are not names", name)
	case utf8.RuneCountInString(name) > 80:
		return fmt.Errorf("share %q: a name is 80 characters at most", name)
	case strings.TrimSpace(name) != name:
		return fmt.Errorf("share %q: a name does not begin or end with a space", name)
	case !utf8.ValidString(name):
		return fmt.Errorf("share %q: a name is UTF-8", name)
	}
	for _, r := range name {
		// Not IsControl: U+2028 is a line separator that is not a control
		// character, and a log viewer breaks the line there all the same.
		if !unicode.IsPrint(r) || strings.ContainsRune(`:*?"<>|{}%`, r) {
			return fmt.Errorf("share %q: %q is not allowed in a name (unprintable characters, and :*?\"<>|{}%%)", name, r)
		}
	}
	return nil
}

// protectedPaths are the files a share must never contain: whoever may write
// into a share holding them would rewrite who may do what -- the
// configuration, the admin API's and the shared signals' state, the keys.
func (c *config) protectedPaths() []string {
	out := slices.Clone(c.sources)
	add := func(p string) {
		if p != "" {
			out = append(out, p)
		}
	}
	if a := c.Admin; a != nil {
		add(a.StateFile)
		add(a.TLSKeyFile)
		add(a.TLSCertFile)
		add(a.ClientCAFile)
	}
	if s := c.SSF; s != nil {
		add(s.StateFile)
		add(s.TokenFile)
		add(s.ClientSecretFile)
	}
	if t := c.TLS; t != nil {
		add(t.KeyFile)
		add(t.CertFile)
		if t.ACME != nil {
			add(t.ACME.CacheDir)
			add(t.ACME.EABHMACKeyFile)
		}
	}
	add(c.HostKeyFile)
	add(c.TrustedUserCAFile)
	// The provider's trust anchors and revocation lists: a share holding
	// ssh_ca_file would let its writers mint the CA's certificates, one
	// holding a list would let them un-revoke (found while fixing the
	// adversarial review: none of these was protected).
	if o := c.OIDC; o != nil {
		add(o.SSHCAFile)
		add(o.SSHKRLFile)
		add(o.SSHKRLCAFile)
		add(o.SSHKRLStateFile)
	}
	for _, b := range c.Serves {
		add(b.ClientCAFile)
		add(b.CRLFile)
		add(b.CRLCAFile)
		add(b.CRLStateFile)
	}
	if c.Kerberos != nil {
		add(c.Kerberos.Keytab)
	}
	for _, u := range c.Users {
		add(u.PasswordFile)
	}
	return out
}

// checkNoShareHoldsSecrets refuses a directory share, or an image, that is
// or contains one of protectedPaths.
func (c *config) checkNoShareHoldsSecrets(blocks []shareBlock) error {
	protected := map[string]string{}
	for _, p := range c.protectedPaths() {
		if abs, err := filepath.Abs(p); err == nil {
			if real, err := filepath.EvalSymlinks(abs); err == nil {
				abs = real
			} else if dir, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
				abs = filepath.Join(dir, filepath.Base(abs)) // not created yet
			}
			protected[abs] = p
		}
	}
	for _, b := range blocks {
		src := b.source()
		real, err := filepath.EvalSymlinks(src)
		if err != nil {
			continue // opening it will say why
		}
		for abs, orig := range protected {
			rel, err := filepath.Rel(real, abs)
			if err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))) {
				return fmt.Errorf("share %q (%s) holds %s: whoever may write into it would rewrite this server's configuration or keys",
					b.Name, src, orig)
			}
		}
	}
	return nil
}
