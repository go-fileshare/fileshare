// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosftp

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-filesystems/sftp/sshd"
	"golang.org/x/crypto/ssh"
)

// People the identity provider vouches for, over SFTP. Two shapes of
// certificate carry its word, and neither needs an account here:
//
//   - one its SSH certificate authority signed (go-authn/bridge's ssh_ca):
//     the principal is the person, the groups@go-authn.org extension their
//     groups;
//   - an OpenPubkey one, as opkssh makes: signed by the user's own key, with
//     an ID token in the openpubkey-pkt extension that commits to that key.
//
// Both arrive through sshd's CertificateFor, which sees only certificates no
// LOCAL authority (trusted_user_ca_file) signed, after their signature,
// window and principals have been checked.

// federatedMark is the extension CertificateFor sets on the login's
// permissions so that ServerForLogin knows the provider spoke, and its
// value is a secret drawn when the process starts.
//
// ⛔ Not a constant: ServerForLogin is also handed the extensions of a
// certificate a LOCAL authority signed, and a certificate that carried
// federated@go-fileshare=1 would otherwise be read as the provider's word.
// No certificate can carry a value it was never told.
var federatedSecret = randomMark()

const (
	federatedMark = "federated@go-fileshare"
	issuedMark    = "issued@go-fileshare"
	expiresMark   = "expires@go-fileshare"
	issSubMark    = "iss-sub@go-fileshare"
	certMark      = "cert@go-fileshare"
	groupsMark    = "groups@go-fileshare"
	// bridgeGroups is the extension go-authn/bridge's certificates carry.
	bridgeGroups = "groups@go-authn.org"
	opksshPKT    = "openpubkey-pkt"
)

// federatedSFTP is what the oidc block says about SFTP.
type federatedSFTP struct {
	ca ssh.PublicKey // the provider's SSH CA, or nil
	// krl is the list of the provider's certificates it has revoked, when
	// the oidc block names one; see revocation.go.
	krl *revocationList
	// revoked is the shared signals check (caep.go): whether what the
	// provider issued to a person at a moment has been revoked since.
	revoked func(name, iss, sub string, issued time.Time) error
	opk     *opkVerifier
	// opkMaxAge is opkssh_max_age: an opkssh session ends this long after
	// its PK Token was issued, whatever the certificate says.
	opkMaxAge time.Duration
	userClm   string
	groupClm  string
}

func newFederatedSFTP(o *oidcBlock, krl *revocationList, revoked func(name, iss, sub string, issued time.Time) error) (*federatedSFTP, error) {
	if o == nil || (o.SSHCAFile == "" && o.OpksshClientID == "") {
		return nil, nil
	}
	f := &federatedSFTP{userClm: o.UsernameClaim, groupClm: o.GroupsClaim, krl: krl, revoked: revoked}
	if f.userClm == "" {
		f.userClm = "preferred_username"
	}
	if f.groupClm == "" {
		f.groupClm = "groups"
	}
	if o.SSHCAFile != "" {
		b, err := os.ReadFile(o.SSHCAFile)
		if err != nil {
			return nil, fmt.Errorf("the provider's SSH CA: %w", err)
		}
		keys, err := sshd.ParseAuthorizedKeys(b)
		if err != nil || len(keys) != 1 {
			return nil, fmt.Errorf("%s: one SSH CA key is expected", o.SSHCAFile)
		}
		f.ca = keys[0]
	}
	if o.OpksshClientID != "" {
		v, err := newOPK(o)
		if err != nil {
			return nil, err
		}
		f.opk = v
		f.opkMaxAge = opkMaxAge(o.OpksshMaxAge)
	}
	return f, nil
}

// certificate is sshd's CertificateFor.
func (f *federatedSFTP) certificate(user string, cert *ssh.Certificate) (*ssh.Permissions, error) {
	switch {
	case f.ca != nil && string(cert.SignatureKey.Marshal()) == string(f.ca.Marshal()):
		// sshd has checked the signature, the window and that user is among
		// the principals. A certificate with NO principals would be valid
		// for anybody (PROTOCOL.certkeys), and the provider's CA never
		// issues one; refused rather than read as a person.
		if len(cert.ValidPrincipals) == 0 {
			return nil, errors.New("a provider certificate with no principal")
		}
		if err := f.revokedCert(cert); err != nil {
			return nil, err
		}
		// Issued when its validity begins: bridge signs it then.
		issued := time.Unix(int64(cert.ValidAfter), 0)
		if err := f.revoked(user, "", "", issued); err != nil {
			return nil, err
		}
		var groups []string
		for _, g := range strings.Split(cert.Extensions[bridgeGroups], "\n") {
			if g != "" {
				groups = append(groups, g)
			}
		}
		perms := marked(groups)
		perms.Extensions[issuedMark] = fmt.Sprint(cert.ValidAfter)
		perms.Extensions[expiresMark] = fmt.Sprint(cert.ValidBefore)
		if f.krl != nil {
			// Carried to the session, so that a revocation arriving after
			// this login still reaches it; see unionFS.revoked.
			perms.Extensions[certMark] = base64.StdEncoding.EncodeToString(cert.Marshal())
		}
		return perms, nil
	case f.opk != nil && cert.Extensions[opksshPKT] != "":
		return f.openpubkey(user, cert)
	}
	return nil, errors.New("a certificate no trusted authority signed")
}

// groupsOf reads a groups claim that is a list, or -- as some providers send
// one group -- a string.
func groupsOf(raw json.RawMessage) []string {
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many
	}
	var one string
	if json.Unmarshal(raw, &one) == nil && one != "" {
		return []string{one}
	}
	return nil
}

// revokedCert is the KRL's answer about a certificate, and -- when the KRL is
// not known to be current -- a refusal: see revocation.go on failing closed.
func (f *federatedSFTP) revokedCert(cert *ssh.Certificate) error {
	if f.krl == nil {
		return nil
	}
	list, err := f.krl.get()
	if err != nil {
		return err
	}
	if list.(sshKRL).k.IsRevoked(cert) {
		return fmt.Errorf("certificate %d (%s) was revoked by the provider", cert.Serial, cert.KeyId)
	}
	return nil
}

// sessionRevoked is what an open session asks before each operation: the
// KRL, for a certificate the provider's CA signed, and the shared signals,
// for anything the provider vouched for.
func (f *federatedSFTP) sessionRevoked(user string, perms *ssh.Permissions) func() error {
	if f == nil || perms == nil || perms.Extensions[federatedMark] != federatedSecret {
		return nil
	}
	krl := f.certRevoked(perms)
	var issued time.Time
	if v, err := strconv.ParseInt(perms.Extensions[issuedMark], 10, 64); err == nil {
		issued = time.Unix(v, 0)
	}
	// The certificate's end, checked at every operation: SSH checks it at
	// login only, and an expired certificate leaves the provider's KRL, so
	// a session outliving it would outlive its revocation too.
	var expires uint64
	if v, err := strconv.ParseUint(perms.Extensions[expiresMark], 10, 64); err == nil {
		expires = v
	} else if raw, err := base64.StdEncoding.DecodeString(perms.Extensions[certMark]); err == nil && len(raw) > 0 {
		if key, err := ssh.ParsePublicKey(raw); err == nil {
			if cert, ok := key.(*ssh.Certificate); ok {
				expires = cert.ValidBefore
			}
		}
	}
	return func() error {
		if expires != 0 && expires != ssh.CertTimeInfinity && uint64(time.Now().Unix()) >= expires {
			return errors.New("the session's certificate has expired")
		}
		if krl != nil {
			if err := krl(); err != nil {
				return err
			}
		}
		iss, sub, _ := strings.Cut(perms.Extensions[issSubMark], " ")
		return f.revoked(user, iss, sub, issued)
	}
}

// certRevoked is the KRL's question for the session's certificate, or nil.
func (f *federatedSFTP) certRevoked(perms *ssh.Permissions) func() error {
	if f.krl == nil {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(perms.Extensions[certMark])
	if err != nil || len(raw) == 0 {
		return nil
	}
	key, err := ssh.ParsePublicKey(raw)
	cert, ok := key.(*ssh.Certificate)
	if err != nil || !ok {
		return func() error { return errors.New("the session's certificate could not be read back") }
	}
	return func() error { return f.revokedCert(cert) }
}

func marked(groups []string) *ssh.Permissions {
	return &ssh.Permissions{Extensions: map[string]string{
		federatedMark: federatedSecret,
		groupsMark:    strings.Join(groups, "\n"),
	}}
}

// principalOf is who a login is, from the permissions sshd hands over.
func principalOf(user string, perms *ssh.Permissions) principal {
	if perms == nil || perms.Extensions[federatedMark] != federatedSecret {
		return local(user)
	}
	p := principal{name: user, federated: true}
	for _, g := range strings.Split(perms.Extensions[groupsMark], "\n") {
		if g != "" {
			p.groups = append(p.groups, g)
		}
	}
	return p
}

func randomMark() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
