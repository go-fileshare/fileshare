// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosftp && !noopenpubkey

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/verifier"
	"golang.org/x/crypto/ssh"
)

// OpenPubkey (opkssh) logins. `-tags noopenpubkey` leaves this out, with
// the openpubkey library and about 2 MB of binary.

var opksshPolicies = map[string]*verifier.ExpirationPolicy{
	"12h":   &verifier.ExpirationPolicies.MAX_AGE_12HOURS,
	"24h":   &verifier.ExpirationPolicies.MAX_AGE_24HOURS,
	"48h":   &verifier.ExpirationPolicies.MAX_AGE_48HOURS,
	"1week": &verifier.ExpirationPolicies.MAX_AGE_1WEEK,
}

// haveOpenPubkey says this binary can check opkssh logins.
const haveOpenPubkey = true

func knownMaxAge(s string) bool { return opksshPolicies[s] != nil }

// opksshMaxAges are the same policies as durations: how long after the
// provider issued it a PK Token is honoured -- at login by the verifier, and
// for the rest of the session by sessionRevoked.
var opksshMaxAges = map[string]time.Duration{
	"12h": 12 * time.Hour, "24h": 24 * time.Hour, "48h": 48 * time.Hour, "1week": 7 * 24 * time.Hour,
}

// opkMaxAge is opkssh_max_age as a duration, 24h when it is not written --
// the verifier's default in newOPK.
func opkMaxAge(s string) time.Duration {
	if d, ok := opksshMaxAges[s]; ok {
		return d
	}
	return opksshMaxAges["24h"]
}

type opkVerifier = verifier.Verifier

func newOPK(o *oidcBlock) (*opkVerifier, error) {
	policy := opksshPolicies["24h"]
	if o.OpksshMaxAge != "" {
		policy = opksshPolicies[o.OpksshMaxAge]
	}
	op := providers.NewStandardOpWithOptions(&providers.StandardOpOptions{
		Issuer: o.Issuer, ClientID: o.OpksshClientID,
	})
	return verifier.New(op, verifier.WithExpirationPolicy(*policy))
}

// openpubkey checks an opkssh certificate as opkssh verify does -- the PK
// Token by the openpubkey verifier (the provider's signature against its
// published keys, the nonce commitment, the client ID, the age), and the
// certificate's key against the key the token commits to -- and one thing
// more: the SSH user name must be the token's username, because this
// server has no auth_id file to map one to the other.
func (f *federatedSFTP) openpubkey(user string, cert *ssh.Certificate) (*ssh.Permissions, error) {
	pkt, err := pktoken.NewFromCompact([]byte(cert.Extensions[opksshPKT]))
	if err != nil {
		return nil, fmt.Errorf("the openpubkey-pkt extension: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := f.opk.VerifyPKToken(ctx, pkt); err != nil {
		return nil, fmt.Errorf("the PK Token: %w", err)
	}
	cic, err := pkt.GetCicValues()
	if err != nil {
		return nil, err
	}
	upk, err := jwk.Import(cic.PublicKey())
	if err != nil {
		return nil, err
	}
	ck, ok := cert.Key.(ssh.CryptoPublicKey)
	if !ok {
		return nil, errors.New("the certificate's key cannot be compared")
	}
	certKey, err := jwk.Import(ck.CryptoPublicKey())
	if err != nil {
		return nil, err
	}
	if !jwk.Equal(certKey, upk) {
		return nil, errors.New("the certificate's key is not the one the PK Token commits to")
	}
	// The opkssh shape is signed by the key it certifies; anything else is
	// not an opkssh certificate.
	if string(cert.SignatureKey.Marshal()) != string(cert.Key.Marshal()) {
		return nil, errors.New("an OpenPubkey certificate signed by another key")
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return nil, err
	}
	var name string
	if err := json.Unmarshal(claims[f.userClm], &name); err != nil || name == "" {
		return nil, fmt.Errorf("the PK Token carries no %s", f.userClm)
	}
	// An email names somebody only once verified (OpenID Connect Core 5.1):
	// as for a token over WebDAV (oidcauth.go).
	var verified bool
	if f.userClm == "email" && (json.Unmarshal(claims["email_verified"], &verified) != nil || !verified) {
		return nil, fmt.Errorf("the PK Token names %s by an email its provider has not verified", name)
	}
	if name != user {
		return nil, fmt.Errorf("logging in as %q with a PK Token for %q", user, name)
	}
	// The ID token inside is what the provider issued, and when: a person
	// revoked since then is refused, whatever opkssh_max_age still allows.
	var iat, iss, sub json.RawMessage = claims["iat"], claims["iss"], claims["sub"]
	var issuedAt int64
	var issS, subS string
	json.Unmarshal(iat, &issuedAt)
	json.Unmarshal(iss, &issS)
	json.Unmarshal(sub, &subS)
	issued := time.Time{}
	if issuedAt > 0 {
		issued = time.Unix(issuedAt, 0)
	}
	if err := f.revoked(user, issS, subS, issued); err != nil {
		return nil, err
	}
	perms := marked(groupsOf(claims[f.groupClm]))
	if issuedAt > 0 {
		perms.Extensions[issuedMark] = fmt.Sprint(issuedAt)
	}
	// ⛔ The session ends when the PK Token ages out, or when the certificate
	// does, whichever is first. ValidBefore alone is no bound: the person
	// signs this certificate with their OWN key and may write "forever", and
	// a session opened a minute before opkssh_max_age was served for as long
	// as the connection lasted.
	if issuedAt <= 0 {
		return nil, errors.New("the PK Token carries no iat: how old it is cannot be known")
	}
	end := uint64(time.Unix(issuedAt, 0).Add(f.opkMaxAge).Unix())
	if cert.ValidBefore < end {
		end = cert.ValidBefore
	}
	perms.Extensions[expiresMark] = fmt.Sprint(end)
	if issS != "" && subS != "" {
		perms.Extensions[issSubMark] = issS + " " + subS
	}
	return perms, nil
}
