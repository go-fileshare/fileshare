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
	if name != user {
		return nil, fmt.Errorf("logging in as %q with a PK Token for %q", user, name)
	}
	return marked(groupsOf(claims[f.groupClm])), nil
}
