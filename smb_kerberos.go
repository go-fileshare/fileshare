// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosmb

package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-filesystems/smb"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Kerberos for SMB: the same kerberos block as NFS, the same userOf, the same
// people.
//
// ONE keytab holds both services. NFS asks go-authn/krb5 for "any principal in
// the keytab"; SMB asks for the cifs/<host> ones only, so a ticket made for
// nfs/<host> is not accepted by the SMB port (and the other way round, where
// NFS is concerned, is the existing behaviour). A keytab with no cifs/ principal
// for the block's realm is a deployment that has not opted into SMB Kerberos:
// SMB stays NTLM-only, and says so once.
//
// ⛔ Why this is not go-authn/krb5 like NFS: SMB needs the context key (it is
// Session.SessionKey, [MS-SMB2] 3.3.5.5.3 step 6) and the acceptor does not
// export it; go-authn/krb5#22 asks for that. Until it does, this verifies the
// AP-REQ with gokrb5 itself and carries go-authn/krb5's one guard, checkCipher,
// which it cannot do without: gokrb5 PANICS on a ticket whose cipher is shorter
// than a confounder and a checksum, from an unauthenticated caller.

// smbAcceptor is an smb.Acceptor over a keytab.
type smbAcceptor struct {
	kt         *keytab.Keytab
	principals []string // cifs/<host>, without the realm
	k          *kerberosBlock
	known      func(user string) bool
}

// cifsPrincipals are the cifs/<host> service principals of the block's realm
// that the keytab holds a key for.
func cifsPrincipals(kt *keytab.Keytab, realm string) []string {
	var out []string
	for _, e := range kt.Entries {
		p := e.Principal
		if p.Realm != realm || len(p.Components) != 2 || p.Components[0] != "cifs" {
			continue
		}
		name := strings.Join(p.Components, "/")
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// newSMBAcceptor reads the block's keytab. It returns nil, nil for a keytab
// that holds no cifs/ principal of the realm: that is NFS-only, not an error.
func newSMBAcceptor(k *kerberosBlock, known func(string) bool) (*smbAcceptor, error) {
	if err := checkKeytabMode(k.Keytab); err != nil {
		return nil, err
	}
	kt, err := keytab.Load(k.Keytab)
	if err != nil {
		return nil, fmt.Errorf("kerberos keytab %s: %w", k.Keytab, err)
	}
	ps := cifsPrincipals(kt, k.Realm)
	if len(ps) == 0 {
		return nil, nil
	}
	return &smbAcceptor{kt: kt, principals: ps, k: k, known: known}, nil
}

// Accept implements smb.Acceptor.
//
// The answer a stranger gets is one refusal whatever refused it; the reason is
// in the error, which the SMB server logs at debug level and sends nowhere.
func (a *smbAcceptor) Accept(token []byte) (*smb.Accepted, []byte, error) {
	var tok spnego.KRB5Token
	if err := tok.Unmarshal(token); err != nil {
		return nil, nil, fmt.Errorf("not a Kerberos token: %w", err)
	}
	if !tok.IsAPReq() {
		return nil, nil, errors.New("the token is not an AP-REQ")
	}
	req := &tok.APReq
	if err := checkCipher("the ticket", req.Ticket.EncPart); err != nil {
		return nil, nil, err
	}
	if err := checkCipher("the authenticator", req.EncryptedAuthenticator); err != nil {
		return nil, nil, err
	}
	// gokrb5 picks the service key by the ticket's CLEARTEXT realm, so a
	// cifs/<host>@OTHER key sharing this keytab would otherwise decrypt it
	// although cifsPrincipals kept only this realm's names.
	if req.Ticket.Realm != a.k.Realm {
		return nil, nil, fmt.Errorf("the ticket is for realm %q, not %q", req.Ticket.Realm, a.k.Realm)
	}
	verified := false
	var lastErr error
	for _, p := range a.principals {
		ok, _, err := service.VerifyAPREQ(req, service.NewSettings(a.kt,
			service.KeytabPrincipal(p), service.DecodePAC(false)))
		if err == nil && ok {
			verified = true
			break
		}
		lastErr = err
	}
	if !verified {
		return nil, nil, fmt.Errorf("ticket rejected: %w", errors.Join(errors.New("no cifs principal of this keytab accepts it"), lastErr))
	}
	// ⛔ WHO the client is comes from the ticket, which the KDC sealed with our
	// key, never from the authenticator, which the client writes. gokrb5 v8.4.4
	// builds its credentials from the authenticator (service/APExchange.go) and
	// compares only its NAME with the ticket's (messages/APReq.go Verify), so a
	// partner realm's alice with a genuine cross-realm ticket could name our
	// realm and pass userOf. RFC 4120 3.2.3: name and realm are compared,
	// KRB_AP_ERR_BADMATCH otherwise. Same fix as go-authn/krb5 v0.3.4.
	tp := req.Ticket.DecryptedEncPart
	if req.Authenticator.CRealm != tp.CRealm || !req.Authenticator.CName.Equal(tp.CName) {
		return nil, nil, errors.New("the authenticator names another client than the ticket")
	}
	if tp.CName.PrincipalNameString() == "" || tp.CRealm == "" {
		return nil, nil, errors.New("the ticket names no client")
	}
	principal := tp.CName.PrincipalNameString() + "@" + tp.CRealm
	// The same mapping NFS makes, with its refusal of another realm, and then
	// the question NTLM asks without being able to skip it: is this somebody
	// this server knows? A ticket proves the KDC knows the person, not that this
	// configuration does, and a share open to everyone who authenticates would
	// otherwise be open to everybody the realm holds.
	user := a.k.userOf(principal)
	if user == "" {
		return nil, nil, fmt.Errorf("%s is not in realm %s", principal, a.k.Realm)
	}
	if !a.known(user) {
		return nil, nil, fmt.Errorf("%s maps to %q, whom this server does not know", principal, user)
	}

	key := req.Ticket.DecryptedEncPart.Key
	if k := req.Authenticator.SubKey; k.KeyType != 0 && len(k.KeyValue) > 0 {
		key = k
	}
	expires := req.Ticket.DecryptedEncPart.EndTime
	if !mutualRequired(req.APOptions) {
		return &smb.Accepted{User: user, Principal: principal, Key: key.KeyValue, Expires: expires}, nil, nil
	}
	// The AP-REP carries a subkey of the acceptor's, which is then the context
	// key: RFC 4121 section 2, and [MS-KILE] 3.1.1.2 says the AP-REP's subkey is
	// the session key when mutual authentication is asked (and, with AES, that
	// the AP-REQ's is not).
	sub, err := newSubkey(key)
	if err != nil {
		return nil, nil, err
	}
	rep, err := apRep(req, sub)
	if err != nil {
		return nil, nil, err
	}
	return &smb.Accepted{User: user, Principal: principal, Key: sub.KeyValue, Expires: expires}, rep, nil
}

// mutualRequired reads the AP-REQ option bit (RFC 4120 section 5.5.1:
// reserved(0), use-session-key(1), mutual-required(2)).
func mutualRequired(o asn1.BitString) bool { return o.At(2) == 1 }

// newSubkey draws a key of the same encryption type as the one it stands beside.
func newSubkey(like types.EncryptionKey) (types.EncryptionKey, error) {
	et, err := crypto.GetEtype(like.KeyType)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("encryption type %d: %w", like.KeyType, err)
	}
	return types.GenerateEncryptionKey(et)
}

// apRep is the AP-REP of RFC 4120 section 5.5.2, in its GSS-API framing: the
// client's own timestamp, proof that the service holds the key, sealed with the
// ticket's session key, and the acceptor's subkey. gokrb5 reads an AP-REP and
// refuses to write one.
func apRep(req *messages.APReq, sub types.EncryptionKey) ([]byte, error) {
	enc := messages.EncAPRepPart{
		CTime:          req.Authenticator.CTime,
		Cusec:          req.Authenticator.Cusec,
		Subkey:         sub,
		SequenceNumber: int64(time.Now().UnixNano() & 0x3fffffff),
	}
	eb, err := asn1.Marshal(enc)
	if err != nil {
		return nil, fmt.Errorf("marshalling EncAPRepPart: %w", err)
	}
	eb = asn1tools.AddASNAppTag(eb, asnAppTag.EncAPRepPart)
	ed, err := crypto.GetEncryptedData(eb, req.Ticket.DecryptedEncPart.Key, keyusage.AP_REP_ENCPART, 0)
	if err != nil {
		return nil, fmt.Errorf("encrypting EncAPRepPart: %w", err)
	}
	rb, err := asn1.Marshal(messages.APRep{PVNO: iana.PVNO, MsgType: msgtype.KRB_AP_REP, EncPart: ed})
	if err != nil {
		return nil, fmt.Errorf("marshalling AP-REP: %w", err)
	}
	rb = asn1tools.AddASNAppTag(rb, asnAppTag.APREP)
	oid, err := asn1.Marshal(gssapi.OIDKRB5.OID())
	if err != nil {
		return nil, err
	}
	return asn1tools.AddASNAppTag(append(append(oid, 0x02, 0x00), rb...), 0), nil
}

// checkCipher refuses an EncryptedData whose cipher is too short to be one.
//
// ⛔ Copied from go-authn/krb5 (cipherlen.go), not invented here: gokrb5's
// DecryptMessage slices a checksum off the end and a confounder off the front
// without checking either is there, so a cipher of three bytes panics, before
// any key is checked, from an unauthenticated caller. Fixed upstream in
// jcmturner/gokrb5#580, not released; remove this when go-authn/krb5#22 lets SMB
// use that package's acceptor.
func checkCipher(what string, ed types.EncryptedData) error {
	et, err := crypto.GetEtype(ed.EType)
	if err != nil {
		return fmt.Errorf("%s uses encryption type %d: %w", what, ed.EType, err)
	}
	if min := et.GetConfounderByteSize() + et.GetHMACBitLength()/8; len(ed.Cipher) < min {
		return fmt.Errorf("%s carries %d cipher bytes, fewer than the %d a message of type %d needs",
			what, len(ed.Cipher), min, ed.EType)
	}
	return nil
}
