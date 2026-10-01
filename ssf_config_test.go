// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSSFSettings(t *testing.T) {
	withOIDC := &config{OIDC: &oidcBlock{Issuer: "https://idp", Audience: "fileshare"}}
	nothing := &config{}
	for _, c := range []struct {
		b    ssfBlock
		c    *config
		want string
	}{
		{ssfBlock{Transmitter: "https://bridge", Audience: "a", TokenFile: "/t", StateFile: "/s"}, withOIDC, ""},
		{ssfBlock{Transmitter: "http://bridge", Audience: "a", TokenFile: "/t", StateFile: "/s"}, withOIDC, "over https"},
		{ssfBlock{Transmitter: "https://bridge", TokenFile: "/t", StateFile: "/s"}, withOIDC, "no audience"},
		{ssfBlock{Transmitter: "https://bridge", Audience: "a", StateFile: "/s"}, withOIDC, "authenticates, once"},
		{ssfBlock{Transmitter: "https://bridge", Audience: "a", TokenFile: "/t", ClientID: "x", ClientSecretFile: "/c", StateFile: "/s"}, withOIDC, "authenticates, once"},
		{ssfBlock{Transmitter: "https://bridge", Audience: "a", ClientID: "x", ClientSecretFile: "/c", StateFile: "/s"}, withOIDC, ""},
		{ssfBlock{Transmitter: "https://bridge", Audience: "a", ClientID: "x", StateFile: "/s"}, withOIDC, "go together"},
		{ssfBlock{Transmitter: "https://bridge", Audience: "a", ClientID: "x", ClientSecretFile: "/c", TokenURL: "http://t", StateFile: "/s"}, withOIDC, "in the clear"},
		{ssfBlock{Transmitter: "https://bridge", Audience: "a", TokenFile: "/t"}, withOIDC, "state_file is required"},
		{ssfBlock{Transmitter: "https://bridge", Audience: "a", TokenFile: "/t", StateFile: "/s"}, nothing, "nothing here serves"},
		{ssfBlock{Transmitter: "https://bridge", Audience: "a", TokenFile: "/t", StateFile: "/s", MaxAge: "1s"}, withOIDC, "a minute or more"},
		{ssfBlock{Transmitter: "https://bridge", Audience: "a", TokenFile: "/t", StateFile: "/s", MaxAge: "1m"}, withOIDC, ""},
		{ssfBlock{Transmitter: "https://bridge", Audience: "a", TokenFile: "/t", StateFile: "/s", Retain: "5m"}, withOIDC, "shorter than 169h"},
		{ssfBlock{Transmitter: "https://bridge", Audience: "a", TokenFile: "/t", StateFile: "/s", Retain: "169h"}, withOIDC, ""},
	} {
		err := c.b.check(c.c)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%+v refused: %v", c.b, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%+v: %v, want %q", c.b, err, c.want)
		}
	}
}

// An IdP revoked whole at the provider: a tenant subject, its scopes in the
// event -- everyone @ one of them, issued before, is void; others are not.
func TestAnInstitutionRevokedByScope(t *testing.T) {
	revokedAt := time.Now().Add(-time.Minute).Truncate(time.Second)
	payload := []byte(fmt.Sprintf(`{"iss":"https://b","aud":"https://f","iat":%d,"jti":"j",
	  "sub_id":{"tenant":{"format":"opaque","id":"https://idp.univ-a.fr/idp/shibboleth"}},
	  "events":{"https://schemas.openid.net/secevent/caep/event-type/session-revoked":
	    {"event_timestamp":%d,"scopes":["univ-a.fr","UNIV-A.EU"]}}}`, time.Now().Unix(), revokedAt.Unix()))
	keys, at, err := parseRevocation(payload, "https://b", "https://f")
	if err != nil || !at.Equal(revokedAt) || !slices.Equal(keys, []string{"scope:univ-a.fr", "scope:univ-a.eu"}) {
		t.Fatalf("%v %v %v", keys, at, err)
	}
	st, _ := openRevocationStore(filepath.Join(t.TempDir(), "r.json"), time.Hour, time.Hour)
	st.heardFrom()
	if err := st.revoke(keys, at); err != nil {
		t.Fatal(err)
	}
	before, after := revokedAt.Add(-time.Minute), revokedAt.Add(time.Second)
	if st.check("alice@univ-a.fr", "", "", before) == nil {
		t.Error("someone @univ-a.fr issued before was not revoked")
	}
	if st.check("carol@UNIV-A.EU", "", "", before) == nil {
		t.Error("the scope comparison is case-sensitive")
	}
	if st.check("alice@univ-a.fr", "", "", after) != nil {
		t.Error("someone @univ-a.fr issued after was revoked")
	}
	if st.check("bob@univ-b.fr", "", "", before) != nil {
		t.Error("another institution was revoked")
	}
	if st.check("mallory@evil-univ-a.fr", "", "", before) != nil {
		t.Error("a scope matched a longer domain ending in it")
	}
	// No scope: nothing to name its people by, refused rather than ignored.
	if _, _, err := parseRevocation([]byte(`{"iss":"https://b","aud":"https://f","iat":1,
	  "sub_id":{"tenant":{"format":"opaque","id":"x"}},
	  "events":{"https://schemas.openid.net/secevent/caep/event-type/session-revoked":{}}}`), "https://b", "https://f"); err == nil {
		t.Error("an institution with no scope was accepted")
	}
}
