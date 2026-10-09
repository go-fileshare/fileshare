// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"net"
	"slices"
)

// The admin API over HTTPS, for the UIs (docs/ui.md):
//
//	admin {
//	  listen     = "unix:///run/fileshare/admin.sock"
//	  state_file = "/var/lib/fileshare/shares.json"
//	  web {
//	    listen = "0.0.0.0:8443"
//	    issuer "https://login.example.org" {
//	      audience = "fileshare-a"                 # what THIS server is called there
//	      groups   = ["fileshare-admins"]
//	    }
//	    issuer "https://idp.partner.example" {
//	      audience = "fileshare-a.partner"
//	      subjects = ["5b0c…"]                     # by sub: a person is (issuer, sub)
//	    }
//	  }
//	}
//
// The same service as on the socket, answered in Connect, gRPC-Web and gRPC on
// one listener, with the certificate of the tls block. A call carries an OIDC
// bearer token; it is answered when one issuer's verifier accepts the token
// -- signature, "iss", an "aud" naming this server, times -- AND that issuer's
// block names the token's subject or one of its groups. Each server has its
// own audience: a token addressed to several could be replayed by any of them
// to the others (RFC 8707 §1, RFC 9068 §4).
type adminWebBlock struct {
	Listen  string           `hcl:"listen"`
	Issuers []adminWebIssuer `hcl:"issuer,block"`
}

type adminWebIssuer struct {
	Issuer      string   `hcl:"issuer,label"`
	Audience    string   `hcl:"audience"`
	JWKSURL     string   `hcl:"jwks_url,optional"`
	GroupsClaim string   `hcl:"groups_claim,optional"`
	Subjects    []string `hcl:"subjects,optional"`
	Groups      []string `hcl:"groups,optional"`
}

// check refuses what could not work or would let in more than it says.
func (w *adminWebBlock) check(haveTLS bool) error {
	if _, _, err := net.SplitHostPort(w.Listen); err != nil {
		return fmt.Errorf("web: listen %q is not an address: %w", w.Listen, err)
	}
	if !haveTLS {
		// ⛔ A bearer token is as good as a password: never in the clear.
		return fmt.Errorf("web: the admin API over HTTPS needs the tls block's certificate, and there is no tls block")
	}
	if len(w.Issuers) == 0 {
		return fmt.Errorf("web: no issuer block: no token could ever be accepted")
	}
	var seen []string
	for _, i := range w.Issuers {
		if slices.Contains(seen, i.Issuer) {
			return fmt.Errorf("web: issuer %q is given twice", i.Issuer)
		}
		seen = append(seen, i.Issuer)
		if i.Audience == "" {
			return fmt.Errorf("web: issuer %q has no audience: a token minted for another service would be accepted here", i.Issuer)
		}
		if len(i.Subjects) == 0 && len(i.Groups) == 0 {
			return fmt.Errorf("web: issuer %q names no subject and no group: nobody it vouches for could call", i.Issuer)
		}
	}
	return nil
}
