// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/hcldir"
)

// ⛔ This is the defect the shared block closes, stated as a test.
//
// The `user` block was declared here AND in go-authn/authnd, and the two had
// drifted: authnd's carried nt_hash and totp_secret, this one carried neither.
// canServeUser says SMB needs directory.NTHash and nothing else will do, so a
// person written inline in a fileshare configuration could not be served over
// SMB at all -- not because of a policy, but because the configuration had no
// word for what SMB needs.
//
// Both blocks are hcldir's now. This asserts the consequence rather than the
// refactor: the same person, written inline, is servable over SMB.
func TestAnInlineUserCanCarryTheHashSMBNeeds(t *testing.T) {
	src, err := hcldir.File([]hcldir.UserBlock{{
		Name:   "alice",
		NTHash: "8846f7eaee8fb117ad06bdd830b7586c",
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	people, err := src.Identities()
	if err != nil || len(people) != 1 {
		t.Fatalf("identities: %v", err)
	}
	alice := people[0]
	if !alice.Can(directory.NTHash) {
		t.Fatal("an inline user still cannot carry an NT hash")
	}
	if !canServeUser("smb", alice, nil) {
		t.Error("SMB still refuses a person written in the configuration file")
	}
	// And the neighbouring distinction still holds: an NT hash is not a
	// secret S3 can compute an HMAC from, so S3 must still refuse her.
	if canServeUser("s3", alice, nil) {
		t.Error("S3 accepted an identity holding only an NT hash: an HMAC " +
			"cannot be computed from an MD4, so this must refuse")
	}
}

// The other half of the drift: a one-time-code secret, which this block also
// had no word for.
func TestAnInlineUserCanCarryATOTPSecret(t *testing.T) {
	src, err := hcldir.File([]hcldir.UserBlock{{
		Name: "alice", TOTPSecret: "JBSWY3DPEHPK3PXP",
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	people, _ := src.Identities()
	if !people[0].Can(directory.TOTPSecret) {
		t.Error("an inline user still cannot carry a TOTP secret")
	}
}
