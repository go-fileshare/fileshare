// SPDX-License-Identifier: BSD-3-Clause

//go:build !nogrpc && !nowebdav

package main

import (
	"context"
	"fmt"
	"os"
	"testing"

	adminv1 "github.com/go-fileshare/fileshare/proto/fileshare/admin/v1"
	"google.golang.org/grpc/codes"
)

// The admin API is held to the same rule as the files: a share it creates
// may not lie inside a configured directory share, nor hold one, nor be its
// source again -- and the refusal writes nothing down. The control is a
// sibling tree, which is created.
func TestAnAPIShareInsideAnotherShareIsRefused(t *testing.T) {
	dir := t.TempDir()
	roots := mkdir(t, dir, "roots")
	pub := mkdir(t, roots, "pub")
	inner := mkdir(t, pub, "private")
	m := startManaged(t, dir, fmt.Sprintf("share \"pub\" { directory = %q }\n", hclPath(pub)))
	ctx := context.Background()
	stateBefore, _ := os.ReadFile(m.state)
	create := func(name, tree string) error {
		_, err := m.client.CreateShare(ctx, &adminv1.CreateShareRequest{Name: name,
			Source: &adminv1.CreateShareRequest_Directory{Directory: tree},
			Grants: []*adminv1.Grant{grantOf(userSubject("alice"), adminv1.Access_ACCESS_WRITE)}})
		return err
	}
	for name, tree := range map[string]string{"inner": inner, "outer": roots, "again": pub} {
		wantCode(t, create(name, tree), codes.FailedPrecondition)
		if m.srv.shareByName(name) != nil {
			t.Errorf("%s: the refused share is served", name)
		}
	}
	if got, _ := os.ReadFile(m.state); string(got) != string(stateBefore) {
		t.Fatal("a refused CreateShare was written down")
	}
	if err := create("beside", mkdir(t, roots, "beside")); err != nil {
		t.Fatalf("CONTROL: a sibling tree was refused: %v", err)
	}
}
