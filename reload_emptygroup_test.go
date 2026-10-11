package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/go-authn/directory"
)

// A reload is forgiving about groups that grant nothing: one deleted, one
// emptied. Each is a note, never a failed reload -- that is an outage's
// answer. go-authn/directory v0.12.0 reports an emptied group as
// ErrEmptyGroup rather than ErrNoSuchGroup; without its own case here, one
// group emptied in LDAP failed the whole reload.
func TestAReloadToleratesAGroupThatGrantsNothing(t *testing.T) {
	dir := directory.NewSet(&directory.Static{Groups: map[string][]string{
		"empty": {},
		"staff": {"alice"},
	}})
	people := map[string]*directory.Identity{"alice": directory.NewIdentity("alice")}
	var notes []string
	got, err := tolerantExpand(dir, people, &notes)([]string{"@gone", "@empty", "@staff", "alice"})
	if err != nil {
		t.Fatalf("the reload failed: %v", err)
	}
	//  gives alice, and alice is named again: tolerantExpand keeps both,
	// as Expand's caller deduplicates.
	if strings.Join(got, ",") != "alice,alice" {
		t.Errorf("expanded to %v", got)
	}
	for _, want := range []string{
		"group @gone no longer exists: it grants nothing",
		"group @empty has no members: it grants nothing",
	} {
		if !slices.Contains(notes, want) {
			t.Errorf("no note %q in %q", want, notes)
		}
	}
	// A start is not forgiving: the empty group is refused, and says why.
	if _, err := directory.Expand([]string{"@empty"}, dir); err == nil || !strings.Contains(err.Error(), "no members") {
		t.Errorf("a start would serve an empty group: %v", err)
	}
}
