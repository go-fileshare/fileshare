// SPDX-License-Identifier: BSD-3-Clause

package account

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/go-authn/directory"
)

func person(t *testing.T, name string, groups []string, attrs ...directory.Attribute) *directory.Identity {
	t.Helper()
	a, err := directory.NewAttributes(attrs...)
	if err != nil {
		t.Fatal(err)
	}
	return directory.NewIdentity(name, directory.WithAttributes(a), directory.WithGroups(groups...))
}

func ids(uid, gid string) []directory.Attribute {
	return []directory.Attribute{{Name: "uidNumber", Values: []string{uid}}, {Name: "gidNumber", Values: []string{gid}}}
}

// resolver over a fixed directory and a fixed passwd.
func resolver(people map[string]*directory.Identity, groups map[string]uint32, passwd map[string][3]any) *Resolver {
	return &Resolver{
		Find: func(name string) (*directory.Identity, error) {
			if name == "broken" {
				return nil, errors.New("ldap down")
			}
			return people[name], nil
		},
		GroupGID: func(g string) (uint32, bool, error) {
			if g == "@broken" {
				return 0, false, errors.New("ldap down")
			}
			n, ok := groups[g]
			return n, ok, nil
		},
		Passwd: func(name string) (uint32, uint32, []uint32, error) {
			p, ok := passwd[name]
			if !ok {
				return 0, 0, nil, ErrNoAccount
			}
			if err, isErr := p[0].(error); isErr {
				return 0, 0, nil, err
			}
			return p[0].(uint32), p[1].(uint32), p[2].([]uint32), nil
		},
		Policy: DefaultPolicy,
	}
}

func TestFromTheDirectory(t *testing.T) {
	r := resolver(map[string]*directory.Identity{
		"alice": person(t, "alice", []string{"@staff", "@wheelish", "@nogid", "@staff2"}, ids("1001", "1001")...),
	}, map[string]uint32{"@staff": 2000, "@wheelish": 10, "@staff2": 2000}, nil)
	a, err := r.Resolve("alice")
	if err != nil {
		t.Fatal(err)
	}
	// The primary is in Groups; a group with no gidNumber is no system group;
	// one below min_gid is dropped, and said; duplicates go.
	if a.UID != 1001 || a.GID != 1001 || fmt.Sprint(a.Groups) != "[1001 2000]" || fmt.Sprint(a.Dropped) != "[10]" || a.From != "the directory" {
		t.Fatalf("%+v", a)
	}
}

// The directory first; /etc/passwd only for a person it has no numbers for.
func TestOrder(t *testing.T) {
	r := resolver(map[string]*directory.Identity{
		"alice": person(t, "alice", nil, ids("1001", "1001")...),
		"bob":   person(t, "bob", nil, directory.Attribute{Name: "mail", Values: []string{"b@x"}}),
	}, nil, map[string][3]any{
		"alice": {uint32(5000), uint32(5000), []uint32(nil)},
		"bob":   {uint32(1002), uint32(1002), []uint32{3000}},
		"carol": {uint32(1003), uint32(1003), []uint32(nil)},
	})
	for name, want := range map[string]string{
		"alice": "1001 the directory", // passwd has her too, and is not asked
		"bob":   "1002 /etc/passwd",   // in the directory, without numbers
		"carol": "1003 /etc/passwd",   // not in the directory at all
	} {
		a, err := r.Resolve(name)
		if err != nil || fmt.Sprintf("%d %s", a.UID, a.From) != want {
			t.Errorf("%s: %+v %v", name, a, err)
		}
	}
	if _, err := r.Resolve("dave"); !errors.Is(err, ErrNoAccount) {
		t.Errorf("nobody: %v", err)
	}
	// Without a directory, or without a passwd, the other one answers alone.
	r.Find = nil
	if a, err := r.Resolve("alice"); err != nil || a.UID != 5000 {
		t.Errorf("no directory: %+v %v", a, err)
	}
	r.Passwd = nil
	if _, err := r.Resolve("alice"); !errors.Is(err, ErrNoAccount) {
		t.Errorf("neither: %v", err)
	}
}

// A half-configured account is an error, never a guess.
func TestBadDirectoryNumbers(t *testing.T) {
	people := map[string]*directory.Identity{
		"onlyuid":  person(t, "onlyuid", nil, directory.Attribute{Name: "uidNumber", Values: []string{"1001"}}),
		"onlygid":  person(t, "onlygid", nil, directory.Attribute{Name: "gidNumber", Values: []string{"1001"}}),
		"twouids":  person(t, "twouids", nil, directory.Attribute{Name: "uidNumber", Values: []string{"1001", "1002"}}, directory.Attribute{Name: "gidNumber", Values: []string{"1001"}}),
		"letters":  person(t, "letters", nil, ids("abc", "1001")...),
		"negative": person(t, "negative", nil, ids("-1", "1001")...),
		"toobig":   person(t, "toobig", nil, ids("4294967296", "1001")...),
		"badgroup": person(t, "badgroup", []string{"@broken"}, ids("1001", "1001")...),
	}
	r := resolver(people, nil, map[string][3]any{"onlyuid": {uint32(1001), uint32(1001), []uint32(nil)}})
	for name := range people {
		a, err := r.Resolve(name)
		if err == nil || errors.Is(err, ErrNoAccount) {
			t.Errorf("%s: %+v, %v", name, a, err)
		}
	}
	if _, err := r.Resolve("broken"); err == nil || !strings.Contains(err.Error(), "ldap down") {
		t.Errorf("a directory that fails: %v", err)
	}
	r = resolver(nil, nil, map[string][3]any{"x": {errors.New("disk on fire")}})
	if _, err := r.Resolve("x"); err == nil || errors.Is(err, ErrNoAccount) || !strings.Contains(err.Error(), "/etc/passwd") {
		t.Errorf("a passwd that fails: %v", err)
	}
}

// What the policy refuses, and what it refuses whatever it says.
func TestPolicy(t *testing.T) {
	for name, c := range map[string]struct {
		uid, gid string
		p        Policy
	}{
		"root":                 {"0", "1001", Policy{}},
		"root group":           {"1001", "0", Policy{}},
		"uid -1 (leave as is)": {"4294967295", "1001", Policy{}},
		"gid -1 (leave as is)": {"1001", "4294967295", Policy{}},
		"below min_uid":        {"999", "1001", DefaultPolicy},
		"below min_gid":        {"1001", "100", DefaultPolicy},
		"denied":               {"1001", "1001", Policy{DenyUIDs: []uint32{1001}}},
	} {
		r := resolver(map[string]*directory.Identity{"x": person(t, "x", nil, ids(c.uid, c.gid)...)}, nil, nil)
		r.Policy = c.p
		if a, err := r.Resolve("x"); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %+v, %v", name, a, err)
		}
	}
	// A site whose people are in gid 100 sets min_gid: it is a setting.
	r := resolver(map[string]*directory.Identity{"x": person(t, "x", nil, ids("1001", "100")...)}, nil, nil)
	r.Policy = Policy{MinUID: 1000, MinGID: 100}
	if a, err := r.Resolve("x"); err != nil || a.GID != 100 {
		t.Errorf("min_gid 100: %+v %v", a, err)
	}
	// Supplementary 0 and -1 are dropped even when min_gid would let them in.
	r = resolver(map[string]*directory.Identity{"x": person(t, "x", []string{"@root", "@minus", "@ok"}, ids("1001", "1001")...)},
		map[string]uint32{"@root": 0, "@minus": 4294967295, "@ok": 5}, nil)
	r.Policy = Policy{}
	if a, err := r.Resolve("x"); err != nil || !slices.Equal(a.Groups, []uint32{5, 1001}) || !slices.Equal(a.Dropped, []uint32{0, 4294967295}) {
		t.Errorf("supplementary 0 and -1: %+v %v", a, err)
	}
}

// SystemPasswd against this machine's own account, and one that is not there.
func TestSystemPasswd(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		t.Skip("no /etc/passwd")
	}
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	uid, gid, groups, err := SystemPasswd(me.Username)
	if err != nil {
		t.Fatal(err)
	}
	if uid != uint32(os.Getuid()) || gid != uint32(os.Getgid()) || len(groups) == 0 {
		t.Fatalf("%d %d %v", uid, gid, groups)
	}
	if _, _, _, err := SystemPasswd("no-such-user-for-fileshare-tests"); !errors.Is(err, ErrNoAccount) {
		t.Fatalf("an unknown name: %v", err)
	}
}

// A directory that cannot say a group's gid: the person runs with the
// primary group alone.
func TestNoGroupGIDs(t *testing.T) {
	r := resolver(map[string]*directory.Identity{"x": person(t, "x", []string{"@staff"}, ids("1001", "1001")...)}, nil, nil)
	r.GroupGID = nil
	if a, err := r.Resolve("x"); err != nil || !slices.Equal(a.Groups, []uint32{1001}) {
		t.Fatalf("%+v %v", a, err)
	}
}

// A group can name the person (memberUid, a configuration's group block) as
// well as the person naming the group (memberOf): both make a supplementary
// group, once each.
func TestMemberOf(t *testing.T) {
	r := resolver(map[string]*directory.Identity{
		"alice": person(t, "alice", []string{"@staff"}, ids("1001", "1001")...),
	}, map[string]uint32{"@staff": 2000, "@lab": 3000}, nil)
	r.MemberOf = func(name string) ([]string, error) {
		if name != "alice" {
			return nil, nil
		}
		return []string{"@lab", "@staff"}, nil
	}
	a, err := r.Resolve("alice")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(a.Groups) != "[1001 2000 3000]" {
		t.Fatalf("%+v", a)
	}
	r.MemberOf = func(string) ([]string, error) { return nil, errors.New("ldap down") }
	if _, err := r.Resolve("alice"); err == nil || !strings.Contains(err.Error(), "ldap down") {
		t.Fatalf("a broken group listing got %v", err)
	}
}
