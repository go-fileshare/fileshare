// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/jcmturner/gokrb5/v8/keytab"
)

// maxKeytab bounds what is read: a keytab is a few entries, a few hundred
// bytes each; a path pointing at something huge is a mistake, not a keytab.
const maxKeytab = 1 << 20

// readKeytab opens the keytab ONCE, checks that open file, and parses what was
// read from it. Checking the path and then loading the path again would check
// one file and load whatever stands at the path a moment later.
//
// The file must not be readable or writable by others, nor writable by its
// group, and must belong to root or to the account this server runs as. A
// keytab holds the service's long-term keys -- with both nfs/ and cifs/ in
// one file, the right to be this server for both -- so a copy another account
// can read forges tickets to it for every person of the realm.
//
// Group-READ stays allowed: the usual layout is root:<service group> 0640,
// the same as every other secret a systemd unit reads through its group.
//
// Windows has no mode bits worth reading; its ACLs are the operator's (the
// README says where to put the file), so only the reading is done there.
func readKeytab(path string) (*keytab.Keytab, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("kerberos keytab %s: %w", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("kerberos keytab %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("kerberos keytab %s is not a regular file", path)
	}
	if runtime.GOOS != "windows" {
		if m := fi.Mode().Perm(); m&0o027 != 0 {
			return nil, fmt.Errorf("kerberos keytab %s is mode %v: it must not be readable or writable by others, nor writable by its group (chmod 0640 or 0600)", path, m)
		}
		if err := keytabOwnerOK(fi); err != nil {
			return nil, fmt.Errorf("kerberos keytab %s: %w", path, err)
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, maxKeytab+1))
	if err != nil {
		return nil, fmt.Errorf("kerberos keytab %s: %w", path, err)
	}
	if len(b) > maxKeytab {
		return nil, fmt.Errorf("kerberos keytab %s is larger than %d bytes", path, maxKeytab)
	}
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		return nil, fmt.Errorf("kerberos keytab %s: %w", path, err)
	}
	if len(kt.Entries) == 0 {
		return nil, fmt.Errorf("kerberos keytab %s: %w", path, errEmptyKeytab)
	}
	return kt, nil
}

var errEmptyKeytab = errors.New("it holds no key")
