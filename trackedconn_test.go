// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
)

// readFromConn is a net.Conn with a ReadFrom, which records that it was used.
type readFromConn struct {
	net.Conn
	used bool
	got  bytes.Buffer
}

func (c *readFromConn) ReadFrom(r io.Reader) (int64, error) {
	c.used = true
	return c.got.ReadFrom(r)
}

// writeOnlyConn is a net.Conn without one.
type writeOnlyConn struct {
	net.Conn
	got bytes.Buffer
}

func (c *writeOnlyConn) Write(p []byte) (int, error) { return c.got.Write(p) }

// A tracked connection passes ReadFrom to the connection it wraps -- the
// path to sendfile(2) -- and copies when that one has none.
func TestATrackedConnPassesReadFromOn(t *testing.T) {
	with := &readFromConn{}
	tc := &trackedConn{Conn: with}
	var _ io.ReaderFrom = tc
	if n, err := tc.ReadFrom(strings.NewReader("hello")); n != 5 || err != nil || !with.used || with.got.String() != "hello" {
		t.Fatalf("ReadFrom over a ReaderFrom: n=%d err=%v used=%v got=%q", n, err, with.used, with.got.String())
	}
	without := &writeOnlyConn{}
	tc = &trackedConn{Conn: without}
	if n, err := tc.ReadFrom(strings.NewReader("world")); n != 5 || err != nil || without.got.String() != "world" {
		t.Fatalf("ReadFrom over a plain conn: n=%d err=%v got=%q", n, err, without.got.String())
	}
}
