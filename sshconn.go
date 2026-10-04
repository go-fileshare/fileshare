// SPDX-License-Identifier: BSD-3-Clause

//go:build !nosftp

package main

import (
	"net"
	"sync"
	"time"
)

// An sshConn is one SSH connection, with a deadline on everything before
// login. Without it a client that sends its version string and nothing more
// holds a connection, a goroutine and a file descriptor for as long as it
// likes, and a few thousand of them are a server nobody can reach.
type sshConn struct {
	net.Conn
	once sync.Once
}

// loggedIn lifts the handshake deadline: from here the person has proved who
// they are, and a session left idle is theirs to leave. Safe on nil, which is
// the configuration checked once at start.
func (c *sshConn) loggedIn() {
	if c == nil {
		return
	}
	c.once.Do(func() { c.Conn.SetDeadline(time.Time{}) })
}

// serveSSH accepts connections until ln is closed or stop is, handing each one
// to handle with a deadline of preAuth on its handshake, and closes every
// connection still open when it returns -- a change to the shares starts
// another daemon, and this one's sessions must not outlive it.
func serveSSH(ln net.Listener, stop <-chan struct{}, preAuth time.Duration, handle func(*sshConn) error) error {
	var (
		mu     sync.Mutex
		conns  = map[net.Conn]struct{}{}
		closed bool
		wg     sync.WaitGroup
	)
	shut := func() {
		mu.Lock()
		closed = true
		for c := range conns {
			c.Close()
		}
		mu.Unlock()
		ln.Close()
	}
	returned := make(chan struct{})
	go func() {
		select {
		case <-stop:
		case <-returned:
		}
		shut()
	}()
	defer func() {
		close(returned)
		shut()
		wg.Wait()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		c.SetDeadline(time.Now().Add(preAuth))
		mu.Lock()
		if closed {
			mu.Unlock()
			c.Close()
			continue
		}
		conns[c] = struct{}{}
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				mu.Lock()
				delete(conns, c)
				mu.Unlock()
				c.Close()
			}()
			// One client's failure -- a handshake that timed out included --
			// is that client's: it does not end the accept loop.
			_ = handle(&sshConn{Conn: c})
		}()
	}
}
