// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
)

// A generation is one set of protocol servers over one list of shares.
//
// It exists because the shares can now change while the server runs -- the
// admin API creates them and grants them -- and the protocol libraries cannot
// follow: go-filesystems/smb has Share and no Unshare, nfs has Export and no
// Unexport, and SMB fixes who may connect when the share is added. So a change
// is not applied TO the running servers; they are replaced by new ones built
// from the new list, the way a restart would, without giving up the ports.
//
// ⛔ The connections of the old generation are CLOSED, not left to finish. A
// session that outlived a revocation would keep the access that was just taken
// away -- an SMB tree connect is checked once, and an SFTP login builds its
// tree once -- and "revoked, except for whoever was already connected" is not
// a revocation. Clients reconnect; that is the price, and it is paid for every
// change, which is why the API applies one change per call rather than one per
// field.

// A feed is a listening socket that outlives generations. One goroutine
// accepts, and whichever generation is current takes the connection -- so a
// client that connects during a swap waits in the channel instead of being
// refused, and a port is never closed and re-bound.
type feed struct {
	proto string
	ln    net.Listener
	conns chan net.Conn
	// closing is closed by Close; done when the accepting goroutine has
	// returned, and err is why Accept stopped.
	closing   chan struct{}
	closeOnce sync.Once
	done      chan struct{}
	err       error

	accepted atomic.Uint64
	open     atomic.Int64
}

func newFeed(proto string, ln net.Listener) *feed {
	f := &feed{proto: proto, ln: ln, conns: make(chan net.Conn),
		closing: make(chan struct{}), done: make(chan struct{})}
	go f.accept()
	return f
}

func (f *feed) accept() {
	defer close(f.done)
	for {
		c, err := f.ln.Accept()
		if err != nil {
			f.err = err
			return
		}
		f.accepted.Add(1)
		select {
		case f.conns <- c:
		case <-f.closing:
			// Accepted in the instant before the socket closed, with no
			// generation left to take it: closed rather than handed to nobody.
			c.Close()
			return
		}
	}
}

func (f *feed) Close() error {
	var err error
	f.closeOnce.Do(func() {
		close(f.closing)
		err = f.ln.Close()
	})
	return err
}

// A genListener is what one generation's protocol server listens on: the
// feed's connections, until the generation is stopped.
type genListener struct {
	f    *feed
	stop chan struct{}
	once sync.Once

	mu    sync.Mutex
	conns map[*trackedConn]struct{}
}

func (f *feed) listener() *genListener {
	return &genListener{f: f, stop: make(chan struct{}), conns: map[*trackedConn]struct{}{}}
}

func (l *genListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.f.conns:
		t := &trackedConn{Conn: c, l: l}
		l.f.open.Add(1)
		l.mu.Lock()
		select {
		case <-l.stop:
			// Stopped between the receive and here: this generation must not
			// start serving anybody now.
			l.mu.Unlock()
			t.Close()
			return nil, net.ErrClosed
		default:
		}
		l.conns[t] = struct{}{}
		l.mu.Unlock()
		return t, nil
	case <-l.stop:
		return nil, net.ErrClosed
	case <-l.f.done:
		if l.f.err != nil {
			return nil, l.f.err
		}
		return nil, net.ErrClosed
	}
}

// Close stops this generation taking connections and closes every one it
// took. The socket underneath stays open for the next generation.
func (l *genListener) Close() error {
	l.shut()
	return nil
}

// shut is Close, saying how many open connections it closed; the second call
// closes none.
func (l *genListener) shut() (closed int) {
	l.once.Do(func() {
		l.mu.Lock()
		close(l.stop)
		conns := l.conns
		l.conns = nil
		l.mu.Unlock()
		for c := range conns {
			c.Close()
		}
		closed = len(conns)
	})
	return closed
}

func (l *genListener) Addr() net.Addr { return l.f.ln.Addr() }

// A trackedConn is removed from its listener's set when it closes, whoever
// closes it, and counted once.
type trackedConn struct {
	net.Conn
	l    *genListener
	once sync.Once
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.l.f.open.Add(-1)
		c.l.mu.Lock()
		if c.l.conns != nil {
			delete(c.l.conns, c)
		}
		c.l.mu.Unlock()
	})
	return err
}

// generation is the protocol servers running now.
type generation struct {
	n       uint64
	lns     []*genListener
	wg      sync.WaitGroup
	stopped atomic.Bool
}

// startGeneration serves every feed with the shares current at this moment.
// A protocol that fails reports it on failures -- unless its generation was
// stopped on purpose, which makes every one of them fail with ErrClosed.
func (s *server) startGeneration(n uint64, feeds []*feed, failures chan<- error) *generation {
	g := &generation{n: n}
	for _, f := range feeds {
		p := protocolByName(f.proto)
		l := f.listener()
		g.lns = append(g.lns, l)
		// WebDAV and S3 are HTTP, and HTTPS is HTTP over a TLS listener --
		// wrapped here, over the generation's listener, so that closing the
		// generation still closes every connection under the TLS. NFS starts
		// TLS inside its own protocol (RFC 9289), so it is not wrapped.
		var ln net.Listener = l
		if c := s.tlsConfigs[f.proto]; c != nil && f.proto != "nfs" {
			ln = tls.NewListener(l, c)
		}
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			err := p.serve(s, p, ln)
			if g.stopped.Load() {
				return
			}
			if err == nil || errors.Is(err, net.ErrClosed) {
				// The feed closed: the server is going away.
				return
			}
			select {
			case failures <- &protocolError{p.name, err}:
			default:
			}
		}()
	}
	return g
}

// stop closes this generation's listeners and connections, waits for its
// protocol servers to return, and says how many connections were open.
func (g *generation) stop() (closed uint64) {
	g.stopped.Store(true)
	for _, l := range g.lns {
		closed += uint64(l.shut())
	}
	g.wg.Wait()
	return closed
}

type protocolError struct {
	proto string
	err   error
}

func (e *protocolError) Error() string { return e.proto + ": " + e.err.Error() }
func (e *protocolError) Unwrap() error { return e.err }
