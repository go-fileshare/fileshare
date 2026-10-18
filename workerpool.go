// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"io/fs"
	"sync"
	"time"

	filesystem "github.com/go-filesystems/interface"
)

// A workerPool is the front's workers: one per person and share, shared by
// that person's connections over every protocol, started on first use and
// closed once nothing has used it for idle.
//
// Closing a worker's filesystem closes the socket to it, and a worker whose
// socket closes exits: the pool is the only thing that keeps one alive.
type workerPool struct {
	// get starts a worker: in the front, a request to the launcher.
	get  func(person, share string) (filesystem.Filesystem, error)
	idle time.Duration

	mu     sync.Mutex
	m      map[workerKey]*worker
	closed bool
}

type workerKey struct{ person, share string }

// A worker is one person's filesystem on one share, and what the protocols
// built over it.
type worker struct {
	pool *workerPool
	key  workerKey
	// ready is closed once fsys or err is set: a second request for a worker
	// still starting waits for the first rather than starting another.
	ready chan struct{}
	fsys  filesystem.Filesystem
	err   error

	refs  int // under pool.mu
	timer *time.Timer

	mu       sync.Mutex
	attached map[string]any
}

var errPoolClosed = errors.New("the server is stopping")

func newWorkerPool(get func(person, share string) (filesystem.Filesystem, error), idle time.Duration) *workerPool {
	return &workerPool{get: get, idle: idle, m: map[workerKey]*worker{}}
}

// acquire is person's worker on share, and the release that says this use of
// it is over. Every acquire that returns a worker must be released, once.
func (p *workerPool) acquire(person, share string) (*worker, func(), error) {
	if person == "" {
		// The launcher would refuse it too, by ending the conversation: an
		// empty name is not a request a front sends.
		return nil, nil, errors.New("a worker runs as somebody, and nobody authenticated")
	}
	k := workerKey{person, share}
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, nil, errPoolClosed
		}
		w, ok := p.m[k]
		if !ok {
			w = &worker{pool: p, key: k, ready: make(chan struct{}), refs: 1}
			p.m[k] = w
			p.mu.Unlock()
			w.fsys, w.err = p.get(person, share)
			close(w.ready)
			if w.err != nil {
				p.mu.Lock()
				if p.m[k] == w {
					delete(p.m, k)
				}
				p.mu.Unlock()
				return nil, nil, w.err
			}
			return w, w.releaser(), nil
		}
		w.refs++
		if w.timer != nil {
			w.timer.Stop()
			w.timer = nil
		}
		p.mu.Unlock()
		<-w.ready
		if w.err != nil {
			// The first request's failure is this one's too; the entry is
			// gone, so the next request tries again.
			return nil, nil, w.err
		}
		if w.alive() {
			return w, w.releaser(), nil
		}
		// Its worker is gone -- it crashed, or was killed. Forget it and
		// start another, rather than serve errors until it goes idle.
		w.releaser()()
		p.forget(w)
	}
}

// alive asks the worker something cheap: a worker that has exited answers
// fs.ErrClosed, and one that answers anything at all is there.
func (w *worker) alive() bool {
	_, err := w.fsys.Stat("/")
	return err == nil || !isClosed(err)
}

func isClosed(err error) bool { return errors.Is(err, fs.ErrClosed) }

// releaser is the release for one acquire: it counts once however often it is
// called.
func (w *worker) releaser() func() {
	var once sync.Once
	return func() { once.Do(w.release) }
}

func (w *worker) release() {
	p := w.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	w.refs--
	if w.refs > 0 || p.m[w.key] != w {
		return
	}
	w.timer = time.AfterFunc(p.idle, func() {
		p.mu.Lock()
		if w.refs > 0 || p.m[w.key] != w {
			p.mu.Unlock()
			return
		}
		delete(p.m, w.key)
		p.mu.Unlock()
		w.close()
	})
}

// forget closes w now and drops it from the pool, if it is still there.
func (p *workerPool) forget(w *worker) {
	p.mu.Lock()
	if p.m[w.key] == w {
		delete(p.m, w.key)
		if w.timer != nil {
			w.timer.Stop()
		}
	}
	p.mu.Unlock()
	w.close()
}

func (w *worker) close() {
	if w.fsys != nil {
		_ = w.fsys.Close()
	}
}

// attach is what the protocol called name built over this worker, built once
// by build: WebDAV keeps its handlers here, so a person's locks live as long
// as their worker does.
func (w *worker) attach(name string, build func(filesystem.Filesystem) (any, error)) (any, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if v, ok := w.attached[name]; ok {
		return v, nil
	}
	v, err := build(w.fsys)
	if err != nil {
		return nil, err
	}
	if w.attached == nil {
		w.attached = map[string]any{}
	}
	w.attached[name] = v
	return v, nil
}

// reset closes every worker: the shares they serve may have changed, and the
// connections that used them were closed with the generation that served
// them. A release that comes later finds its worker gone, and does nothing.
func (p *workerPool) reset() {
	p.mu.Lock()
	old := p.m
	p.m = map[workerKey]*worker{}
	for _, w := range old {
		if w.timer != nil {
			w.timer.Stop()
		}
	}
	p.mu.Unlock()
	for _, w := range old {
		<-w.ready
		w.close()
	}
}

// Close closes every worker and refuses new ones.
func (p *workerPool) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.reset()
	return nil
}

// size is how many workers are open or starting.
func (p *workerPool) size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.m)
}
