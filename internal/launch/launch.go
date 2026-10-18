// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package launch

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"

	"github.com/go-filesystems/remote"

	"github.com/go-fileshare/fileshare/internal/account"
)

// Share is a share as the launcher knows it, from the configuration.
type Share struct {
	Name      string
	Directory string
	ReadOnly  bool
}

// Spawn starts a worker as a, serving s, and returns the launcher's end of
// the socket to it -- the end the front is handed.
type Spawn func(a account.Account, s Share) (*os.File, error)

// Launcher answers a front's requests for workers.
type Launcher struct {
	Resolve func(person string) (account.Account, error)
	// Share is the share named, if the configuration has it and it serves
	// a directory as its people (identity = "system").
	Share func(name string) (Share, bool)
	Spawn Spawn
	// Log says what was started and what was refused; nil says nothing.
	Log func(format string, args ...any)
}

const (
	maxName    = 256 // a person's or a share's name
	maxRequest = 4 + 4 + maxName + 4 + maxName
	maxReply   = 4 + 1 + 4 + 1024
)

var errMalformed = errors.New("launch: malformed message")

// Serve answers requests on conn, one at a time, until conn closes. A request
// that does not decode, or that comes with descriptors, ends it: only the
// front holds this socket, and a front that sends those is not the front.
func (l *Launcher) Serve(conn *net.UnixConn) error {
	defer conn.Close()
	for {
		msg, fds, err := readMsg(conn, maxRequest)
		for _, fd := range fds {
			_ = syscall.Close(fd)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if len(fds) != 0 {
			return fmt.Errorf("%w: a request came with %d descriptors", errMalformed, len(fds))
		}
		person, share, err := decodeRequest(msg)
		if err != nil {
			return err
		}
		f, err := l.start(person, share)
		if err != nil {
			l.logf("worker for %s on %s refused: %v", person, share, err)
			if err := writeMsg(conn, reply(err), nil); err != nil {
				return err
			}
			continue
		}
		err = writeMsg(conn, reply(nil), f)
		f.Close() // the front has its own copy now; the launcher keeps none
		if err != nil {
			return err
		}
	}
}

func (l *Launcher) logf(format string, args ...any) {
	if l.Log != nil {
		l.Log(format, args...)
	}
}

func (l *Launcher) start(person, share string) (*os.File, error) {
	s, ok := l.Share(share)
	if !ok {
		return nil, fmt.Errorf("no share %q serves its people as themselves", share)
	}
	a, err := l.Resolve(person)
	if err != nil {
		return nil, err
	}
	f, err := l.Spawn(a, s)
	if err != nil {
		return nil, fmt.Errorf("starting the worker: %w", err)
	}
	l.logf("worker for %s on %s: uid %d, gid %d, groups %v (from %s)", person, share, a.UID, a.GID, a.Groups, a.From)
	return f, nil
}

// Client is the front's side: it asks the launcher for workers, one request
// at a time.
type Client struct {
	mu   sync.Mutex
	conn *net.UnixConn
}

// NewClient asks for workers over conn, the front's end of the socketpair the
// launcher started it with.
func NewClient(conn *net.UnixConn) *Client { return &Client{conn: conn} }

// Worker is person's worker for share: the filesystem it serves, as them.
// The error says why the launcher refused, if it did.
func (c *Client) Worker(person, share string) (*remote.FS, error) {
	if len(person) > maxName || len(share) > maxName {
		return nil, fmt.Errorf("launch: a name longer than %d bytes", maxName)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var req []byte
	req = appendStr(req, person)
	req = appendStr(req, share)
	if err := writeMsg(c.conn, req, nil); err != nil {
		return nil, fmt.Errorf("launch: %w", err)
	}
	msg, fds, err := readMsg(c.conn, maxReply)
	if err != nil {
		closeAll(fds)
		return nil, fmt.Errorf("launch: %w", err)
	}
	if refused, err := decodeReply(msg); err != nil || refused != nil {
		closeAll(fds)
		if err != nil {
			return nil, err
		}
		return nil, refused
	}
	if len(fds) != 1 {
		closeAll(fds)
		return nil, fmt.Errorf("%w: a worker came with %d descriptors, not one", errMalformed, len(fds))
	}
	f := os.NewFile(uintptr(fds[0]), "worker")
	conn, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("launch: the worker's socket: %w", err)
	}
	return remote.New(conn)
}

func closeAll(fds []int) {
	for _, fd := range fds {
		_ = syscall.Close(fd)
	}
}

// The messages: u32 length, then the payload. A request is two strings
// (u32 length + bytes): the person and the share. A reply is a status byte
// (0 started, 1 refused) and a string: why it was refused.

func appendStr(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

func takeStr(b []byte, limit int) (string, []byte, error) {
	if len(b) < 4 {
		return "", nil, errMalformed
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) || uint64(n) > uint64(limit) {
		return "", nil, errMalformed
	}
	return string(b[4 : 4+n]), b[4+n:], nil
}

func decodeRequest(b []byte) (person, share string, err error) {
	if person, b, err = takeStr(b, maxName); err != nil {
		return "", "", err
	}
	if share, b, err = takeStr(b, maxName); err != nil {
		return "", "", err
	}
	if len(b) != 0 || person == "" || share == "" {
		return "", "", errMalformed
	}
	return person, share, nil
}

// Refused is the launcher's refusal, as the front receives it.
type Refused struct{ Reason string }

func (r *Refused) Error() string { return "the launcher refused: " + r.Reason }

func reply(err error) []byte {
	if err == nil {
		return appendStr([]byte{0}, "")
	}
	msg := err.Error()
	if len(msg) > 1024 {
		msg = msg[:1024]
	}
	return appendStr([]byte{1}, msg)
}

func decodeReply(b []byte) (*Refused, error) {
	if len(b) < 1 || b[0] > 1 {
		return nil, errMalformed
	}
	why, rest, err := takeStr(b[1:], 1024)
	if err != nil || len(rest) != 0 {
		return nil, errMalformed
	}
	if b[0] == 1 {
		return &Refused{Reason: why}, nil
	}
	return nil, nil
}

// writeMsg writes one message, with f's descriptor alongside when f is not
// nil. The descriptor rides with the first byte; the reader collects it while
// reading this message and no other, since it never reads past a message's
// end.
func writeMsg(c *net.UnixConn, payload []byte, f *os.File) error {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(payload)))
	b = append(b, payload...)
	var oob []byte
	if f != nil {
		oob = syscall.UnixRights(int(f.Fd()))
	}
	n, _, err := c.WriteMsgUnix(b, oob, nil)
	if err != nil {
		return err
	}
	if n < len(b) {
		_, err = c.Write(b[n:])
	}
	return err
}

// readMsg reads exactly one message and the descriptors that came with it.
// Received descriptors are close-on-exec (Go sets it); the caller owns them.
func readMsg(c *net.UnixConn, limit int) (payload []byte, fds []int, err error) {
	var hdr [4]byte
	if fds, err = readFull(c, hdr[:], fds); err != nil {
		return nil, fds, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if uint64(n) > uint64(limit) {
		return nil, fds, fmt.Errorf("%w: %d bytes", errMalformed, n)
	}
	payload = make([]byte, n)
	if fds, err = readFull(c, payload, fds); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, fds, err
	}
	return payload, fds, nil
}

// readFull fills b, collecting the descriptors that arrive meanwhile.
func readFull(c *net.UnixConn, b []byte, fds []int) ([]int, error) {
	oob := make([]byte, syscall.CmsgSpace(4*4))
	got := 0
	for got < len(b) {
		n, oobn, flags, _, err := c.ReadMsgUnix(b[got:], oob)
		if oobn > 0 {
			more, perr := parseRights(oob[:oobn])
			fds = append(fds, more...)
			if perr != nil {
				return fds, perr
			}
		}
		if flags&syscall.MSG_CTRUNC != 0 {
			return fds, fmt.Errorf("%w: descriptors were cut off", errMalformed)
		}
		got += n
		if err != nil {
			if got > 0 && errors.Is(err, io.EOF) {
				return fds, io.ErrUnexpectedEOF
			}
			return fds, err
		}
		if n == 0 {
			return fds, io.ErrUnexpectedEOF
		}
	}
	return fds, nil
}

func parseRights(oob []byte) ([]int, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	var fds []int
	for i := range msgs {
		got, err := syscall.ParseUnixRights(&msgs[i])
		if err != nil {
			return fds, err
		}
		fds = append(fds, got...)
	}
	return fds, nil
}

// Pair is the socket between a launcher and the front it starts: the
// launcher's end, to Serve on, and the front's, for its ExtraFiles. Both are
// close-on-exec; the front's is inherited only because ExtraFiles names it.
func Pair() (launcher *net.UnixConn, front *os.File, err error) {
	ours, theirs, err := socketpair()
	if err != nil {
		return nil, nil, err
	}
	c, err := net.FileConn(ours)
	ours.Close()
	if err != nil {
		theirs.Close()
		return nil, nil, fmt.Errorf("launch: %w", err)
	}
	return c.(*net.UnixConn), theirs, nil
}

// FrontConn is the front's end, from the descriptor it inherited -- which
// the launcher says it passed, in FrontEnv.
func FrontConn(fd int) (*net.UnixConn, error) {
	f, err := Inherited(fd, FrontEnv)
	if err != nil {
		return nil, err
	}
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("launch: the socket on descriptor %d: %w", fd, err)
	}
	u, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, fmt.Errorf("launch: descriptor %d is a %T, not a unix socket", fd, c)
	}
	return u, nil
}

// The variables that say a descriptor was passed, and which: the launcher
// sets FrontEnv for the front, Exec sets WorkerEnv for a worker.
const (
	FrontEnv  = "FILESHARE_LAUNCHER_FD"
	WorkerEnv = "FILESHARE_WORKER_FD"
)

// Inherited is descriptor fd, if env says it was passed and it is a socket.
//
// ⛔ Never take a descriptor on faith. A process started by hand has nothing
// on fd 3, and the Go runtime puts its own poller there (kqueue, epoll):
// os.NewFile(3) and Close then closes the runtime's poller, and the process
// dies in netpoll -- measured, running serve-front by hand.
func Inherited(fd int, env string) (*os.File, error) {
	if os.Getenv(env) != strconv.Itoa(fd) {
		return nil, fmt.Errorf("launch: no descriptor was passed (%s is not %d): this is started by `fileshare serve`, not by hand", env, fd)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("launch: descriptor %d: %w", fd, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
		return nil, fmt.Errorf("launch: descriptor %d is not a socket", fd)
	}
	return os.NewFile(uintptr(fd), "inherited"), nil
}
