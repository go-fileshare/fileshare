//go:build !nosftp

package main

import (
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// The source-address tests elsewhere dial from 127.0.0.1 only, so they could
// not tell a pin matched against the connecting address from one matched
// against "loopback", or against IPv4 alone. These dial from ::1 and from a
// second IPv4 loopback address, 127.0.0.2, through the server's real SFTP
// listener.
//
// Neither address is always there: a host may have no IPv6, and macOS routes
// only 127.0.0.1 on lo0 unless an alias is added. A missing one skips with
// the reason -- unless FILESHARE_REQUIRE_JUDGE is set, as it is on the Linux
// lanes, where both exist and a skip would be a silent no-op.

// needAddress skips, or fails where the lane requires it, if nothing can be
// bound to ip on this host.
func needAddress(t *testing.T, ip, why string) {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err == nil {
		ln.Close()
		return
	}
	if os.Getenv("FILESHARE_REQUIRE_JUDGE") != "" {
		t.Fatalf("%s is required here (FILESHARE_REQUIRE_JUDGE is set): %v", ip, err)
	}
	t.Skipf("%s is not available on this host (%s): %v", ip, why, err)
}

// needSecondIPv4Loopback is needAddress for 127.0.0.2, with the reason it is
// missing where it usually is.
func needSecondIPv4Loopback(t *testing.T) {
	t.Helper()
	why := "the loopback interface does not route 127.0.0.0/8"
	if runtime.GOOS == "darwin" {
		why = "macOS routes only 127.0.0.1 on lo0; `sudo ifconfig lo0 alias 127.0.0.2` adds it"
	}
	needAddress(t, "127.0.0.2", why)
}

// sftpFrom is sftpAs dialling from the local address from, so that is the
// address the server sees the connection come from.
func sftpFrom(t *testing.T, from, addr, user string, auth ssh.AuthMethod) (*sftp.Client, func(), error) {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(from)}, Timeout: 10 * time.Second}
	nc, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dialling %s from %s: %v", addr, from, err)
	}
	if got := nc.LocalAddr().(*net.TCPAddr).IP.String(); got != from {
		nc.Close()
		t.Fatalf("dialled from %s, wanted %s: the test would not be the one it names", got, from)
	}
	sc, chans, reqs, err := ssh.NewClientConn(nc, addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		nc.Close()
		return nil, func() {}, err
	}
	c := ssh.NewClient(sc, chans, reqs)
	cl, err := sftp.NewClient(c)
	if err != nil {
		c.Close()
		return nil, func() {}, err
	}
	return cl, func() { cl.Close(); c.Close() }, nil
}

// logsInFrom is logsIn from a chosen local address.
func logsInFrom(t *testing.T, from, addr, user string, signer ssh.Signer) error {
	t.Helper()
	cl, done, err := sftpFrom(t, from, addr, user, ssh.PublicKeys(signer))
	if err != nil {
		return err
	}
	defer done()
	_, err = cl.ReadDir("/photos")
	return err
}

// pinCase is one login: a certificate granted grant and pinned to pin ("" for
// no pin), presented from the address from.
type pinCase struct {
	pin, grant, from string
	admit            bool
}

// Under ssh_domains, a certificate pinned to ::1/128 is let in from ::1 and
// refused from 127.0.0.1; 127.0.0.1/32 is refused from ::1. The grant is
// still read on IPv6: pinned to ::1 but granted another host, refused.
func TestSFTPDomainGrantSourceAddressIPv6(t *testing.T) {
	needUsers(t)
	needAddress(t, "::1", "the host has no IPv6 loopback")
	domains := `ssh_domains = ["files.example.org"]`
	v6, ca6, _ := grantServerOn(t, "[::1]:0", domains)
	v4, ca4, _ := grantServerOn(t, "127.0.0.1:0", domains)
	here, elsewhere := granted(t, "files.example.org"), granted(t, "login.example.org")
	for _, tc := range []pinCase{
		{"", here, "::1", true}, // the witness: ::1 itself is no obstacle
		{"::1/128", here, "::1", true},
		{"::1/128", here, "127.0.0.1", false},
		{"127.0.0.1/32", here, "::1", false},
		{"127.0.0.1/32,::1/128", here, "::1", true},
		{"::1/128", elsewhere, "::1", false},
	} {
		r, ca := v4, ca4
		if tc.from == "::1" {
			r, ca = v6, ca6
		}
		var extra map[string]string
		if tc.pin != "" {
			extra = map[string]string{"critical:source-address": tc.pin}
		}
		err := logsInFrom(t, tc.from, r.addrs["sftp"], "alice", grantCert(t, ca, "alice", tc.grant, extra))
		if (err == nil) != tc.admit {
			t.Errorf("pinned to %q, granted %s, from %s: admitted = %v (%v), want %v", tc.pin, tc.grant, tc.from, err == nil, err, tc.admit)
		}
	}
}

// Under ssh_domains, from 127.0.0.2: a certificate pinned to 127.0.0.1/32 is
// refused, one pinned to 127.0.0.0/8 is let in -- the pin is matched against
// the connecting address, not against "this is loopback".
func TestSFTPDomainGrantSourceAddressSecondIPv4(t *testing.T) {
	needUsers(t)
	needSecondIPv4Loopback(t)
	r, ca, _ := grantServerOn(t, "127.0.0.1:0", `ssh_domains = ["files.example.org"]`)
	here, elsewhere := granted(t, "files.example.org"), granted(t, "login.example.org")
	for _, tc := range []pinCase{
		{"", here, "127.0.0.2", true}, // the witness
		{"127.0.0.1/32", here, "127.0.0.1", true},
		{"127.0.0.1/32", here, "127.0.0.2", false},
		{"127.0.0.0/8", here, "127.0.0.2", true},
		{"127.0.0.2/32", here, "127.0.0.2", true},
		{"127.0.0.2/32", here, "127.0.0.1", false},
		{"127.0.0.0/8", elsewhere, "127.0.0.2", false},
	} {
		var extra map[string]string
		if tc.pin != "" {
			extra = map[string]string{"critical:source-address": tc.pin}
		}
		err := logsInFrom(t, tc.from, r.addrs["sftp"], "alice", grantCert(t, ca, "alice", tc.grant, extra))
		if (err == nil) != tc.admit {
			t.Errorf("pinned to %q, granted %s, from %s: admitted = %v (%v), want %v", tc.pin, tc.grant, tc.from, err == nil, err, tc.admit)
		}
	}
}
