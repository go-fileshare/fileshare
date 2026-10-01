// SPDX-License-Identifier: BSD-3-Clause

//go:build !nonfs

package main

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// A file handle a client holds outlives a change. Every admin change and
// every revoking reload starts a new NFS server over the same socket; with a
// key drawn per server, each one answered BADHANDLE to every handle the
// mounted clients held, and a mount had to be redone after every change.
// One key per process, given to every generation, keeps them valid.
func TestAnNFSHandleOutlivesAGeneration(t *testing.T) {
	if protocolByName("nfs") == nil {
		t.Skip("built without nfs")
	}
	dir := t.TempDir()
	img := image(t, dir, "d.img", map[string]string{"/x.txt": "x"})
	srv, addrs := runServer(t, fmt.Sprintf(`share "d" { image = %q }
serve "nfs" { addr = "127.0.0.1:0" }
`, hclPath(img)))

	fh := nfsMount(t, addrs["nfs"], "/d")
	if st := nfsGetattr(t, addrs["nfs"], fh); st != 0 {
		t.Fatalf("control: GETATTR on a fresh handle: status %d", st)
	}
	before := srv.generationNumber()
	if _, err := srv.swap(srv.currentShares()); err != nil {
		t.Fatal(err)
	}
	if srv.generationNumber() == before {
		t.Fatal("control: no new generation")
	}
	// A new connection, as a client reconnecting after the old one was
	// closed by the change.
	if st := nfsGetattr(t, addrs["nfs"], fh); st != 0 {
		t.Errorf("BUG: the handle the client held is refused by the next generation: status %d (10001 is BADHANDLE)", st)
	}
}

// nfsMount asks MOUNTv3 MNT for path and returns the root handle.
func nfsMount(t *testing.T, addr, path string) []byte {
	t.Helper()
	res := nfsRPC(t, addr, 100005, 3, 1, xdrOpaque([]byte(path)))
	if len(res) < 8 || getBE32(res) != 0 {
		t.Fatalf("MNT %s: % x", path, res)
	}
	n := getBE32(res[4:])
	if int(n) > len(res)-8 {
		t.Fatalf("MNT %s: short handle: % x", path, res)
	}
	return append([]byte(nil), res[8:8+n]...)
}

// nfsGetattr calls NFSv3 GETATTR on fh and returns its nfsstat3.
func nfsGetattr(t *testing.T, addr string, fh []byte) uint32 {
	t.Helper()
	res := nfsRPC(t, addr, 100003, 3, 1, xdrOpaque(fh))
	if len(res) < 4 {
		t.Fatalf("GETATTR: % x", res)
	}
	return getBE32(res)
}

// nfsRPC makes one ONC RPC call over a new connection, with an AUTH_SYS
// credential for uid 0 (RFC 5531 §9.2), and returns the procedure's result
// after the accept status, which must be SUCCESS.
func nfsRPC(t *testing.T, addr string, prog, vers, proc uint32, args []byte) []byte {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	cred := append(append(xdrU32(0), xdrOpaque([]byte("test"))...), xdrU32(0, 0, 0)...) // stamp, machine, uid, gid, no gids
	msg := xdrU32(7, 0, 2, prog, vers, proc, 1)
	msg = append(msg, xdrOpaque(cred)...)
	msg = append(msg, xdrU32(0, 0)...) // AUTH_NONE verifier
	msg = append(msg, args...)
	rec := append(xdrU32(0x80000000|uint32(len(msg))), msg...)
	if _, err := c.Write(rec); err != nil {
		t.Fatal(err)
	}
	var mark [4]byte
	if _, err := ioReadFull(c, mark[:]); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, getBE32(mark[:])&^0x80000000)
	if _, err := ioReadFull(c, body); err != nil {
		t.Fatal(err)
	}
	if len(body) < 24 || getBE32(body[4:]) != 1 || getBE32(body[8:]) != 0 {
		t.Fatalf("not an accepted reply: % x", body)
	}
	off := 20 + (int(getBE32(body[16:]))+3)&^3
	if off+4 > len(body) || getBE32(body[off:]) != 0 {
		t.Fatalf("the call was not accepted: % x", body)
	}
	return body[off+4:]
}

func xdrU32(vs ...uint32) []byte {
	b := make([]byte, 4*len(vs))
	for i, v := range vs {
		be32(b[4*i:], v)
	}
	return b
}

func xdrOpaque(p []byte) []byte {
	b := append(xdrU32(uint32(len(p))), p...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}
