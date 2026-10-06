// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package provision

import (
	"errors"
	"fmt"
	"regexp"
	"syscall"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// nameRE is the whole grammar of a volume, snapshot or parent name. It is
// strict on purpose (Proxmox's volume names are as strict): a name becomes a
// path component, a ZFS dataset component and a snapshot name, and this is a
// set every one of those accepts with one meaning. No dot, so never "." or
// "..", nor a hidden name; no slash; no '@' or '#', which ZFS reads as a
// snapshot or a bookmark.
var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

func checkName(what, name string) error {
	if !nameRE.MatchString(name) {
		return refuse(codes.InvalidArgument, "%s %q is not a name: it must match %s", what, name, nameRE)
	}
	return nil
}

// A refusal is an answer with a status code: the caller asked for something
// this provisioner will not do, and the code says which kind of no.
type refusal struct {
	code codes.Code
	msg  string
}

func (r *refusal) Error() string { return r.msg }

func refuse(code codes.Code, format string, args ...any) error {
	return &refusal{code: code, msg: fmt.Sprintf(format, args...)}
}

// errAbsent and errNotOurs are what an ownership check finds when the answer
// is not "ours": nothing is there, or something is that this provisioner did
// not create -- an untagged dataset, an inherited tag, a project id outside
// the range. The second is never touched.
var (
	errAbsent  = errors.New("nothing is there")
	errNotOurs = errors.New("it was not created by this provisioner")
)

// statusOf turns any error into the status the caller sees.
//
// A full filesystem is RESOURCE_EXHAUSTED whichever way the kernel says it:
// ENOSPC on XFS and on a full pool, EDQUOT on ext4, btrfs and ZFS quotas.
func statusOf(err error) error {
	if err == nil {
		return nil
	}
	var r *refusal
	if errors.As(err, &r) {
		return status.Error(r.code, r.msg)
	}
	if errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) {
		return status.Error(codes.ResourceExhausted, err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}
