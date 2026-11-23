// SPDX-License-Identifier: BSD-3-Clause

//go:build nosmb || wasip1

package main

import (
	"crypto/tls"
	"errors"
	"net"
)

var errNoSMBQUIC = errors.New("smb over quic is not in this build")

func listenQUIC(string, *tls.Config) (net.Listener, error) { return nil, errNoSMBQUIC }

func requireSMBClientCert(*tls.Config, []byte) error { return errNoSMBQUIC }
