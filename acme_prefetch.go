// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"time"
)

// prefetcher is what prefetchCerts needs of a certificate source.
type prefetcher interface {
	Prefetch(ctx context.Context) error
}

// prefetchCerts asks for the ACME certificates as soon as the listeners are
// up, instead of at the first client that names the host -- so that client
// does not wait for an issuance, and a host no one has reached by name yet
// still has its certificate. The CA validates tls-alpn-01 on 443 and http-01
// on the http_challenge listener, which is why it runs after both are bound.
//
// A failure is retried after a minute, then twice as long each time up to an
// hour, until it succeeds or the server stops: the CA may not reach us yet
// (a firewall opened later, a DNS record propagating), and its rate limits
// (Let's Encrypt: 5 failed validations per name per hour) are why the
// retries slow down rather than hammer it. Each failure is already reported
// by the source's OnError.
func prefetchCerts(ctx context.Context, src prefetcher, wait func(context.Context, time.Duration) bool) {
	delay := time.Minute
	for src.Prefetch(ctx) != nil {
		if !wait(ctx, delay) {
			return
		}
		delay = min(2*delay, time.Hour)
	}
}

// sleepCtx waits d, or until ctx is done; it reports whether to go on.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
