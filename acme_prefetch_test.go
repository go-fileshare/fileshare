// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

type flakySource struct{ fails, calls int }

func (f *flakySource) Prefetch(context.Context) error {
	f.calls++
	if f.calls <= f.fails {
		return errors.New("the CA cannot reach us yet")
	}
	return nil
}

// Retried until it works, waiting a minute, then twice as long, up to an hour.
func TestPrefetchRetriesWithBackoff(t *testing.T) {
	src := &flakySource{fails: 9}
	var waits []time.Duration
	prefetchCerts(context.Background(), src, func(_ context.Context, d time.Duration) bool {
		waits = append(waits, d)
		return true
	})
	if src.calls != 10 {
		t.Fatalf("%d attempts, want 10", src.calls)
	}
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute,
		32 * time.Minute, time.Hour, time.Hour, time.Hour}
	if len(waits) != len(want) {
		t.Fatalf("waits %v", waits)
	}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("wait %d: %v, want %v", i, waits[i], want[i])
		}
	}
}

// A stopping server stops the retries.
func TestPrefetchStopsWithTheServer(t *testing.T) {
	src := &flakySource{fails: 1 << 30}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	prefetchCerts(ctx, src, sleepCtx)
	if src.calls != 1 {
		t.Fatalf("%d attempts after the server stopped", src.calls)
	}
	if !sleepCtx(context.Background(), time.Millisecond) {
		t.Fatal("a wait that ran out said stop")
	}
}
