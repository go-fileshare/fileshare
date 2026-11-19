// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"strconv"
	"testing"
	"time"
)

// limitedStore is a store whose rate table holds max sources.
func limitedStore(max int) *stsStore {
	st := newSTSStore(time.Now)
	st.lim = newRateLimiter(time.Now, 1<<30, max)
	return st
}

// BenchmarkSTSAllowRoom is allow() with room in the table: one known source.
func BenchmarkSTSAllowRoom(b *testing.B) {
	st := limitedStore(stsRateSources)
	st.allow("198.51.100.1")
	b.ReportAllocs()
	for b.Loop() {
		st.allow("198.51.100.1")
	}
}

// BenchmarkSTSAllowFull is allow() with a FULL table and a fresh source every
// time: what a flood of new /64s costs.
func BenchmarkSTSAllowFull(b *testing.B) {
	st := limitedStore(stsRateSources)
	for i := range stsRateSources {
		st.allow("seed-" + strconv.Itoa(i))
	}
	keys := make([]string, 1<<16)
	for i := range keys {
		keys[i] = "fresh-" + strconv.Itoa(i)
	}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		st.allow(keys[i&(len(keys)-1)])
		i++
	}
}

// BenchmarkSTSGetWhileAllowFull is get() on a live session while another
// goroutine floods allow() on a full table.
func BenchmarkSTSGetWhileAllowFull(b *testing.B) {
	st := limitedStore(stsRateSources)
	sess, err := st.issue(principal{name: "m"}, "iss", "sub", time.Now(), time.Hour)
	if err != nil {
		b.Fatal(err)
	}
	for i := range stsRateSources {
		st.allow("seed-" + strconv.Itoa(i))
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				st.allow("flood-" + strconv.Itoa(i))
			}
		}
	}()
	b.ReportAllocs()
	for b.Loop() {
		st.get(sess.accessKey)
	}
	close(stop)
	<-done
}
