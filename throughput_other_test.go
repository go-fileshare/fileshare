// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux && !darwin

package main

// Neither can be done here: the harness says "warm" and "load unknown".
func evictFromCache(string) bool      { return false }
func loadAverage1() (float64, bool) { return 0, false }
