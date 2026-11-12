// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

// platformMatcher runs hdiutil ONCE (bounded by ctx and a WaitDelay) and
// answers for every image of the load from its list. Any failure is an error
// (the answer is "unknown"), never "not mounted".
func platformMatcher(ctx context.Context) (mountMatcher, error) {
	cmd := exec.CommandContext(ctx, "/usr/bin/hdiutil", "info", "-plist")
	cmd.Stdin = nil
	// Without it a hung child that holds the pipe open outlives the context.
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("hdiutil info: %w", err)
	}
	const max = 32 << 20
	buf, rerr := io.ReadAll(io.LimitReader(out, max+1))
	if len(buf) > max {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("hdiutil info: more than %d bytes of output", max)
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("hdiutil info: %w", err)
	}
	if rerr != nil {
		return nil, rerr
	}
	imgs, err := parseHdiutilInfo(bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	return func(fi os.FileInfo) (string, error) { return attachedHolder(fi, imgs) }, nil
}
