// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// platformMountedBy asks hdiutil, which is bounded by ctx. Any failure is an
// error (the answer is "unknown"), never "not mounted".
func platformMountedBy(ctx context.Context, fi os.FileInfo) (string, error) {
	cmd := exec.CommandContext(ctx, "/usr/bin/hdiutil", "info", "-plist")
	cmd.Stdin = nil
	out, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("hdiutil info: %w", err)
	}
	const max = 32 << 20
	buf, rerr := io.ReadAll(io.LimitReader(out, max+1))
	if len(buf) > max {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return "", fmt.Errorf("hdiutil info: more than %d bytes of output", max)
	}
	if err := cmd.Wait(); err != nil {
		return "", fmt.Errorf("hdiutil info: %w", err)
	}
	if rerr != nil {
		return "", rerr
	}
	imgs, err := parseHdiutilInfo(bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	return attachedHolder(fi, imgs), nil
}
