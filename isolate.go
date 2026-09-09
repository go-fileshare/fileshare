// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"

	"github.com/spf13/cobra"
)

// One process per protocol.
//
// Build tags answer "do not carry what I do not run". They cannot answer the
// other half: the protocols you DO run share one address space, and every
// image is open in it -- including the ones a protocol is refused. The NFS
// server may not serve a restricted share, but the bytes of that image are one
// bug away from it.
//
// With --isolate, the parent binds the listeners and then execs ITSELF once per
// protocol, handing each child only the shares that protocol may serve. A
// child opens nothing else: not the restricted image, not the other protocols'
// images. A panic, a leaked goroutine or an exhausted heap takes down one
// protocol rather than the file server, and each child can be confined by
// whatever the operating system offers, which is not a thing that can be done
// to a goroutine.
//
// This is not a plugin system and deliberately so: same binary, no framework,
// no gRPC, no second thing to version-match. See docs/plugins.md for the
// measurements behind that choice.
//
// # The rule that makes it honest
//
// A child opens the image itself, so an image served WRITABLE by two protocols
// would be two drivers over one file, with no common lock and two caches of the
// same metadata -- exactly what lockedfs.go exists to prevent inside one
// process. That configuration is REFUSED rather than served: make the share
// read-only, serve it over one protocol, or do not isolate. Read-only images
// are safe in as many processes as you like, because nothing mutates them.

// isolationRefusal reports why this configuration cannot be served one process
// per protocol, or "" when it can.
func isolationRefusal(shares []*share, serves []serveBlock) string {
	for _, sh := range shares {
		if sh.readOnly {
			continue // nothing mutates it: any number of readers is fine
		}
		var writable []string
		for _, b := range serves {
			p := protocolByName(b.Protocol)
			if p == nil {
				continue
			}
			served, _ := p.exports([]*share{sh})
			if len(served) == 1 {
				writable = append(writable, b.Protocol)
			}
		}
		if len(writable) > 1 {
			return fmt.Sprintf(
				"%s is writable over %s, and one process per protocol means that many drivers "+
					"writing one file with no lock between them. Say `protocols = [%q]` on the "+
					"share, or make it read_only, or do not isolate.",
				sh.name, list(writable), writable[0])
		}
	}
	return ""
}

// sharesForChild is what one protocol's process is allowed to know about. It
// is the least-privilege half of the whole idea: a name that is not in this
// list is a file the child never opens.
func sharesForChild(cfg *config, p *protocol) []string {
	var names []string
	for _, b := range cfg.Shares {
		sh := &share{name: b.Name, readOnly: b.ReadOnly, allow: b.Allow, writers: b.Writers, protocols: b.Protocols}
		if served, _ := p.exports([]*share{sh}); len(served) == 1 {
			names = append(names, b.Name)
		}
	}
	return names
}

// childExe is the program a child runs: this one. It is a variable so a test
// can point it at a binary it built rather than at the test binary.
var childExe = os.Executable

// runIsolated binds every listener, spawns a child per protocol, and waits.
//
// The parent binds so that a privileged port works with children that are not
// privileged -- and so that a child that dies cannot take the port with it.
func runIsolated(ctx context.Context, cfg *config, out *os.File, files []string) error {
	exe, err := childExe()
	if err != nil {
		return fmt.Errorf("finding this program: %w", err)
	}

	type child struct {
		p   *protocol
		cmd *exec.Cmd
		ln  net.Listener
	}
	var children []child
	stopAll := func() {
		for _, c := range children {
			if c.cmd.Process != nil {
				c.cmd.Process.Kill()
			}
			c.ln.Close()
		}
	}

	for i := range cfg.Serves {
		b := cfg.Serves[i]
		p := protocolByName(b.Protocol)
		ln, err := net.Listen("tcp", b.Addr)
		if err != nil {
			stopAll()
			return fmt.Errorf("%s: %w", b.Protocol, err)
		}
		args := []string{"serve-one", "--protocol", b.Protocol, "--addr", ln.Addr().String()}
		for _, f := range files {
			args = append(args, "--config", f)
		}
		if names := sharesForChild(cfg, p); len(names) > 0 {
			args = append(args, "--share-only", strings.Join(names, ","))
		}
		cmd := exec.Command(exe, args...)
		cmd.Stdout, cmd.Stderr = out, os.Stderr
		if err := passListener(cmd, ln); err != nil {
			stopAll()
			return fmt.Errorf("%s: %w", b.Protocol, err)
		}
		if err := cmd.Start(); err != nil {
			stopAll()
			return fmt.Errorf("%s: %w", b.Protocol, err)
		}
		fmt.Fprintf(out, "%-6s on %s — process %d, serving %s\n",
			b.Protocol, ln.Addr(), cmd.Process.Pid, list(sharesForChild(cfg, p)))
		children = append(children, child{p, cmd, ln})
	}

	// One child's death stops the lot: a file server reachable over two of the
	// three protocols it was told to serve is one nobody can reason about.
	done := make(chan error, len(children))
	var wg sync.WaitGroup
	for _, c := range children {
		wg.Add(1)
		go func(c child) {
			defer wg.Done()
			err := c.cmd.Wait()
			if err != nil {
				done <- fmt.Errorf("%s stopped: %w", c.p.name, err)
				return
			}
			done <- fmt.Errorf("%s stopped", c.p.name)
		}(c)
	}
	select {
	case <-ctx.Done():
		stopAll()
		wg.Wait()
		return nil
	case err := <-done:
		stopAll()
		wg.Wait()
		return err
	}
}

// newServeOneCmd is what a child runs. It is hidden because a person does not
// type it: the parent does.
func newServeOneCmd(o *options) *cobra.Command {
	var (
		protocolName string
		addr         string
		only         string
	)
	cmd := &cobra.Command{
		Use:           "serve-one",
		Short:         "Serve one protocol (this is what --isolate spawns; you do not type it)",
		Hidden:        true,
		Args:          noArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p := protocolByName(protocolName)
			if p == nil {
				return fmt.Errorf("this binary has no %q protocol", protocolName)
			}
			cfg, err := configOf(o, nil)
			if err != nil {
				return err
			}
			// A child serves ONE protocol and knows only the shares it was
			// given: everything else is dropped before an image is opened.
			cfg.Serves = []serveBlock{{Protocol: protocolName, Addr: addr}}
			if only != "" {
				keep := strings.Split(only, ",")
				var kept []shareBlock
				for _, b := range cfg.Shares {
					if slices.Contains(keep, b.Name) {
						kept = append(kept, b)
					}
				}
				cfg.Shares = kept
			}
			if len(cfg.Shares) == 0 {
				return fmt.Errorf("%s was given no shares to serve", protocolName)
			}
			srv, err := open(cfg, cmd.OutOrStdout())
			if err != nil {
				return err
			}
			defer srv.Close()

			ln, err := inheritedListener(addr)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			go func() { <-ctx.Done(); ln.Close() }()
			if err := p.serve(srv, p, ln); err != nil && !errors.Is(err, net.ErrClosed) {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&protocolName, "protocol", "", "the protocol to serve")
	cmd.Flags().StringVar(&addr, "addr", "", "the address the parent bound")
	cmd.Flags().StringVar(&only, "share-only", "", "the shares this process may open (comma separated)")
	return cmd
}
