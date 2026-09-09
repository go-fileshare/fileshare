// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"slices"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// options is what the flags say.
//
// The flags are the shape of the ONE-IMAGE case and they stay: a person
// sharing a single image should not have to write a configuration file to do
// it. When files ARE given they own the shares and the users, because a share
// defined in two places is a question nobody wants to answer at three in the
// morning.
type options struct {
	files    []string
	image    string
	share    string
	user     string
	pwFile   string
	readOnly bool
	only     []string
	name     string
}

func (o *options) bind(f *pflag.FlagSet) {
	f.StringArrayVarP(&o.files, "config", "c", nil,
		"an HCL file, or a directory of .hcl files, describing shares, users and protocols (repeatable)")
	f.StringVarP(&o.image, "image", "i", "", "a disk image to share")
	f.StringVarP(&o.share, "share", "s", "",
		"the name to share it under (default: the image's file name without its extension)")
	f.StringVarP(&o.user, "user", "u", "", "the user a client authenticates as")
	f.StringVarP(&o.pwFile, "password-file", "p", "", "a file holding that user's password")
	f.BoolVar(&o.readOnly, "read-only", false, "refuse every write, whatever the image would allow")
	f.StringArrayVar(&o.only, "protocol", nil,
		"serve only this protocol (repeatable; default: every one this binary has)")
	f.StringVar(&o.name, "name", "FILESHARE", "what the server calls itself to a client")
}

const longHelp = `fileshare serves disk images over SMB, NFS and WebDAV -- the same images, the
same users, the same per-share access, from one configuration file.

    fileshare --image disk.img --user alice --password-file pw
    fileshare --config /etc/fileshare.d
    fileshare check /etc/fileshare.d

The password comes from a FILE, never a flag: an argument is visible in the
process list to every user on the machine.

The protocols do not agree about the one thing access control needs: whether
the server can tell WHO is asking. SMB proves it with NTLMv2 and WebDAV with
HTTP Basic; NFSv3 cannot -- AUTH_UNIX is a claim the wire cannot check. So a
share that names who may use it is NOT exported over NFS. That is a refusal,
not a warning: a configuration saying "photos belongs to alice" and a protocol
handing photos to whoever connects cannot both be honoured.`

func newRootCmd() *cobra.Command {
	var o options
	root := &cobra.Command{
		Use:           "fileshare",
		Short:         "Share disk images over SMB, NFS and WebDAV",
		Long:          longHelp,
		Args:          noArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return serve(cmd, &o)
		},
	}
	o.bind(root.PersistentFlags())
	root.SuggestionsMinimumDistance = 2
	root.SetFlagErrorFunc(flagError)
	root.AddCommand(newServeCmd(&o), newCheckCmd(&o))
	return root
}

func newServeCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:           "serve",
		Short:         "Serve the shares and wait for clients",
		Args:          noArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return serve(cmd, o)
		},
	}
}

// serve reads the configuration, opens every image, and listens.
func serve(cmd *cobra.Command, o *options) error {
	cfg, err := configOf(o, nil)
	if err != nil {
		return err
	}
	srv, err := open(cfg, cmd.OutOrStdout())
	if err != nil {
		return err
	}
	defer srv.Close()

	// A signal closes the listeners, which lets the deferred Close above run
	// so every driver flushes whatever it was holding.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return srv.run(ctx, cfg)
}

// newCheckCmd is the command a person wants before restarting a server other
// people are using.
func newCheckCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "check [file or directory...]",
		Short: "Read the configuration, open every image, and say what would be served to whom",
		Long: `check parses the configuration, opens every image read-only to see that it is
really there and that a driver owns it, and prints the whole matrix: every
share against every protocol, and who may read and write it. It changes
nothing and serves nothing.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := configOf(o, args)
			if err != nil {
				return err
			}
			return report(cmd, cfg)
		},
	}
}

func configOf(o *options, args []string) (*config, error) {
	files := append(append([]string{}, o.files...), args...)
	if len(files) > 0 {
		if o.image != "" || o.user != "" || o.pwFile != "" {
			return nil, fmt.Errorf("--config describes the shares and the users; --image, --user and --password-file do not go with it")
		}
		return loadConfig(files)
	}
	return o.oneImage()
}

// oneImage is the flag form: one image, one user, every protocol this binary
// has, each on a port that does not need root.
func (o *options) oneImage() (*config, error) {
	if o.image == "" {
		return nil, fmt.Errorf("nothing to serve: --image, or a configuration file")
	}
	if o.user == "" || o.pwFile == "" {
		// A share with no user is every stranger's. Refusing is the only
		// answer that cannot surprise somebody.
		return nil, fmt.Errorf("--image needs --user and --password-file: a share with nobody named on it is open to whoever can reach the port")
	}
	name := o.share
	if name == "" {
		name = defaultShareName(o.image)
	}
	cfg := &config{
		Name:   o.name,
		Users:  []userBlock{{Name: o.user, PasswordFile: o.pwFile}},
		Shares: []shareBlock{{Name: name, Image: o.image, ReadOnly: o.readOnly}},
	}
	for _, p := range protocols {
		if len(o.only) > 0 && !slices.Contains(o.only, p.name) {
			continue
		}
		cfg.Serves = append(cfg.Serves, serveBlock{Protocol: p.name})
	}
	if len(cfg.Serves) == 0 {
		return nil, fmt.Errorf("--protocol names none this binary has: it has %s", protocolNames())
	}
	if err := cfg.check(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// defaultShareName is the image's file name without its extension, which is
// what a person would have typed.
func defaultShareName(path string) string {
	base := path
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	if i := strings.LastIndex(base, "."); i > 0 {
		base = base[:i]
	}
	if base == "" {
		return "disk"
	}
	return base
}

// report prints what would be served, to whom, over what.
//
// The matrix is the point. `allow` and `writers` are easy to get subtly wrong,
// and the failure is silent -- the server starts, and somebody cannot see their
// own share, or everybody can see one that was meant for one person.
func report(cmd *cobra.Command, cfg *config) error {
	out := cmd.OutOrStdout()
	srv, err := open(cfg, out)
	if err != nil {
		return err
	}
	defer srv.Close()

	fmt.Fprintf(out, "%s\n\n", srv.name)
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	header := "SHARE\tIMAGE\tFILESYSTEM\tWHO MAY CONNECT\tWHO MAY WRITE"
	for _, b := range cfg.Serves {
		header += "\t" + strings.ToUpper(b.Protocol)
	}
	fmt.Fprintln(w, header)
	for _, sh := range srv.shares {
		row := fmt.Sprintf("%s\t%s\t%s\t%s\t%s", sh.name, sh.image, sh.kind, sh.who(), sh.writeAccess())
		for _, b := range cfg.Serves {
			p := protocolByName(b.Protocol)
			if !p.authenticates && sh.restricted() {
				row += "\tNO"
				continue
			}
			row += "\tyes"
		}
		fmt.Fprintln(w, row)
	}
	if err := w.Flush(); err != nil {
		return err
	}

	// Every refusal, spelled out. A column of NO says what happens; this says
	// why, and a person deciding whether to loosen a share needs the why.
	var said bool
	for _, b := range cfg.Serves {
		p := protocolByName(b.Protocol)
		_, refused := p.exports(srv.shares)
		for _, sh := range refused {
			if !said {
				fmt.Fprintln(out)
				said = true
			}
			fmt.Fprintf(out, "%s\n", p.refusal(sh))
		}
	}

	fmt.Fprintln(out)
	fmt.Fprintln(w, "USER\tPASSWORD FROM")
	for _, u := range cfg.Users {
		from := "the configuration file"
		if u.PasswordFile != "" {
			// The file is named; what is IN it is never printed.
			from = u.PasswordFile
		}
		fmt.Fprintf(w, "%s\t%s\n", u.Name, from)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(out, "\nthis configuration can be served")
	return nil
}

// noArgs refuses a leftover argument, and says what one usually means.
func noArgs(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return nil
	}
	arg := args[0]
	dashes := "flags take two dashes here -- --config, not -config -- and a single dash is\n" +
		"read as a short flag, which leaves the rest over. `fileshare --help` lists them"
	if strings.ContainsAny(arg, `/\.`) {
		return fmt.Errorf("unexpected argument %q\n\n%s", arg, dashes)
	}
	if near := cmd.Root().SuggestionsFor(arg); len(near) > 0 {
		return fmt.Errorf("unknown command %q\n\nDid you mean this?\n\t%s", arg, strings.Join(near, "\n\t"))
	}
	return fmt.Errorf("unknown command %q\n\nIf you meant a flag: %s", arg, dashes)
}

// flagError says what a single dash means to pflag.
func flagError(cmd *cobra.Command, err error) error {
	msg := err.Error()
	if i := strings.Index(msg, "unknown shorthand flag: "); i >= 0 {
		if j := strings.Index(msg, " in -"); j >= 0 {
			typed := msg[j+len(" in -"):]
			if len(typed) > 1 {
				return fmt.Errorf("%s\n\nflags take two dashes here: --%s, not -%s", msg, typed, typed)
			}
		}
	}
	return err
}

func version() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "unknown"
}
