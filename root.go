// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"slices"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/go-authn/directory"
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
	isolate  bool
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
	f.BoolVar(&o.isolate, "isolate", false,
		"serve each protocol in its own process, each opening only the images it may serve")
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
		RunE: func(cmd *cobra.Command, args []string) error {
			return serve(cmd, &o, args)
		},
	}
	o.bind(root.PersistentFlags())
	root.SuggestionsMinimumDistance = 2
	root.SetFlagErrorFunc(flagError)
	root.AddCommand(newServeCmd(&o), newCheckCmd(&o), newServeOneCmd(&o))
	return root
}

func newServeCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:           "serve",
		Short:         "Serve the shares and wait for clients",
		Args:          noArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return serve(cmd, o, args)
		},
	}
}

// serve reads the configuration, opens every image, and listens.
func serve(cmd *cobra.Command, o *options, args []string) error {
	cfg, err := configOf(o, nil)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if o.isolate {
		// The parent opens NOTHING: the images belong to the children, which
		// is the whole point. What it does check is that the configuration can
		// be honoured this way at all.
		shares := make([]*share, 0, len(cfg.Shares))
		for _, b := range cfg.Shares {
			shares = append(shares, &share{name: b.Name, readOnly: b.ReadOnly,
				allow: b.Allow, writers: b.Writers, protocols: b.Protocols})
		}
		if why := isolationRefusal(shares, cfg.Serves); why != "" {
			return errors.New(why)
		}
		return runIsolated(ctx, cfg, os.Stdout, append(append([]string{}, o.files...), args...))
	}

	srv, err := open(cfg, cmd.OutOrStdout())
	if err != nil {
		return err
	}
	defer srv.Close()

	// A signal closes the listeners, which lets the deferred Close above run
	// so every driver flushes whatever it was holding.
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
	// yes: served here. NO: this protocol cannot honour the share's own rules.
	// -: the share names other protocols.
	for _, sh := range srv.shares {
		row := fmt.Sprintf("%s\t%s\t%s\t%s\t%s", sh.name, sh.image, sh.kind, sh.who(), sh.writeAccess())
		for _, b := range cfg.Serves {
			// Asked of the function that DECIDES it, not derived again here:
			// a table that computes the answer a second way is a table that
			// can disagree with the server, and the reader would believe the
			// table.
			p := protocolByName(b.Protocol)
			served, refused := p.exports([]*share{sh})
			switch {
			case len(served) == 1:
				row += "\tyes"
			case len(refused) == 1:
				row += "\tNO"
			default:
				// Not refused: the share named other protocols.
				row += "\t-"
			}
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
	// What each person can PROVE, and therefore which protocols they can use.
	//
	// This is the honest half of taking users from a directory: an LDAP bind
	// answers WebDAV and cannot answer SMB, because NTLMv2 needs the password
	// or its MD4 and the client never sends one. Said here, with the reason,
	// rather than discovered by somebody at a mount.
	// Where a password was read from, per person: the file, not its contents.
	// A reader checking that alice's password comes from the file they think
	// it does can do it here, without opening anything.
	files := map[string]string{}
	for _, u := range cfg.Users {
		if u.PasswordFile != "" {
			files[u.Name] = u.PasswordFile
		}
	}
	header = "USER\tFROM\tAUTHENTICATES WITH"
	for _, b := range cfg.Serves {
		if protocolByName(b.Protocol).authenticates {
			header += "\t" + strings.ToUpper(b.Protocol)
		}
	}
	fmt.Fprintln(w, header)
	var stranded []string
	for _, who := range srv.sortedIdentities() {
		row, any := canUse(cfg, who)
		fmt.Fprintf(w, "%s\t%s\t%s%s\n", who.Name(), who.Where(), credentials(who, files), row)
		if !any {
			stranded = append(stranded, who.Name())
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}

	// A person who can prove NOTHING here is a person the configuration names
	// and no protocol can serve: worth a line of its own, because the table
	// says it in the negative and a reader scanning columns can miss it.
	if len(stranded) > 0 {
		fmt.Fprintf(out, "\n%s cannot use any protocol here: nothing in %s proves them\n",
			list(stranded), srv.dir.Describe())
	}

	// ⛔ Which protocols a TOKEN can be carried by, which is one. Said in the
	// same place as everything else a person cannot do, because a site that
	// points a browser at this and then tries to mount it over SMB with the
	// same account should find out here.
	if cfg.OIDC != nil {
		fmt.Fprintf(out, "\ntokens from %s are accepted over webdav and nowhere else: "+
			"SMB authenticates with NTLMv2, SFTP with a key, and NFS with nothing -- "+
			"none of them has anywhere to put a token\n", cfg.OIDC.Issuer)
		who := "somebody a token names must also be named here"
		if cfg.OIDC.TrustAll {
			who = "trust_all: anybody that provider vouches for is let in, whether or not this file knows them"
		}
		fmt.Fprintf(out, "%s\n", who)
	}

	fmt.Fprintln(out, "\nthis configuration can be served")
	return nil
}

// credentials says what a source could give for somebody, in the order a
// reader cares about: never what it IS, only what kind and where from.
func credentials(who *directory.Identity, files map[string]string) string {
	var have []string
	if who.Can(directory.Password) {
		have = append(have, "a password")
	} else if who.Can(directory.Verifier) {
		// A check the directory answers -- a bind, or a hash comparison --
		// which is a different thing from holding the password.
		have = append(have, "a password check")
	}
	if who.Can(directory.NTHash) && !who.Can(directory.Password) {
		have = append(have, "an NT hash")
	}
	if n := len(who.Keys()); n == 1 {
		have = append(have, "1 key")
	} else if n > 1 {
		have = append(have, fmt.Sprintf("%d keys", n))
	}
	if len(have) == 0 {
		return "nothing"
	}
	said := list(have)
	if f := files[who.Name()]; f != "" {
		said += " from " + f
	}
	return said
}

// canUse is one column per authenticating protocol, and whether ANY of them
// said yes -- returned rather than recomputed by comparing the row against a
// string of dashes, which is a spelling test and not a question about people.
func canUse(cfg *config, who *directory.Identity) (row string, any bool) {
	for _, b := range cfg.Serves {
		p := protocolByName(b.Protocol)
		if !p.authenticates {
			continue
		}
		ok := false
		switch b.Protocol {
		case "smb":
			// NTLMv2 needs the password or its MD4, and nothing else will do.
			ok = who.Can(directory.NTHash)
		case "webdav":
			ok = who.Can(directory.Verifier) || who.Can(directory.Password)
		case "sftp":
			// A trusted authority makes everybody able to present a
			// certificate, whatever this directory holds for them.
			ok = who.Can(directory.PublicKeys) || cfg.TrustedUserCAFile != ""
		}
		if ok {
			row += "\tyes"
			any = true
			continue
		}
		row += "\t-"
	}
	return row, any
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
