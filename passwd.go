// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/go-authn/directory/hcldir"
	"github.com/spf13/cobra"
)

// newPasswdCmd changes a password for somebody written down in the
// configuration.
//
// ⛔ Only for a person a `user` block declares. Somebody served from a
// database or an LDAP directory is changed where they live, by whatever owns
// that -- this server reads those and does not write them, and saying so is
// more use than a generic failure.
func newPasswdCmd(o *options) *cobra.Command {
	var pwFile string
	cmd := &cobra.Command{
		Use:   "passwd <user> [file or directory...]",
		Short: "Change the password of somebody written in the configuration",
		Long: `passwd writes a new password for a person declared by a user block.

Where it goes is decided by that block: a password_file has its FILE
rewritten and the configuration is left alone, and an inline password is
edited in place, keeping the comments and spacing around it. A block that
also carries an nt_hash has it recomputed, because NTLMv2 works from the hash
and SMB would otherwise go on accepting the old password.

The new password is read from a file, or from standard input with "-". It is
never a flag: an argument is visible in the process list to every user on the
machine.`,
		Args:          cobra.MinimumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if pwFile == "" {
				return errors.New("--password-file: the new password comes from a file, or from \"-\" for standard input")
			}
			user := args[0]
			paths := expandConfigPaths(append(append([]string{}, o.files...), args[1:]...))
			if len(paths) == 0 {
				return errors.New("no configuration: give a .hcl file or a directory of them")
			}
			password, err := readPassword(cmd.InOrStdin(), pwFile)
			if err != nil {
				return err
			}
			if err := hcldir.SetPassword(paths, user, password); err != nil {
				if errors.Is(err, hcldir.ErrNotDeclared) {
					return fmt.Errorf("%w -- somebody served from a database or an "+
						"LDAP directory is changed where they live, not here", err)
				}
				return err
			}
			// ⛔ A running server read the configuration once, at startup. It
			// is still answering the OLD password, and nothing about this
			// command changes that -- saying "done" without saying so would
			// leave somebody wondering why their new password is refused.
			fmt.Fprintf(cmd.OutOrStdout(),
				"%s: password changed. A server already running still holds the old one until it is restarted.\n",
				user)
			return nil
		},
	}
	cmd.Flags().StringVarP(&pwFile, "password-file", "p", "",
		`a file holding the new password, or "-" for standard input`)
	return cmd
}

// readPassword is the new password, from a file or from standard input.
//
// ⛔ One trailing newline is removed and nothing else is touched. A password
// may legitimately end in spaces, and trimming them would let somebody set one
// they can never type back; a file written by `echo` ends in exactly one
// newline, which is not part of it.
func readPassword(stdin io.Reader, path string) (string, error) {
	var (
		raw []byte
		err error
	)
	if path == "-" {
		raw, err = io.ReadAll(stdin)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return "", fmt.Errorf("reading the new password: %w", err)
	}
	s := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	if s == "" {
		return "", errors.New("the new password is empty, which would let anybody in as this person")
	}
	return s, nil
}
