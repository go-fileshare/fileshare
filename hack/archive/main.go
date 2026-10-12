// SPDX-License-Identifier: BSD-3-Clause

// Command archive packs a directory into a .tar.gz or a .zip that depends on
// nothing but its input and the Go that runs it: entries in byte order, owner
// 0:0, one modification time for every entry, no name or time in the gzip
// header. hack/release.sh uses it so that a release archive rebuilt anywhere
// -- macOS, Linux, BSD -- with the same Go is the same bytes. The system's
// tar and gzip are not: Apple's gzip and GNU's compress the same tar stream
// to different bytes.
//
//	go run ./hack/archive -mtime 1760203143 -o out.tar.gz -C parent dir
package main

import (
	"archive/tar"
	"archive/zip"
	"compress/flate"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

func main() {
	out := flag.String("o", "", "the archive to write: .tar.gz or .zip")
	parent := flag.String("C", ".", "the directory the entry is named relative to")
	mtime := flag.Int64("mtime", 0, "the modification time of every entry, in seconds since the epoch")
	flag.Parse()
	if *out == "" || flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: archive -mtime SECONDS -o OUT.tar.gz|OUT.zip [-C PARENT] DIR")
		os.Exit(2)
	}
	if err := pack(*out, *parent, flag.Arg(0), time.Unix(*mtime, 0).UTC()); err != nil {
		fmt.Fprintln(os.Stderr, "archive:", err)
		os.Exit(1)
	}
}

type entry struct {
	name string // slash-separated, relative to parent
	path string
	info fs.FileInfo
}

// walk lists dir under parent, in byte order of the names.
func walk(parent, dir string) ([]entry, error) {
	var es []entry
	err := filepath.WalkDir(filepath.Join(parent, dir), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(parent, p)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() && !info.IsDir() {
			return fmt.Errorf("%s: only files and directories are archived", p)
		}
		es = append(es, entry{name: filepath.ToSlash(rel), path: p, info: info})
		return nil
	})
	slices.SortFunc(es, func(a, b entry) int { return strings.Compare(a.name, b.name) })
	return es, err
}

// mode is the permission an entry is archived with: executable or not, never
// the umask of the machine that built it.
func mode(info fs.FileInfo) int64 {
	switch {
	case info.IsDir():
		return 0o755
	case info.Mode()&0o111 != 0:
		return 0o755
	}
	return 0o644
}

func pack(out, parent, dir string, when time.Time) (err error) {
	es, err := walk(parent, dir)
	if err != nil {
		return err
	}
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	switch {
	case strings.HasSuffix(out, ".tar.gz"):
		return packTar(f, es, when)
	case strings.HasSuffix(out, ".zip"):
		return packZip(f, es, when)
	}
	return errors.New("the archive must end in .tar.gz or .zip")
}

func packTar(w io.Writer, es []entry, when time.Time) error {
	gz, err := gzip.NewWriterLevel(w, gzip.BestCompression) // no Name, ModTime zero: nothing of the machine
	if err != nil {
		return err
	}
	tw := tar.NewWriter(gz)
	for _, e := range es {
		// USTAR: no access or change times, which PAX would add; the names
		// here are short enough for it. Owner 0:0, no user or group name.
		h := &tar.Header{Name: e.name, Mode: mode(e.info), ModTime: when, Format: tar.FormatUSTAR}
		if e.info.IsDir() {
			h.Typeflag, h.Name = tar.TypeDir, e.name+"/"
		} else {
			h.Typeflag, h.Size = tar.TypeReg, e.info.Size()
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if !e.info.IsDir() {
			if err := copyFile(tw, e.path); err != nil {
				return err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func packZip(w io.Writer, es []entry, when time.Time) error {
	zw := zip.NewWriter(w)
	zw.RegisterCompressor(zip.Deflate, func(out io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(out, flate.BestCompression)
	})
	for _, e := range es {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate, Modified: when}
		h.SetMode(fs.FileMode(mode(e.info)))
		if e.info.IsDir() {
			h.Name, h.Method = e.name+"/", zip.Store
			h.SetMode(fs.ModeDir | 0o755)
		}
		fw, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		if !e.info.IsDir() {
			if err := copyFile(fw, e.path); err != nil {
				return err
			}
		}
	}
	return zw.Close()
}

func copyFile(w io.Writer, p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}
