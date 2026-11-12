// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
)

// The macOS half of the mount check, without a build tag so that its parsing and
// matching run (and are fuzzed) on every platform.
//
// Source: hdiutil(1), `hdiutil info -plist`: a property list (Apple's
// PropertyList-1.0 DTD, XML form) whose top-level "images" array holds one
// dict per attached disk image, with "image-path" (the file), and
// "system-entities", an array of dicts with "dev-entry" (/dev/diskN) and, for a
// volume that is mounted, "mount-point". An image attached with -nomount is
// listed too, and counts: its blocks are exposed to the OS as a disk. No
// IOKit or DiskArbitration route is used: both would need cgo, and neither
// lists a disk image's backing file more directly than hdiutil does, which
// reads it from the DiskImages framework.

// attachedImage is one entry of `hdiutil info -plist`.
type attachedImage struct {
	Path   string   // image-path
	Devs   []string // dev-entry of each system entity
	Mounts []string // mount-point of each system entity that has one
}

const (
	plistMaxDepth = 32
	plistMaxNodes = 1 << 20
)

// plistNode is a decoded plist value: a dict, an array or a string. Other
// scalars (integer, real, date, data, true, false) are read and dropped.
type plistNode struct {
	kind string // "dict", "array", "string", or the scalar's tag
	str  string
	keys []string    // dict only, parallel to kids
	kids []plistNode // dict values or array elements
}

func (n plistNode) get(key string) (plistNode, bool) {
	for i, k := range n.keys {
		if k == key {
			return n.kids[i], true
		}
	}
	return plistNode{}, false
}

// parsePlist decodes the XML property list on r with encoding/xml, bounded in
// depth and size: its input is another program's output, read in a server.
func parsePlist(r io.Reader) (plistNode, error) {
	d := xml.NewDecoder(io.LimitReader(r, 32<<20))
	d.Strict = true
	// A plist names its DTD with a DOCTYPE; encoding/xml reads it as a
	// directive and does not fetch anything.
	nodes := 0
	var parse func(start xml.StartElement, depth int) (plistNode, error)
	parse = func(start xml.StartElement, depth int) (plistNode, error) {
		if depth > plistMaxDepth {
			return plistNode{}, errors.New("plist nested too deeply")
		}
		if nodes++; nodes > plistMaxNodes {
			return plistNode{}, errors.New("plist too large")
		}
		n := plistNode{kind: start.Name.Local}
		var key string
		haveKey := false
		var text strings.Builder
		for {
			tok, err := d.Token()
			if err != nil {
				return plistNode{}, err
			}
			switch t := tok.(type) {
			case xml.CharData:
				text.Write(t)
			case xml.StartElement:
				switch n.kind {
				case "dict":
					if t.Name.Local == "key" {
						var k string
						if err := d.DecodeElement(&k, &t); err != nil {
							return plistNode{}, err
						}
						key, haveKey = k, true
						continue
					}
					if !haveKey {
						return plistNode{}, errors.New("plist dict value with no key")
					}
					kid, err := parse(t, depth+1)
					if err != nil {
						return plistNode{}, err
					}
					n.keys = append(n.keys, key)
					n.kids = append(n.kids, kid)
					haveKey = false
				case "array", "plist":
					kid, err := parse(t, depth+1)
					if err != nil {
						return plistNode{}, err
					}
					n.kids = append(n.kids, kid)
				default:
					return plistNode{}, fmt.Errorf("plist: <%s> inside <%s>", t.Name.Local, n.kind)
				}
			case xml.EndElement:
				if n.kind == "string" {
					n.str = text.String()
				}
				return n, nil
			}
		}
	}
	for {
		tok, err := d.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return plistNode{}, errors.New("plist: no <plist> element")
			}
			return plistNode{}, err
		}
		if s, ok := tok.(xml.StartElement); ok {
			if s.Name.Local != "plist" {
				return plistNode{}, fmt.Errorf("plist: root is <%s>", s.Name.Local)
			}
			root, err := parse(s, 0)
			if err != nil {
				return plistNode{}, err
			}
			if len(root.kids) != 1 {
				return plistNode{}, errors.New("plist: want one value in <plist>")
			}
			return root.kids[0], nil
		}
	}
}

// parseHdiutilInfo reads `hdiutil info -plist` output.
func parseHdiutilInfo(r io.Reader) ([]attachedImage, error) {
	root, err := parsePlist(r)
	if err != nil {
		return nil, err
	}
	if root.kind != "dict" {
		return nil, errors.New("hdiutil info: top level is not a dict")
	}
	imgs, ok := root.get("images")
	if !ok || imgs.kind != "array" {
		return nil, errors.New("hdiutil info: no images array")
	}
	var out []attachedImage
	for _, im := range imgs.kids {
		if im.kind != "dict" {
			continue
		}
		var a attachedImage
		if p, ok := im.get("image-path"); ok && p.kind == "string" {
			a.Path = p.str
		}
		if ents, ok := im.get("system-entities"); ok && ents.kind == "array" {
			for _, e := range ents.kids {
				if e.kind != "dict" {
					continue
				}
				if v, ok := e.get("dev-entry"); ok && v.kind == "string" {
					a.Devs = append(a.Devs, v.str)
				}
				if v, ok := e.get("mount-point"); ok && v.kind == "string" {
					a.Mounts = append(a.Mounts, v.str)
				}
			}
		}
		out = append(out, a)
	}
	return out, nil
}

// attachedHolder says which attached image is the file fi, matching by device
// and inode (os.SameFile) and never by path string, and describes it.
//
// A path that is not there (ENOENT) cannot be this image and is skipped. Any
// other stat error (EACCES, ELOOP, ...) means that entry could not be judged:
// if nothing else matches, it is returned, so image_mount_unknown decides.
func attachedHolder(fi os.FileInfo, imgs []attachedImage) (string, error) {
	var unjudged error
	for _, a := range imgs {
		if a.Path == "" {
			continue
		}
		afi, err := os.Stat(a.Path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			if unjudged == nil {
				unjudged = err
			}
			continue
		}
		if !os.SameFile(fi, afi) {
			continue
		}
		d := "attached"
		if len(a.Devs) > 0 {
			d += " as " + strings.Join(a.Devs, ", ")
		}
		if len(a.Mounts) > 0 {
			d += ", mounted at " + strings.Join(a.Mounts, ", ")
		}
		return d, nil
	}
	if unjudged != nil {
		return "", fmt.Errorf("could not judge an attached image's path: %w", unjudged)
	}
	return "", nil
}
