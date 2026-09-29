// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2/hclparse"
)

// Every ```hcl block in the README parses. Only the syntax is asked -- the
// paths in them do not exist here -- and that is what went wrong once: a
// one-line block holding two arguments, which HCL refuses, printed as the
// example of how to turn TLS on.
func TestTheREADMEsHCLParses(t *testing.T) {
	data, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	// \r?: on Windows git checks the README out with CRLF endings.
	blocks := regexp.MustCompile("(?s)```hcl\r?\n(.*?)```").FindAllStringSubmatch(string(data), -1)
	if len(blocks) < 5 {
		// The control: a pattern that finds nothing would pass forever.
		t.Fatalf("found %d hcl blocks in the README; the pattern is not finding them", len(blocks))
	}
	for i, b := range blocks {
		_, diags := hclparse.NewParser().ParseHCL([]byte(b[1]), "README.md")
		if diags.HasErrors() {
			t.Errorf("hcl block %d does not parse: %v\n%s", i+1, diags, strings.TrimSpace(b[1]))
		}
	}
}
