// Command janus-verify checks Janus evidence offline.
//
// This is the binary handed to an auditor, a regulator, or a customer's own
// compliance function. It is a single static executable with no Janus service
// dependency, no network access, and no configuration beyond the artifact and
// the public keys it is told to trust: everything it concludes, it concludes
// from bytes on disk.
//
// Exit status is 0 when verification passes, 1 when it fails, and 2 when the
// artifact could not be read at all. Failing loudly matters more than being
// convenient — a verifier that shrugs is worse than no verifier.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mustafarslan/janus/pkg/evidence/bundle"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
	"github.com/mustafarslan/janus/pkg/tenancy"
)

// version is stamped at build time with -ldflags.
var version = "dev"

const usage = `janus-verify %s — offline verification of Janus evidence

usage:
  janus-verify [flags] <path>

<path> is either an exported bundle directory (one containing %s)
or a raw evidence segment directory.

flags:
`

func main() {
	var (
		keyFile    = flag.String("keys", "", "JSON file of trusted writer public keys (key id -> hex). These are the *roots*: a log that rotated its writer key declares each successor in a segment the previous one signed, so the first key is usually enough. Strongly recommended — without any, a bundle is checked against the keys it carries, which proves only internal consistency.")
		expectHead = flag.String("expect-head", "", "expected head chain hash, obtained out of band (e.g. from an anchor). Compared against the computed head.")
		allowOpen  = flag.Bool("allow-open-tail", false, "accept a final segment with no signed footer, as a log still being written will have")
		listEvents = flag.Bool("list", false, "list every verified event with its labels")
		asJSON     = flag.Bool("json", false, "emit the report as JSON")
		quiet      = flag.Bool("quiet", false, "print only the verdict line")
		reqSigned  = flag.Bool("require-signed-manifest", false, "for a bundle: fail unless its manifest is signed and the signature verifies against the -keys roots. A bundle cut off at its end is a valid prefix of a hash chain; only the signature over its segment list, or -expect-head, can show nothing was dropped.")
		tenant     = flag.String("tenant", "", "tenant this evidence is expected to belong to. Every event labelled with another tenant is a critical finding.")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), usage, version, bundle.ManifestName)
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVer {
		fmt.Printf("janus-verify %s\n", version)
		return
	}
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	target := flag.Arg(0)

	opts := verify.Options{
		AllowUnsealedTail:     *allowOpen,
		ExpectHeadChain:       *expectHead,
		RequireSignedManifest: *reqSigned,
		IncludeEvents:         *listEvents,
		Version:               version,
		Tenant:                tenancy.Tenant{ID: *tenant},
	}
	if err := opts.Tenant.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "janus-verify: %v\n", err)
		os.Exit(2)
	}
	if *keyFile != "" {
		set, err := loadKeys(*keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "janus-verify: %v\n", err)
			os.Exit(2)
		}
		opts.Keys = set
	}

	rep, err := verifyTarget(target, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "janus-verify: %v\n", err)
		os.Exit(2)
	}

	switch {
	case *asJSON:
		blob, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "janus-verify: %v\n", err)
			os.Exit(2)
		}
		fmt.Println(string(blob))
	case *quiet:
		fmt.Println(verdict(rep))
	default:
		fmt.Print(rep.Text())
	}

	if !rep.OK {
		os.Exit(1)
	}
}

// verifyTarget picks the right check by looking for a bundle manifest, so the
// caller does not have to know which kind of directory they were given.
func verifyTarget(target string, opts verify.Options) (*verify.Report, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory (expected a bundle or a segment directory)", target)
	}
	if _, err := os.Stat(filepath.Join(target, bundle.ManifestName)); err == nil {
		return verify.Bundle(target, opts)
	}
	if opts.RequireSignedManifest {
		// Refused rather than ignored: an auditor who asked for a signed
		// manifest and was handed a raw directory would otherwise read a pass
		// as meeting a requirement nothing checked.
		return nil, fmt.Errorf("%s is a segment directory, not a bundle, so it has no manifest to "+
			"require a signature on; use -expect-head for a raw log", target)
	}
	return verify.SegmentDir(target, opts)
}

func loadKeys(path string) (keys.PublicKeySet, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var set keys.PublicKeySet
	if err := json.Unmarshal(blob, &set); err != nil {
		return nil, fmt.Errorf("parse key file %s: %w", path, err)
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("key file %s contains no keys", path)
	}
	return set, nil
}

func verdict(r *verify.Report) string {
	status := "PASS"
	if !r.OK {
		status = "FAIL"
	}
	return fmt.Sprintf("%s %s events=%d seq=%d..%d head=%s", status, r.Target, r.Events, r.FirstSeq, r.LastSeq, r.HeadChain)
}
