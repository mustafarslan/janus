// janus-conformance checks that an integration built on Janus got the
// guarantees Janus offers.
//
// It reads an evidence directory and an expectation, and nothing else. It does
// not know how the integration works or what language it is written in — which
// is the point: two adapters that produce the same evidence are equally
// conformant, and one that produces different evidence is a different
// integration however similar its source looks.
//
//	janus-conformance -evidence ./janus-evidence -expect loan-desk.json \
//	                  -keys writer-keys.json
//
// The expectation is required. Every check this runs passes on a log with
// nothing in it, so a run that did not say what the integration was asked to do
// would be measuring nothing.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/mustafarslan/janus/pkg/conformance"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/registry"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "janus-conformance: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		dir      = flag.String("evidence", "./janus-evidence", "evidence directory to check")
		expect   = flag.String("expect", "", "JSON expectation: what the integration was asked to do")
		keyPath  = flag.String("keys", "", "writer public key set (janus-keys pub ...)")
		trustDir = flag.String("trust", "", "manifest-signing trust store, for the registry audit")
		unsealed = flag.Bool("allow-unsealed-tail", false,
			"permit the final segment to have no footer, which is normal while a writer is running")
		asJSON  = flag.Bool("json", false, "print the report as JSON")
		showVer = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()
	if *showVer {
		fmt.Println("janus-conformance", version)
		return nil
	}
	if *expect == "" {
		return errors.New("-expect is required: every check here passes on a log with " +
			"nothing in it, so a run has to say what the integration was asked to do")
	}

	raw, err := os.ReadFile(*expect)
	if err != nil {
		return fmt.Errorf("reading the expectation: %w", err)
	}
	var want conformance.Expectation
	if err := json.Unmarshal(raw, &want); err != nil {
		return fmt.Errorf("parsing the expectation: %w", err)
	}

	opts := conformance.Options{AllowUnsealedTail: *unsealed}
	if *keyPath != "" {
		set, kerr := loadKeys(*keyPath)
		if kerr != nil {
			return kerr
		}
		opts.Keys = set
	}
	if *trustDir != "" {
		trust, terr := loadTrust(*trustDir)
		if terr != nil {
			return terr
		}
		opts.Trust = trust
	}

	report, err := conformance.Run(*dir, want, opts)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else {
		fmt.Print(report)
	}
	if !report.Passed {
		os.Exit(1)
	}
	return nil
}

func loadKeys(path string) (keys.PublicKeySet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the key set: %w", err)
	}
	var set keys.PublicKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("parsing the key set: %w", err)
	}
	return set, nil
}

func loadTrust(path string) (registry.TrustStore, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the trust store: %w", err)
	}
	var byPrincipal map[string]json.RawMessage
	if err := json.Unmarshal(raw, &byPrincipal); err != nil {
		return nil, fmt.Errorf("parsing the trust store: %w", err)
	}
	trust := registry.TrustStore{}
	for principal, encoded := range byPrincipal {
		var set keys.PublicKeySet
		if err := json.Unmarshal(encoded, &set); err != nil {
			return nil, fmt.Errorf("trust store entry for %q: %w", principal, err)
		}
		for _, pub := range set {
			trust.Trust(principal, pub)
		}
	}
	return trust, nil
}
