package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence/bundle"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// Backup and restore with proof continuity (Phase 6).
//
// A backup here is a bundle with the open tail included and the manifest signed.
// Not a new artifact shape: `bundle.Export` already produces the per-segment
// digests, the sequence bounds and the head chain, and `janus-verify` already
// reads what it writes. What a backup adds is the two things an audit bundle
// does not need — the unsealed tail, because leaving it out costs a whole
// segment of RPO, and a signature over the manifest, because an unsealed segment
// has no footer of its own and because a manifest an attacker can rewrite is a
// segment list they can shorten.
//
// # Proof continuity, as three claims that can be checked
//
// "The backup is good" is not testable. These are:
//
//  1. **Byte identity** — every restored segment hashes to the digest the
//     manifest names.
//  2. **Chain continuity across the boundary** — the restored directory verifies
//     from the original root and its computed head equals the manifest's
//     `HeadChain`. Nothing is re-signed and nothing is re-chained, which is why
//     a restore is a file copy and not a replay.
//  3. **Continuation** — an appender opened on the restored directory continues
//     the *same* chain, so records from before the backup and after the restore
//     verify as one log.
//
// The third is the one a well-meaning implementation breaks, and it has its own
// test.

func backup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	dir := fs.String("evidence", "", "evidence directory to back up")
	dest := fs.String("out", "", "directory to write the backup into; must not exist")
	keyPath := fs.String("key", "", "writer signing key, to sign the manifest with")
	pub := fs.String("keys", "", "public key set to record in the manifest (janus-keys pub)")
	rationale := fs.String("reason", "scheduled backup", "why this backup was taken")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *dest == "" || *keyPath == "" {
		return errors.New("-evidence, -out and -key are required")
	}
	if _, err := os.Stat(*dest); err == nil {
		return fmt.Errorf("%s already exists; refusing to write a backup over one that "+
			"may be the only copy of something", *dest)
	}

	signer, err := keys.Load(*keyPath)
	if err != nil {
		return fmt.Errorf("loading the signing key: %w", err)
	}
	set := keys.PublicKeySet{signer.KeyID(): signer.Public()}
	if *pub != "" {
		set, err = loadPublicKeys(*pub)
		if err != nil {
			return err
		}
	}

	start := time.Now()
	m, err := bundle.Export(bundle.ExportOptions{
		SegmentDir: *dir,
		Dest:       *dest,
		Keys:       set,
		Producer:   "janus-tier " + version,
		Rationale:  *rationale,
		// The open tail is the difference between a backup and an audit bundle.
		// Its torn end is cut off by Export rather than copied, so what lands
		// here is exactly the acknowledged prefix.
		IncludeUnsealed: true,
	})
	if err != nil {
		return fmt.Errorf("exporting: %w", err)
	}
	if err := bundle.SignManifest(*dest, signer); err != nil {
		return err
	}

	fmt.Printf("backed up %s to %s in %s\n", *dir, *dest, time.Since(start).Round(time.Millisecond))
	fmt.Printf("  events %d (seq %d..%d) across %d segments\n",
		m.Events, m.FirstSeq, m.LastSeq, len(m.Segments))
	fmt.Printf("  head   %s\n", m.HeadChain)
	fmt.Printf("  signed by %s\n", signer.KeyID())
	fmt.Printf("\nrestore with: janus-tier restore -backup %s -evidence <empty dir> -keys <roots>\n", *dest)
	return nil
}

// restorePhase is one measured step of a restore.
//
// Decomposed for the same reason the append path was: RTO is a number somebody
// will be asked to defend, and "restore took four minutes" cannot be improved
// or trusted. The phases are named so that the one that grows with the log is
// visible as such.
type restorePhase struct {
	Name string        `json:"name"`
	Took time.Duration `json:"took_ns"`
}

func restore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	src := fs.String("backup", "", "backup directory to restore from")
	dir := fs.String("evidence", "", "evidence directory to restore into; must be empty or absent")
	trust := fs.String("keys", "", "trusted writer public keys (janus-keys pub). Required: a\n"+
		"backup checked against the keys it carries proves only that it is\n"+
		"internally consistent, which is what a forger also produces")
	jsonOut := fs.String("json", "", "write the phase timings to this path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *src == "" || *dir == "" {
		return errors.New("-backup and -evidence are required")
	}
	if *trust == "" {
		return errors.New("-keys is required")
	}
	roots, err := loadPublicKeys(*trust)
	if err != nil {
		return err
	}

	var phases []restorePhase
	phase := func(name string, fn func() error) error {
		start := time.Now()
		err := fn()
		phases = append(phases, restorePhase{Name: name, Took: time.Since(start)})
		return err
	}

	// The signature first, because everything after it trusts the manifest: the
	// digest list, the segment list and the head. Checking the digests before
	// establishing that the list is the one the writer produced would be
	// checking an attacker's arithmetic.
	var m bundle.Manifest
	if err := phase("verify_manifest_signature", func() error {
		if err := bundle.VerifyManifestSignature(*src, roots); err != nil {
			if errors.Is(err, bundle.ErrUnsigned) {
				return fmt.Errorf("%w — this is an audit bundle, not a backup; a restore "+
					"needs a manifest signed by the writer, because an unsealed segment "+
					"has no footer of its own", err)
			}
			return err
		}
		var err error
		m, err = bundle.LoadManifest(*src)
		return err
	}); err != nil {
		return err
	}

	if err := phase("check_target", func() error { return emptyTarget(*dir) }); err != nil {
		return err
	}

	if err := phase("copy_segments", func() error { return copySegments(*src, *dir, m) }); err != nil {
		return err
	}

	// What is checked before this returns, and what is deliberately not.
	//
	// Not: any per-record work. `verify.SegmentDir` decodes every record header,
	// recomputes every chain hash and builds a Merkle tree per segment — that is
	// the 254.5 s at 100M events this whole design is arranged around, and
	// calling it here would have meant the restore could not meet its five-minute
	// recovery budget at the scale this design is justified by. An earlier version
	// did exactly that: it ran the full verification the design said it skipped.
	//
	// What is checked instead is sufficient rather than merely cheaper. The
	// signature authenticates the manifest's claims — the segment list, each
	// digest, the head — and the digests prove the files are exactly the ones the
	// writer bundled. An attacker without the writer key can neither drop a
	// segment (the manifest edit fails the signature) nor alter one (the digest
	// fails). What it does *not* establish is that the source log was internally
	// sound when the backup was taken: corruption faithfully bundled is
	// faithfully restored, and that is precisely the window the sweep closes.
	//
	// Still O(bytes) — blake3 at gigabytes a second, but linear. A smaller
	// constant, not a different shape.
	if err := phase("check_manifest_contiguity", func() error { return m.Contiguous() }); err != nil {
		return err
	}

	fmt.Printf("restored %s to %s\n", *src, *dir)
	fmt.Printf("  events %d (seq %d..%d), head %s\n", m.Events, m.FirstSeq, m.LastSeq, m.HeadChain)
	var total time.Duration
	for _, p := range phases {
		fmt.Printf("  %-28s %s\n", p.Name, p.Took.Round(time.Millisecond))
		total += p.Took
	}
	fmt.Printf("  %-28s %s\n", "total", total.Round(time.Millisecond))
	fmt.Printf("\nNo record in this log has been read. What has been established is that\n")
	fmt.Printf("the manifest is the writer's and the files are the ones it names.\n")
	fmt.Printf("Run:  janus-tier sweep -evidence %s -keys <roots>\n", *dir)
	fmt.Printf("Until that completes, these bytes are trusted on the signed manifest\n")
	fmt.Printf("and their digests alone.\n")

	if *jsonOut != "" {
		if err := writeJSON(*jsonOut, map[string]any{
			"backup": *src, "evidence": *dir, "events": m.Events,
			"head_chain": m.HeadChain, "phases": phases,
			"total_ns": total,
		}); err != nil {
			return err
		}
		fmt.Printf("\ntimings written to %s\n", *jsonOut)
	}
	return nil
}

// emptyTarget refuses a directory that already holds a log.
//
// The operator error this exists for happens at three in the morning: restoring
// over a live directory, or over a previous restore. Either would interleave two
// logs' segments and produce a directory whose sequence numbers jump, which the
// verifier calls damage long after the cause is gone.
// loadPublicKeys reads the same trusted-key file janus-verify and janus-replicad
// take, rather than a third format invented here.
func loadPublicKeys(path string) (keys.PublicKeySet, error) {
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

// writeJSON records the phase timings where a bench doc can read them.
func writeJSON(path string, v any) error {
	blob, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(blob, '\n'), 0o644)
}

func emptyTarget(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return os.MkdirAll(dir, 0o750)
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".jseg" {
			return fmt.Errorf("%s already contains segment files; restoring into it would "+
				"interleave two logs. Restore into an empty directory", dir)
		}
	}
	return nil
}

// copySegments copies the backup's segments and checks each digest.
//
// Byte identity is claim one of proof continuity, and it is checked here rather
// than trusted: a copy is where bytes get lost, and the manifest already says
// what each file should hash to.
func copySegments(src, dir string, m bundle.Manifest) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	for _, entry := range m.Segments {
		from := filepath.Join(src, entry.File)
		to := segment.Path(dir, entry.SegmentID)
		digest, err := copyAndDigest(from, to)
		if err != nil {
			return fmt.Errorf("restoring segment %d: %w", entry.SegmentID, err)
		}
		if digest != entry.Digest {
			return fmt.Errorf("segment %d does not match the manifest: the backup holds %s, "+
				"the manifest names %s", entry.SegmentID, digest, entry.Digest)
		}
	}
	return nil
}

func copyAndDigest(from, to string) (string, error) {
	blob, err := os.ReadFile(from)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(to, blob, 0o640); err != nil {
		return "", err
	}
	return bundle.FileDigest(to)
}
