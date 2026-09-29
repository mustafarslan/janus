package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/bundle"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// The audit bundle: the artifact janus-verify was written to read.
//
// # Why this exists
//
// `janus-verify` documents a bundle as its primary input and dispatches on the
// presence of a manifest. `bundle.Export` has produced one since Phase 0. But
// until this command, the only things that called it were the walking skeleton —
// a demonstration, not a deployment — and `janus-tier backup`, which produces a
// *backup*: the open tail included and the manifest signed. Restore's own error
// message names the other artifact ("this is an audit bundle, not a backup")
// while nothing in a deployment produced one. Criterion S1 is "passes a mock
// supervisory inspection using Janus evidence bundles alone", and an operator
// asked for a bundle had a demo binary and a backup to choose between.
//
// # How it differs from a backup, and why the difference is kept
//
// Sealed segments only. A backup includes the open tail because leaving it out
// costs a whole segment of RPO; an audit bundle excludes it because an unsealed
// segment carries no footer, so including one hands an auditor bytes that no
// signature covers. There is deliberately no flag to include it here: the two
// commands mean two things, and a flag that turned one into the other would make
// "which artifact is this" a question about how it was invoked.
//
// # What it does not do, said here rather than discovered later
//
// **It signs the manifest when given the writer's key (-key), and not
// otherwise.** An audit bundle is sealed segments, each authenticated by its own
// footer, and an exporter need not hold the writing key -- key custody left the
// writing process in Phase 5c. But the footers do not cover the *list*: the
// manifest signature does, which makes a signed audit bundle's
// end-truncation visible from the bytes alone, and an auditor can insist on one
// with janus-verify -require-signed-manifest.
//
// Unsigned, the residual risk is prefix truncation: an attacker who drops trailing
// segments leaves a shorter bundle that verifies perfectly, because a valid
// prefix of a hash chain is a valid hash chain. Neither the digests nor the
// contiguity check can see it — nothing inside an unsigned artifact can. What
// catches it is the head, compared against a value obtained out of band, which
// is what `janus-verify -expect-head` takes; an anchor outside Janus is not built.
// So the head is printed here in the form that flag wants, and the operator is
// told to convey it separately. That is a real instruction to a person, not a
// control, and it is described as one.
//
// A *signed* backup is different, and the difference became real only when
// `janus-verify` started checking the signature: shortening the segment list
// breaks it, so a truncated backup is now named from the bytes alone. That is
// the `truncated-bundle` attack in `janus-evilauditor`, which this command's
// work is what turned up.
func export(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	dir := fs.String("evidence", "", "evidence directory to export from")
	dest := fs.String("out", "", "bundle directory to create; must not exist")
	pub := fs.String("keys", "", "public key set to record in the manifest (janus-keys pub).\n"+
		"Required: an auditor who has no roots of their own checks the footers\n"+
		"against these, and a bundle that carries none can only be checked for\n"+
		"internal consistency")
	sagaID := fs.String("saga", "", "add Merkle inclusion proofs for this saga's events")
	reason := fs.String("reason", "", "why this export was made (audit request, DORA exit, ...);\n"+
		"recorded in the manifest's scope")
	partition := fs.String("partition", "", "log partition label, if the deployment uses them")
	keyPath := fs.String("key", "", "writer signing key: sign the manifest, so that dropping segments\n"+
		"from the end is visible from the bundle alone (janus-verify\n"+
		"-require-signed-manifest). Without it the bundle is unsigned, and only a\n"+
		"head conveyed out of band closes end-truncation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *dest == "" {
		return errors.New("-evidence and -out are required")
	}
	if *pub == "" {
		return errors.New("-keys is required: the manifest records the public keys an " +
			"auditor needs to check the segment footers, and a bundle that names none " +
			"can be checked only against itself. Produce one with janus-keys pub")
	}
	if _, err := os.Stat(*dest); err == nil {
		return fmt.Errorf("%s already exists; refusing to write a bundle over one that "+
			"may already have been handed to somebody", *dest)
	}
	set, err := loadPublicKeys(*pub)
	if err != nil {
		return err
	}

	start := time.Now()
	m, err := bundle.Export(bundle.ExportOptions{
		SegmentDir: *dir,
		Dest:       *dest,
		Keys:       set,
		Producer:   "janus-tier " + version,
		Partition:  *partition,
		SagaID:     *sagaID,
		Rationale:  *reason,
		// Sealed only. See the comment above: this is the difference between
		// this artifact and a backup, and it is not a flag.
		IncludeUnsealed: false,
	})
	if err != nil {
		return fmt.Errorf("exporting: %w", err)
	}
	if *keyPath != "" {
		signer, err := keys.Load(*keyPath)
		if err != nil {
			return fmt.Errorf("loading the signing key: %w", err)
		}
		if err := bundle.SignManifest(*dest, signer); err != nil {
			return err
		}
	}

	fmt.Printf("exported %s to %s in %s\n", *dir, *dest, time.Since(start).Round(time.Millisecond))
	fmt.Printf("  events %d (seq %d..%d) across %d sealed segment(s)\n",
		m.Events, m.FirstSeq, m.LastSeq, len(m.Segments))
	if m.Tenant != nil {
		fmt.Printf("  tenant %s\n", m.Tenant.ID)
		if m.Tenant.Unlabelled > 0 {
			fmt.Printf("  NOTE: %d event(s) here were written before the log was bound to a\n",
				m.Tenant.Unlabelled)
			fmt.Printf("        tenant, so this bundle is one tenant's evidence plus some that\n")
			fmt.Printf("        does not say whose it is.\n")
		}
	}
	if *sagaID != "" {
		fmt.Printf("  %d inclusion proof(s) for saga %s\n", len(m.Selection), *sagaID)
		if err := reportTheTail(*dir, *sagaID, len(m.Selection)); err != nil {
			return err
		}
	}

	fmt.Printf("\n  head %s\n", m.HeadChain)
	if *keyPath != "" {
		fmt.Printf("  manifest signed: dropping segments from the end breaks the signature\n")
		fmt.Printf("\nVerify it the way the auditor will:\n")
		fmt.Printf("  janus-verify -keys <roots> -require-signed-manifest %s\n", *dest)
		return nil
	}
	fmt.Printf("\nVerify it the way the auditor will:\n")
	fmt.Printf("  janus-verify -keys <roots> -expect-head %s %s\n", m.HeadChain, *dest)
	fmt.Printf("\nSend that head separately from the bundle. Nothing inside a bundle can\n")
	fmt.Printf("prove that records were not removed from its end: a valid prefix of a hash\n")
	fmt.Printf("chain is a valid hash chain. The head is what closes that, and only if it\n")
	fmt.Printf("reaches the auditor by some route the bundle did not.\n")
	return nil
}

// reportTheTail says how many of the saga's events did not make it in.
//
// The bundle stops at the last sealed segment, so a saga still being written has
// events in the open tail that no proof here covers. The bundle is not wrong —
// every claim in it is true — and that is exactly the problem:
// an accurate, incomplete artifact whose reader concludes more than it says. An
// auditor handed proofs for eleven of a saga's fourteen events, with nothing
// saying so, would reasonably believe they had the saga.
func reportTheTail(dir, sagaID string, inBundle int) error {
	var total int
	err := evidence.Walk(dir, func(h evidence.EventHeader, _ segment.Record) error {
		if h.SagaID == sagaID {
			total++
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("counting saga %s in %s: %w", sagaID, dir, err)
	}
	if total == 0 {
		fmt.Printf("  WARNING: saga %s has no events in %s at all. This bundle proves\n",
			sagaID, dir)
		fmt.Printf("           nothing about it.\n")
		return nil
	}
	if missing := total - inBundle; missing > 0 {
		fmt.Printf("  WARNING: %d of this saga's %d events are in the open tail and are NOT\n",
			missing, total)
		fmt.Printf("           in this bundle. Every proof here is sound; the set is not\n")
		fmt.Printf("           complete. Export again once the tail seals, or say plainly\n")
		fmt.Printf("           that this covers %d of %d.\n", inBundle, total)
	}
	return nil
}
