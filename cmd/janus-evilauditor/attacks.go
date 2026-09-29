package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/bundle"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
	"google.golang.org/protobuf/proto"
)

// The attack list is quoted rather than paraphrased, so that the suite can be
// checked against the list it was written from:
//
//	"attempts include back-dating events, forging writer signatures, replaying
//	old segments, shredding-then-claiming-integrity, double-releasing effects,
//	registering a participant with a false REVERSIBLE claim, prompt-injecting a
//	tool result to trigger an unauthorized wire."
//
// Two of those are already the subject of a standing gate elsewhere and are
// referenced rather than reimplemented — see `coveredElsewhere` at the bottom.
// The rest are here.
func attacks() []attack {
	return []attack{
		backDatedEvent(),
		forgedWriterSignature(),
		replayedOldSegment(),
		shredThenClaimIntegrity(),
		forgedRelease(),
		mutatedByte(),
		removedSegment(),
		truncatedBundle(),
		truncatedAuditBundle(),
	}
}

// truncatedAuditBundle is truncated-bundle against an UNSIGNED audit bundle,
// performed carefully: the last segment dropped, and the manifest's segment
// list, last sequence, event count and head all rewritten to agree with what is
// left. The result is a valid prefix of a hash chain and verifies -- which is
// why this suite once listed it as not covered.
//
// What names it now is the auditor's own requirement: janus-verify
// -require-signed-manifest refuses a bundle whose segment list nobody signed.
// The attack is run the way that auditor runs the check.
func truncatedAuditBundle() attack {
	return attack{
		name: "truncated-audit-bundle",
		goal: "hand an auditor who requires a signed manifest an unsigned bundle that stops early",
		run: func(h *harness) outcome {
			if err := h.writeLog(150); err != nil {
				return undetected("setup: " + err.Error())
			}
			dest := filepath.Join(h.root, "audit")
			m, err := bundle.Export(bundle.ExportOptions{
				SegmentDir: h.dir, Dest: dest, Keys: h.keySet(),
				Producer: "janus-evilauditor " + version,
			})
			if err != nil {
				return undetected("setup: exporting: " + err.Error())
			}
			if len(m.Segments) < 3 {
				return undetected("setup: the fixture did not rotate enough to drop a tail")
			}
			path := filepath.Join(dest, bundle.ManifestName)
			blob, err := os.ReadFile(path)
			if err != nil {
				return undetected("setup: " + err.Error())
			}
			var raw map[string]any
			if err := json.Unmarshal(blob, &raw); err != nil {
				return undetected("setup: " + err.Error())
			}
			segs := raw["segments"].([]any)
			gone := segs[len(segs)-1].(map[string]any)
			raw["segments"] = segs[:len(segs)-1]
			raw["last_seq"] = segs[len(segs)-2].(map[string]any)["last_seq"]
			raw["events"] = raw["events"].(float64) - gone["records"].(float64)
			delete(raw, "head_chain")
			if err := os.Remove(filepath.Join(dest, gone["file"].(string))); err != nil {
				return undetected("setup: " + err.Error())
			}
			write := func() error {
				out, err := json.MarshalIndent(raw, "", "  ")
				if err != nil {
					return err
				}
				return os.WriteFile(path, out, 0o640)
			}
			if err := write(); err != nil {
				return undetected("setup: " + err.Error())
			}
			// The attacker checks their own work and writes down the head the
			// shortened chain really has.
			mine, err := verify.Bundle(dest, verify.Options{Keys: h.keySet(), Version: version})
			if err != nil {
				return undetected("setup: " + err.Error())
			}
			raw["head_chain"] = mine.HeadChain
			if err := write(); err != nil {
				return undetected("setup: " + err.Error())
			}
			if again, err := verify.Bundle(dest, verify.Options{Keys: h.keySet(), Version: version}); err != nil || !again.OK {
				return undetected("setup: the truncation was not clean, so this is not the attack " +
					"it claims to be")
			}

			rep, err := verify.Bundle(dest, verify.Options{
				Keys: h.keySet(), Version: version, RequireSignedManifest: true,
			})
			if err != nil {
				return detected("janus-verify", err.Error())
			}
			if f, ok := named(rep, "MANIFEST_UNSIGNED"); ok && f.Severity == verify.Critical {
				return detected("janus-verify -require-signed-manifest", f.Code+": "+f.Message)
			}
			return undetected("an auditor required a signed manifest and passed an unsigned bundle " +
				"cut off at its end")
		},
	}
}

// truncatedBundle drops records from the END of an artifact rather than the
// middle, which is a different attack and was not in this suite until the
// audit-bundle work performed it by hand.
//
// `removed-segment` takes a segment from the middle and the chain names it: the
// sequence jumps, the hashes do not join up. Taking segments from the *end*
// leaves a valid prefix of a hash chain, which is a valid hash chain. Every
// digest matches, every footer verifies, the chain is contiguous, and the
// verifier says PASS. Nothing inside the artifact can see it, and no amount of
// checking harder will change that — the missing records are missing.
//
// The attack is performed against a **signed** bundle, the artifact `janus-tier
// backup` produces, because that is where the system has an answer from the
// bytes alone: the manifest names the segments and the signature covers the
// manifest, so shortening the list breaks it. Until the audit-bundle work,
// nothing an auditor ran checked that signature, and this attack succeeded
// silently against a correctly signed backup.
//
// For an **unsigned** audit bundle the honest answer is that the artifact cannot
// name this and is not supposed to. What names it is the head chain compared
// against a value obtained out of band, which is a practice rather than a
// control, and closing it properly needs an anchor outside Janus's control,
// which is not built. That is recorded in coveredElsewhere so that reading this
// suite does not leave an impression the unsigned case is covered.
func truncatedBundle() attack {
	return attack{
		name: "truncated-bundle",
		goal: "hand the auditor a bundle that stops just before the part I did not want them to see",
		run: func(h *harness) outcome {
			if err := h.writeLog(150); err != nil {
				return undetected("setup: " + err.Error())
			}
			dest := filepath.Join(h.root, "backup")
			m, err := bundle.Export(bundle.ExportOptions{
				SegmentDir: h.dir, Dest: dest, Keys: h.keySet(),
				Producer: "janus-evilauditor " + version,
			})
			if err != nil {
				return undetected("setup: exporting: " + err.Error())
			}
			if len(m.Segments) < 3 {
				return undetected("setup: the fixture did not rotate enough to drop a tail")
			}
			if err := bundle.SignManifest(dest, h.signer); err != nil {
				return undetected("setup: signing: " + err.Error())
			}

			// Drop the last segment and adjust the manifest so that everything
			// left agrees with everything else. This is the whole attack: what
			// remains is a shorter, internally perfect bundle.
			blob, err := os.ReadFile(filepath.Join(dest, bundle.ManifestName))
			if err != nil {
				return undetected("setup: " + err.Error())
			}
			var raw map[string]any
			if err := json.Unmarshal(blob, &raw); err != nil {
				return undetected("setup: " + err.Error())
			}
			segs := raw["segments"].([]any)
			gone := segs[len(segs)-1].(map[string]any)
			raw["segments"] = segs[:len(segs)-1]
			last := segs[len(segs)-2].(map[string]any)
			raw["last_seq"] = last["last_seq"]
			if err := os.Remove(filepath.Join(dest, gone["file"].(string))); err != nil {
				return undetected("setup: " + err.Error())
			}
			out, err := json.MarshalIndent(raw, "", "  ")
			if err != nil {
				return undetected("setup: " + err.Error())
			}
			if err := os.WriteFile(filepath.Join(dest, bundle.ManifestName), out, 0o640); err != nil {
				return undetected("setup: " + err.Error())
			}

			// The auditor's own command: the bundle, and the roots they were
			// handed. No head supplied, because the point is what the artifact
			// alone can establish.
			rep, err := verify.Bundle(dest, verify.Options{Keys: h.keySet(), Version: version})
			if err != nil {
				return detected("janus-verify", err.Error())
			}
			if f, ok := named(rep, "MANIFEST_SIGNATURE_INVALID"); ok && f.Severity == verify.Critical {
				return detected("janus-verify", f.Code+": "+f.Message)
			}
			return undetected("segments were dropped from the end of a SIGNED bundle and the " +
				"verifier reported nothing: the signature over the segment list was not checked")
		},
	}
}

// backDatedEvent writes a record claiming to have happened last week.
//
// The door is `Request.Wall`, which exists so a replay or an import can
// reproduce an existing record and which therefore lets a caller choose a
// timestamp. The chain does not care — ordering comes from the HLC, which the
// writer assigns and which cannot move backwards — but the wall reading is the
// *regulatory* timestamp (MiFID II RTS 25), and an evidence log whose
// timestamps are chosen by whoever writes them is not an audit trail.
//
// Until this suite existed, nothing detected it.
func backDatedEvent() attack {
	return attack{
		name: "back-dated-event",
		goal: "make an action appear to have happened inside a reporting period it missed",
		run: func(h *harness) outcome {
			if err := h.writeLog(30); err != nil {
				return undetected("setup: " + err.Error())
			}
			a, err := h.openAppender()
			if err != nil {
				return undetected("setup: " + err.Error())
			}
			// A week ago, through the writer's own API, with the writer's key.
			_, err = a.Append(context.Background(), evidence.Request{
				Kind: evidence.KindStepResult, SagaID: "sg_victim", StepID: "st_backdated",
				Participant: evidence.ParticipantRef{ID: "ag_honest", ManifestVersion: "1.0.0"},
				Payload:     []byte(`{"amount":"9999999"}`),
				Wall:        time.Now().Add(-7 * 24 * time.Hour),
			})
			_ = a.Close()
			if err != nil {
				return prevented("the appender", err.Error())
			}

			rep, verr := h.verifyFrom()
			if verr != nil {
				return undetected("the verifier could not read the log: " + verr.Error())
			}
			if f, ok := named(rep, "TIMESTAMP_IMPLAUSIBLE"); ok {
				return detected("janus-verify", f.Message)
			}
			return undetected("the record is in the log with a timestamp of the adversary's " +
				"choosing, and the verifier reports nothing about it")
		},
	}
}

// forgedWriterSignature re-signs a sealed segment with a key the log never
// declared.
//
// The adversary here has the disk and a key of their own. They want to replace a
// segment's contents and make the footer agree with the replacement.
func forgedWriterSignature() attack {
	return attack{
		name: "forged-writer-signature",
		goal: "replace a sealed segment's contents and re-sign the footer so it checks out",
		run: func(h *harness) outcome {
			if err := h.writeLog(120); err != nil {
				return undetected("setup: " + err.Error())
			}
			victim, err := h.firstSealed()
			if err != nil {
				return undetected("setup: " + err.Error())
			}
			// The adversary cannot re-sign our segment — they do not have the
			// writer's key — so they do what they actually can: seal a segment
			// of their own, with their own key, and put it where ours was. The
			// result is a file that is internally perfect and is not ours, which
			// is the only shape "forging a writer signature" can really take.
			forged, err := h.segmentSignedByAStranger()
			if err != nil {
				return undetected("setup: " + err.Error())
			}
			if err := os.WriteFile(victim, forged, 0o640); err != nil {
				return undetected("setup: " + err.Error())
			}

			rep, verr := h.verifyFrom()
			if verr != nil {
				return detected("janus-verify", verr.Error())
			}
			if f, ok := named(rep, "UNKNOWN_SIGNING_KEY"); ok {
				return detected("janus-verify", f.Message)
			}
			if f, ok := named(rep, "SIGNATURE_INVALID"); ok {
				return detected("janus-verify", f.Message)
			}
			return undetected("a segment signed by a key the log never declared verified")
		},
	}
}

// replayedOldSegment puts a stale copy of a segment back over the current one.
//
// The adversary kept a copy from before something inconvenient was recorded and
// restores it, hoping the log reads as though the later records were never
// written.
func replayedOldSegment() attack {
	return attack{
		name: "replayed-old-segment",
		goal: "roll a segment back to an earlier state so later records disappear",
		run: func(h *harness) outcome {
			if err := h.writeLog(60); err != nil {
				return undetected("setup: " + err.Error())
			}
			victim, err := h.firstSealed()
			if err != nil {
				return undetected("setup: " + err.Error())
			}
			// The copy the adversary kept: this segment as it stood before its
			// last few records. Truncating to an earlier record boundary is the
			// same thing as restoring an older copy, and needs no time machine.
			insp, err := segment.Inspect(victim)
			if err != nil || len(insp.Offsets) < 4 {
				return undetected("setup: not enough records to roll back")
			}
			if err := os.Truncate(victim, insp.Offsets[len(insp.Offsets)-3]); err != nil {
				return undetected("setup: " + err.Error())
			}

			rep, verr := h.verifyFrom()
			if verr != nil {
				return detected("janus-verify", verr.Error())
			}
			for _, code := range []string{"FOOTER_COUNT_MISMATCH", "MERKLE_ROOT_MISMATCH",
				"SEQUENCE_GAP", "CHAIN_BREAK", "SEGMENT_TORN", "FOOTER_RANGE_MISMATCH"} {
				if f, ok := named(rep, code); ok {
					return detected("janus-verify", f.Code+": "+f.Message)
				}
			}
			return undetected("a rolled-back segment verified, so records can be removed " +
				"from history without anybody being told")
		},
	}
}

// shredThenClaimIntegrity destroys a data subject's key and then asks whether
// the log still claims to be intact.
//
// This one is not about catching a forger. Crypto-shredding is a *feature*
// (lawful erasure): the ciphertext stays in the chain and the key is destroyed, so the
// hashes still check out and the log still verifies. The adversarial question is
// narrower and sharper — **does the verifier let that pass silently?** A report
// that says "intact" without saying "and some of it can no longer be read" is a
// report an auditor would be entitled to feel misled by.
func shredThenClaimIntegrity() attack {
	return attack{
		name: "shred-then-claim-integrity",
		goal: "erase content and have the verifier still report an unqualified clean bill",
		run: func(h *harness) outcome {
			// A real shred, not a note saying one would be hard to arrange. The
			// first version of this attack returned "not applicable" and counted
			// it as a catch, which is a green light written for an attack that
			// was never performed — the exact move this suite exists to catch
			// other people making.
			ref, err := h.shredASubject()
			if err != nil {
				return undetected("setup: " + err.Error())
			}

			rep, verr := h.verifyFrom()
			if verr != nil {
				return undetected("the verifier could not read the log after a lawful " +
					"erasure, which would make crypto-shredding unusable: " + verr.Error())
			}
			// The chain must still verify — that is what crypto-shredding is for,
			// and a shred that broke the log would be a different bug.
			if crit := findings(rep, verify.Critical); len(crit) > 0 {
				return undetected("an erasure broke the chain (" + crit[0].Code + "), so erasure " +
					"destroys evidence rather than only content")
			}
			// And it must not report an unqualified clean bill. Something in the
			// report has to tell an auditor that content is present-but-unreadable.
			for _, code := range []string{"ERASURES_RECORDED", "PAYLOAD_UNCHECKED",
				"PAYLOAD_MISSING", "PAYLOAD_UNREADABLE"} {
				if f, ok := named(rep, code); ok {
					return detected("janus-verify", f.Code+": "+f.Message)
				}
			}
			return undetected("after erasing a data subject the verifier reported an " +
				"unqualified clean bill: nothing in the report says that content in this " +
				"log can no longer be read, and the shred receipt at " + ref +
				" is the only record that it happened")
		},
	}
}

// forgedRelease writes an effect-release record for a saga that never
// committed.
//
// The adversary wants the log to show that a payment was authorised. They have
// the writer's API, so they can append whatever record they like — and the
// question is whether anybody reading the log afterwards can tell.
func forgedRelease() attack {
	return attack{
		name: "forged-effect-release",
		goal: "make the log show an irreversible effect as authorised by a commit that never happened",
		run: func(h *harness) outcome {
			// No decoy records. The first version of this attack wrote a log of
			// JSON step results first, and the audit "caught" the forgery by
			// failing to replay *those* — a pass for entirely the wrong reason,
			// and the sort a suite like this exists to be ashamed of. The log
			// here contains the forged effect and nothing else, so a catch can
			// only be a catch.
			a, err := h.openAppender()
			if err != nil {
				return undetected("setup: " + err.Error())
			}
			// Held and then released, with the payloads the outbox actually
			// reads, for a saga that never committed. A bare release would be
			// refused by the fold's transition rules and would prove only that
			// the adversary was clumsy.
			held, _ := proto.Marshal(&janusv1.EffectHeld{
				EffectId: "ef_forged", SagaId: "sg_never_committed", StepId: "st_wire",
				Target: "payments", Action: "wire_transfer", IdemKey: "idem-ef_forged",
				EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
			})
			if _, err = a.Append(context.Background(), evidence.Request{
				Kind: evidence.KindEffectHeld, SagaID: "sg_never_committed", StepID: "st_wire",
				Participant: evidence.ParticipantRef{ID: "ag_honest", ManifestVersion: "1.0.0"},
				Payload:     held,
			}); err == nil {
				releasing, _ := proto.Marshal(&janusv1.EffectReleasing{
					EffectId: "ef_forged", SagaId: "sg_never_committed", Attempt: 1,
					CommitRoot: []byte("a root nobody can produce"), IdemKey: "idem-ef_forged",
				})
				_, err = a.Append(context.Background(), evidence.Request{
					Kind: evidence.KindEffectReleasing, SagaID: "sg_never_committed",
					StepID:      "st_wire",
					Participant: evidence.ParticipantRef{ID: "ag_honest", ManifestVersion: "1.0.0"},
					Payload:     releasing,
				})
			}
			_ = a.Close()
			if err != nil {
				return prevented("the appender", err.Error())
			}

			// pkg/outbox's audit is the mechanism that answers this from the log
			// alone: given only the directory, was any irreversible effect
			// released without a commit that authorised it?
			found, detail := auditFindsForgedRelease(h.dir)
			if found {
				return detected("outbox.Audit", detail)
			}
			return undetected("a release record naming a saga that never committed is in " +
				"the log and the audit does not name it: " + detail)
		},
	}
}

// mutatedByte flips one byte in a sealed segment.
//
// The oldest attack and the one the whole format exists to defeat. It is in the
// suite because a standing adversarial gate that omitted it would be a gate
// nobody would trust, and because it is the control against which the others are
// read: if this were ever *not* caught, no other result here would mean anything.
func mutatedByte() attack {
	return attack{
		name: "mutated-byte",
		goal: "change one byte of a recorded fact and have the log still verify",
		run: func(h *harness) outcome {
			if err := h.writeLog(120); err != nil {
				return undetected("setup: " + err.Error())
			}
			victim, err := h.firstSealed()
			if err != nil {
				return undetected("setup: " + err.Error())
			}
			blob, err := os.ReadFile(victim)
			if err != nil {
				return undetected("setup: " + err.Error())
			}
			blob[len(blob)/2] ^= 0x01
			if err := os.WriteFile(victim, blob, 0o640); err != nil {
				return undetected("setup: " + err.Error())
			}

			rep, verr := h.verifyFrom()
			if verr != nil {
				return detected("janus-verify", verr.Error())
			}
			if crit := findings(rep, verify.Critical); len(crit) > 0 {
				return detected("janus-verify", crit[0].Code+": "+crit[0].Message)
			}
			return undetected("a flipped byte in a sealed segment verified clean")
		},
	}
}

// removedSegment deletes a whole segment from the middle of the log.
//
// Not in the attack list by name, and it belongs here: it is what an adversary
// tries *after* discovering that editing a segment is caught. Removing evidence
// is the more natural attack than altering it, and the chain is what makes it
// detectable — the following segment's recorded predecessor no longer matches.
func removedSegment() attack {
	return attack{
		name: "removed-segment",
		goal: "delete an inconvenient stretch of history rather than trying to edit it",
		run: func(h *harness) outcome {
			if err := h.writeLog(150); err != nil {
				return undetected("setup: " + err.Error())
			}
			paths, err := h.segmentPaths()
			if err != nil || len(paths) < 3 {
				return undetected("setup: the fixture did not rotate enough to remove a middle segment")
			}
			if err := os.Remove(paths[1]); err != nil {
				return undetected("setup: " + err.Error())
			}

			rep, verr := h.verifyFrom()
			if verr != nil {
				return detected("janus-verify", verr.Error())
			}
			for _, code := range []string{"SEQUENCE_GAP", "CHAIN_BREAK", "SEGMENT_ID_GAP"} {
				if f, ok := named(rep, code); ok {
					if f.Severity == verify.Critical {
						return detected("janus-verify", f.Code+": "+f.Message)
					}
					return detected("janus-verify (as a warning only)", f.Code+": "+f.Message)
				}
			}
			return undetected("a segment was removed from the middle of the log and the " +
				"verifier reported nothing")
		},
	}
}

// coveredElsewhere records the two listed attacks that are the subject of a
// standing gate already, so that a reader comparing this suite against the list
// can see they were considered rather than forgotten.
//
//   - "registering a participant with a false REVERSIBLE claim" — pkg/registry's
//     conformance harness refuses a manifest whose declared compensation does not
//     execute against its doubles, and `make registry` is the standing check.
//   - "prompt-injecting a tool result to trigger an unauthorized wire" — the
//     `rogue-step-refused` scenario in `make sagachaos`, which drives a step the
//     admitted plan does not contain and requires the coordinator to refuse it
//     at every one of seven kill points.
//
// Reimplementing either here would duplicate a gate rather than add one. Naming
// them is what stops the omission being invisible.
var coveredElsewhere = []string{
	"false-reversible-claim: make registry (pkg/registry conformance)",
	"prompt-injected-rogue-step: make sagachaos (rogue-step-refused)",
}

// notCoveredAndWhy is printed beside the pass, because a suite that reports only
// what it catches teaches its reader that the list is the territory.
//
// truncated-bundle is run against a signed backup, where the artifact answers for
// itself, and truncated-audit-bundle against an unsigned audit bundle checked by
// an auditor who requires a signed manifest. What remains uncovered is the
// auditor who does not: an unsigned bundle cut off at its end, verified without
// -require-signed-manifest, is a valid prefix of a hash chain and passes. The head
// chain compared against a value obtained out of band is the answer for them — a
// practice, not a control, until an anchor outside Janus's control exists,
// which is not built.
var notCoveredAndWhy = []string{
	"truncated-audit-bundle, for an auditor who does NOT pass -require-signed-manifest:\n" +
		"    an unsigned bundle cut at its end is a valid prefix and passes. Sign exports\n" +
		"    (janus-tier export -key) and require it, or convey the head separately\n" +
		"    (-expect-head).",
}
