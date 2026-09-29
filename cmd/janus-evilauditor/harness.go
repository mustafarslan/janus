package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/crypto"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

// harness gives one attack a log to attack and a verifier to be caught by.
//
// A fresh directory per attack, because an adversary who has damaged a log has
// changed what the next attack is attacking — and a suite whose attacks
// interfere is one whose failures cannot be read.
type harness struct {
	dir    string
	signer *keys.Signer
	root   string
}

func newHarness(name string) (*harness, error) {
	root, err := os.MkdirTemp("", "evil-"+strings.ReplaceAll(name, "/", "-")+"-")
	if err != nil {
		return nil, err
	}
	signer, err := keys.Generate()
	if err != nil {
		return nil, err
	}
	return &harness{dir: filepath.Join(root, "evidence"), signer: signer, root: root}, nil
}

func (h *harness) cleanup() { _ = os.RemoveAll(h.root) }

// keySet is the root an auditor is handed, out of band.
func (h *harness) keySet() keys.PublicKeySet {
	return keys.PublicKeySet{h.signer.KeyID(): h.signer.Public()}
}

// writeLog produces an ordinary log: a saga's worth of records, rotated across
// several segments so that a sealed segment exists to attack.
func (h *harness) writeLog(records int) error {
	a, err := evidence.Open(evidence.Options{
		Dir: h.dir, Signer: h.signer, SyncMode: segment.SyncModeNone,
		SegmentTargetBytes: 4096,
	})
	if err != nil {
		return err
	}
	for i := range records {
		if _, err := a.Append(context.Background(), evidence.Request{
			Kind: evidence.KindStepResult, SagaID: "sg_victim",
			StepID:      fmt.Sprintf("st_%03d", i),
			Participant: evidence.ParticipantRef{ID: "ag_honest", ManifestVersion: "1.0.0"},
			Payload:     fmt.Appendf(nil, `{"i":%d}`, i),
		}); err != nil {
			_ = a.Close()
			return err
		}
	}
	return a.Close()
}

// openAppender reopens the log for an attack that writes through the real API.
//
// Several attacks are performed with the writer's own key and its own entry
// point, because that is the honest threat model: an adversary who has the disk
// often has the process too, and an attack that only works from outside the
// software is the easy case.
func (h *harness) openAppender() (*evidence.Appender, error) {
	return evidence.Open(evidence.Options{
		Dir: h.dir, Signer: h.signer, SyncMode: segment.SyncModeNone,
	})
}

// verifyFrom runs the offline verifier the way an auditor does: against the
// directory, with the one root they were handed and nothing else.
func (h *harness) verifyFrom() (*verify.Report, error) {
	return verify.SegmentDir(h.dir, verify.Options{
		Keys: h.keySet(), Version: version, AllowUnsealedTail: true,
	})
}

// findings returns the codes the verifier reported at or above a severity.
func findings(rep *verify.Report, atLeast verify.Severity) []verify.Finding {
	var out []verify.Finding
	for _, f := range rep.Findings {
		switch atLeast {
		case verify.Critical:
			if f.Severity == verify.Critical {
				out = append(out, f)
			}
		case verify.Warning:
			if f.Severity == verify.Critical || f.Severity == verify.Warning {
				out = append(out, f)
			}
		default:
			out = append(out, f)
		}
	}
	return out
}

// named reports whether the verifier produced a finding with this code, and
// returns it.
//
// The suite asserts on *codes* rather than on `rep.OK`, and that is the
// difference between a suite that proves what it claims and one that passes for
// the wrong reason. An attack that broke the log in some unrelated way would
// make OK false and prove nothing about whether the attack itself was seen —
// which is exactly how a later change caught the restore path doing full
// verification it was designed to skip.
func named(rep *verify.Report, code string) (verify.Finding, bool) {
	for _, f := range rep.Findings {
		if f.Code == code {
			return f, true
		}
	}
	return verify.Finding{}, false
}

// segmentPaths lists the log's segment files, oldest first.
func (h *harness) segmentPaths() ([]string, error) {
	ids, err := segment.ScanComplete(h.dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, id := range ids {
		out = append(out, segment.Path(h.dir, id))
	}
	return out, nil
}

// firstSealed returns a segment that has been sealed, which is what most
// attacks want: a finished, signed artifact rather than the tail being written.
func (h *harness) firstSealed() (string, error) {
	paths, err := h.segmentPaths()
	if err != nil {
		return "", err
	}
	for _, p := range paths {
		sealed, err := segment.IsSealed(p)
		if err != nil {
			return "", err
		}
		if sealed {
			return p, nil
		}
	}
	return "", fmt.Errorf("no sealed segment: the fixture did not rotate, so there is " +
		"nothing finished to attack")
}

// segmentSignedByAStranger returns the bytes of a sealed segment produced by a
// writer this log has never heard of.
//
// It is how "forging a writer signature" is actually done. An adversary cannot
// re-sign our segment, because they do not have our key; what they can do is
// produce a segment of their own — internally perfect, correctly sealed, signed
// by a key nobody declared — and put it where ours was. Detecting that is what
// the trust chain is for, and it is invisible to every check that only
// looks at whether a file is well-formed.
func (h *harness) segmentSignedByAStranger() ([]byte, error) {
	stranger, err := keys.Generate()
	if err != nil {
		return nil, err
	}
	other, err := os.MkdirTemp(h.root, "stranger-")
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(other, "evidence")
	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: stranger, SyncMode: segment.SyncModeNone,
		SegmentTargetBytes: 4096,
	})
	if err != nil {
		return nil, err
	}
	for i := range 120 {
		if _, err := a.Append(context.Background(), evidence.Request{
			Kind: evidence.KindStepResult, SagaID: "sg_victim",
			StepID:      fmt.Sprintf("st_%03d", i),
			Participant: evidence.ParticipantRef{ID: "ag_honest", ManifestVersion: "1.0.0"},
			Payload:     fmt.Appendf(nil, `{"i":%d}`, i),
		}); err != nil {
			_ = a.Close()
			return nil, err
		}
	}
	if err := a.Close(); err != nil {
		return nil, err
	}
	ids, err := segment.ScanComplete(dir)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		p := segment.Path(dir, id)
		sealed, err := segment.IsSealed(p)
		if err != nil {
			return nil, err
		}
		if sealed {
			return os.ReadFile(p)
		}
	}
	return nil, fmt.Errorf("the stranger's log did not seal a segment")
}

// shredASubject writes a record carrying a data subject's personal data, then
// destroys their key — a lawful crypto-shredding erasure, performed for real.
//
// The chain keeps the ciphertext and the hashes still check out, which is the
// design: erasure removes the ability to read content, not the evidence that
// something was recorded. What the adversarial question asks is whether a
// verifier notices, or hands back an unqualified clean bill.
func (h *harness) shredASubject() (string, error) {
	master, err := crypto.GenerateMasterKey()
	if err != nil {
		return "", err
	}
	ring, err := crypto.NewFileKeyRing(filepath.Join(h.root, "keyring"), master)
	if err != nil {
		return "", err
	}
	a, err := evidence.Open(evidence.Options{
		Dir: h.dir, Signer: h.signer, SyncMode: segment.SyncModeNone,
		Sealer: crypto.NewSealer(ring),
	})
	if err != nil {
		return "", err
	}
	for i := range 12 {
		if _, err := a.Append(context.Background(), evidence.Request{
			Kind: evidence.KindStepResult, SagaID: "sg_victim",
			StepID:      fmt.Sprintf("st_%03d", i),
			Participant: evidence.ParticipantRef{ID: "ag_honest", ManifestVersion: "1.0.0"},
			Subject:     "cust_42",
			Payload:     fmt.Appendf(nil, `{"name":"a real person","i":%d}`, i),
		}); err != nil {
			_ = a.Close()
			return "", err
		}
	}
	ref, _, err := evidence.Erase(context.Background(), a, ring, "cust_42",
		"erasure request", "op_dpo")
	if err != nil {
		_ = a.Close()
		return "", err
	}
	if err := a.Close(); err != nil {
		return "", err
	}
	return ref.EventID, nil
}
