package main

import (
	"strings"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

// TestARequiredSignatureIsNotSilentlyDroppedForARawLog: a raw segment
// directory has no manifest, so -require-signed-manifest cannot be met by it.
// Ignoring the flag there would let an auditor read a pass as meeting a
// requirement nothing checked.
func TestARequiredSignatureIsNotSilentlyDroppedForARawLog(t *testing.T) {
	_, err := verifyTarget(t.TempDir(), verify.Options{RequireSignedManifest: true})
	if err == nil || !strings.Contains(err.Error(), "no manifest to require a signature on") {
		t.Fatalf("a raw directory verified with a signed manifest required was told %v", err)
	}
}
