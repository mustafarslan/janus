package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestTheVerifierLinksOnlyWhatItReads is the check the project's rule assumed
// existed and `SECURITY.md` told readers had been performed.
//
// The rule is "nothing new enters `janus-verify`'s import graph without a
// measurement", and `SECURITY.md` said the verifier's packages "import no
// networking at all, **checked rather than asserted**". Nothing checked it. The
// cost of that was 18 AWS modules out of 23 in the published bill of
// materials — for a binary whose entire argument is that a third party does not
// have to trust the people who built it.
//
// It went in through a single edge — `pkg/evidence/cas` imported
// `pkg/evidence/objstore` for an S3 backend with no production caller — and an
// edge like that is added by somebody being helpful, not careless. A sentence in
// a document does not catch it. This does.
//
// # Why the dependency graph rather than the symbol table
//
// The linker already drops the unreachable function bodies, and it is tempting
// to check `go tool nm` and conclude the problem is small. It is the
// wrong instrument: what an auditor reads is the SBOM and `go version -m`, and
// those report the *module* graph. A dependency nobody calls is still a
// dependency somebody has to review, patch and account for.
func TestTheVerifierLinksOnlyWhatItReads(t *testing.T) {
	// Things that have no business inside an offline verifier. Each is here
	// because it would arrive the same way the S3 client did: through a package
	// that does something else useful.
	forbidden := []struct{ prefix, why string }{
		{"github.com/aws/", "an object-store client; the verifier reads a local directory"},
		{"github.com/jackc/", "a Postgres driver; projections are derived and the verifier reads the log"},
		{"google.golang.org/grpc", "an RPC stack; the verifier talks to nobody"},
		{"google.golang.org/protobuf", "the protobuf runtime, measured at 7.0 MB -> 16.3 MB"},
		{"go.opentelemetry.io/", "telemetry; an auditor's copy reports to nobody"},
		{"net/http", "HTTP"},
		{"crypto/tls", "TLS"},
	}

	// From the module root, because `go test` runs in the package directory and
	// the relative path would not resolve there.
	cmd := exec.Command("go", "list", "-deps", "./cmd/janus-verify")
	cmd.Dir = repoRoot(t)
	out, err := cmd.Output()
	if err != nil {
		var stderr string
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("go list: %v\n%s", err, stderr)
	}

	var found []string
	for _, dep := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		for _, f := range forbidden {
			if dep == f.prefix || strings.HasPrefix(dep, f.prefix) {
				found = append(found, dep+"  ("+f.why+")")
			}
		}
	}
	if len(found) > 0 {
		t.Errorf("the offline verifier links %d package(s) it does not read:\n  %s\n\n"+
			"Find the edge with:\n"+
			"    go list -deps -f '{{.ImportPath}}: {{join .Imports \" \"}}' ./cmd/janus-verify | grep <the package>\n\n"+
			"The fix is an interface in the consuming package and the implementation in a\n"+
			"leaf one, wired by the binary that needs it. If the dependency is genuinely\n"+
			"required, the rule asks for a measurement rather than a judgement: the module\n"+
			"count, the binary size, and what it does to the published SBOM.",
			len(found), strings.Join(found, "\n  "))
	}
}

// repoRoot finds the module root by walking up to go.mod, so the test does not
// depend on which directory `go test` happened to be invoked from.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the working directory")
		}
		dir = parent
	}
}
