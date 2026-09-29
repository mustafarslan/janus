// Command janus-keys manages evidence writer keys.
//
// Its main job is exporting the public half of a writer key in the format
// janus-verify consumes, because handing an auditor the public key through a
// channel separate from the evidence is what makes verification mean anything.
// A key that travels inside the artifact it authenticates proves only that the
// artifact is self-consistent.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/mustafarslan/janus/pkg/clockwire"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

var version = "dev"

const usage = `janus-keys %s — evidence writer key management

usage:
  janus-keys gen  <key-file>   create a new Ed25519 writer key
  janus-keys pub  <key-file>   print the public key set for janus-verify -keys
  janus-keys id   <key-file>   print the key id

  janus-keys rotate -evidence <dir> -old <key-file> -new <pub.json> [-reason <text>]
      Declare the next writer key in the log, in a segment the old key signs,
      so an auditor holding the old key can follow the rotation forward without
      being handed the new one.

      Run this BEFORE switching the daemon's key. Swapping the key without it
      leaves recovery sealing the old tail under a key the log never introduced,
      producing a segment permanently unverifiable from the root. Fail-closed,
      and a trap.

      -new takes a public key set (janus-keys pub), not a private key: under
      janus-signer custody the operator never holds the new private half.
      -reason additionally revokes the old key, from this point forward. Its
      earlier segments keep verifying — a rotation is not a repudiation.
`

func main() {
	if len(os.Args) > 1 && os.Args[1] == "rotate" {
		if err := rotate(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "janus-keys: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	cmd, path := os.Args[1], os.Args[2]
	// A path that looks like a flag is a mistyped flag, and `janus-keys gen -h`
	// otherwise writes a *signing key* to a file called "-h" and prints its id
	// as though all is well. Found by doing exactly that.
	if strings.HasPrefix(path, "-") {
		fmt.Fprintf(os.Stderr, "janus-keys: %q looks like a flag, not a path; "+
			"this command takes the key path as its second argument\n", path)
		os.Exit(2)
	}

	if err := run(cmd, path); err != nil {
		fmt.Fprintf(os.Stderr, "janus-keys: %v\n", err)
		os.Exit(1)
	}
}

func run(cmd, path string) error {
	switch cmd {
	case "gen":
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists; refusing to overwrite a signing key", path)
		}
		s, err := keys.Generate()
		if err != nil {
			return err
		}
		if err := s.Save(path); err != nil {
			return err
		}
		fmt.Printf("%s\n", s.KeyID())
		return nil

	case "pub":
		s, err := keys.Load(path)
		if err != nil {
			return err
		}
		blob, err := json.MarshalIndent(keys.PublicKeySet{s.KeyID(): s.Public()}, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(blob))
		return nil

	case "id":
		s, err := keys.Load(path)
		if err != nil {
			return err
		}
		fmt.Println(s.KeyID())
		return nil

	default:
		fmt.Fprintf(os.Stderr, usage, version)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// rotate declares the next writer key in the log.
//
// The declaration has to land in a segment the *old* key signs — that is the
// whole mechanism, and it is why this opens the log with the old signer rather
// than the new one. It also means the tail the previous daemon left open is
// sealed under the old key, which is correct: those records were written in the
// old era.
func rotate(args []string) error {
	fs := flag.NewFlagSet("rotate", flag.ExitOnError)
	dir := fs.String("evidence", "", "evidence segment directory")
	oldPath := fs.String("old", "", "the key currently signing this log")
	newPath := fs.String("new", "", "public key set for the next key (janus-keys pub)")
	reason := fs.String("reason", "",
		"also revoke the old key, with this reason. Its earlier segments keep verifying.")
	clockFlags := clockwire.RegisterFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *oldPath == "" || *newPath == "" {
		fs.Usage()
		return errors.New("-evidence, -old and -new are all required")
	}

	oldSigner, err := keys.Load(*oldPath)
	if err != nil {
		return fmt.Errorf("loading the current key: %w", err)
	}
	next, err := loadOnePublicKey(*newPath)
	if err != nil {
		return err
	}
	if next.id == oldSigner.KeyID() {
		return fmt.Errorf("-new names the key already signing this log (%s); a rotation to "+
			"the same key would record a declaration and change nothing", next.id)
	}

	// A rotation is an operator act, and one whose date matters: an auditor
	// following the key chain asks when trust moved. One-shot, and this process
	// attests its own clock rather than borrowing the daemon's.
	by := evidence.ParticipantRef{ID: "sys_keys", Kind: "SYSTEM", Principal: "pr_operator"}
	clockCfg := clockFlags.Config(by)
	clockCfg.WarnIfUnattested("janus-keys", *dir)
	ctx := context.Background()
	app, _, err := clockwire.Open(ctx, clockCfg, evidence.Options{
		Dir: *dir, Signer: oldSigner, SyncMode: segment.SyncModeFull,
	})
	if err != nil {
		return fmt.Errorf("opening %s with the current key: %w", *dir, err)
	}
	defer func() { _ = app.Close() }()
	ref, err := app.RecordWriterKey(ctx, evidence.WriterKeyDeclaration{
		Kind: evidence.WriterKeyTrusted, KeyID: next.id, PublicKey: next.pub,
	}, by)
	if err != nil {
		return fmt.Errorf("declaring the next key: %w", err)
	}
	fmt.Printf("declared %s at seq %d, in a segment signed by %s\n",
		next.id, ref.Seq, oldSigner.KeyID())

	if *reason != "" {
		ref, err := app.RecordWriterKey(ctx, evidence.WriterKeyDeclaration{
			Kind: evidence.WriterKeyRevoked, KeyID: oldSigner.KeyID(), Reason: *reason,
		}, by)
		if err != nil {
			return fmt.Errorf("revoking the current key: %w", err)
		}
		fmt.Printf("revoked %s at seq %d (%s); its earlier segments still verify\n",
			oldSigner.KeyID(), ref.Seq, *reason)
	}
	fmt.Printf("now switch the writer to %s; an auditor still needs only %s\n",
		next.id, oldSigner.KeyID())
	return nil
}

type publicKey struct {
	id  string
	pub []byte
}

// loadOnePublicKey reads a key set and insists it holds exactly one key.
//
// A set with several would leave the rotation ambiguous, and picking one — the
// first by map order — is how an operator ends up having declared a key they
// did not mean to.
func loadOnePublicKey(path string) (publicKey, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return publicKey{}, err
	}
	var set keys.PublicKeySet
	if err := json.Unmarshal(blob, &set); err != nil {
		return publicKey{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(set) != 1 {
		return publicKey{}, fmt.Errorf("%s holds %d keys; a rotation names exactly one",
			path, len(set))
	}
	for id, pub := range set {
		return publicKey{id: id, pub: pub}, nil
	}
	return publicKey{}, fmt.Errorf("%s holds no key", path)
}
