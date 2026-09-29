// Command janus-identity is the operator path to the identity trust store.
//
// It closes two gaps of the same shape. The first:
// `identity.Recorder.RevokeCredential` has been implemented since Phase 5b, the
// fold has honoured a revocation correctly the whole time, and **nothing could
// record one**. A lost or stolen authenticator could not be withdrawn. A control
// that is implemented and unreachable reads, in a compliance report, exactly
// like a control that works, which is the failure this project exists to
// prevent.
//
// The second is the same shape, larger: `TrustIssuerKey` had **no
// production caller either**, so no deployment could trust an OIDC issuer, so
// `identity.Verify` could never succeed and every assertion-bearing approval was
// refused with "is not an issuer this log trusts". Trusting an issuer is not
// here — it is `janus-orchd -issuer-jwks`, because whoever can add an issuer can
// mint a token establishing any role, and that belongs to whoever controls the
// host rather than to whoever can reach a port. Revoking one *is*
// here, because revocation removes authority rather than granting it.
//
// # Why this is a command and not a button
//
// The console deliberately offers no revoke button, and should not acquire one.
// A page that can revoke a credential from a session is a page a stolen session
// can use to remove the control it is about to bypass — the attacker's first
// move against a step-up requirement is to delete the step-up. Revocation is an
// operator action taken from somewhere a browser session cannot reach, which is
// what "reaching the daemon's address" means here.
//
// # Why it talks to the daemon rather than the directory
//
// One process writes an evidence directory, and in a running
// deployment that process is `janus-orchd`. A command that appended directly
// would take the writer lock, fail, and be useless at exactly the moment it is
// needed. So this asks the daemon, the same way the console asks it to record an
// approval.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/mustafarslan/janus/pkg/identity"
	"github.com/mustafarslan/janus/pkg/orchd"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "janus-identity: %v\n", err)
		os.Exit(1)
	}
}

// errUsage is returned after the help text has been printed. It carries no
// detail of its own because the detail is already on the operator's screen, and
// repeating it under a "janus-identity:" prefix would read as a second, more
// cryptic error.
var errUsage = errors.New("no command given")

func usage() error {
	fmt.Fprint(os.Stderr, `usage:
  janus-identity revoke -addr <host:port> -id <credential-id> -reason <why>
      Withdraw a lost or stolen authenticator, through the daemon that owns the log

  janus-identity revoke-issuer -addr <host:port> -issuer <url> -kid <key-id> -reason <why>
      Withdraw one signing key of one OIDC issuer. Trusting one is NOT here:
      see janus-orchd -issuer-jwks. Whoever can add a trusted issuer can mint a
      token establishing any role, so that stays on the host; revoking removes
      authority and is safe to expose

  janus-identity credentials -evidence <dir>
      List the credentials the log currently trusts, with their subjects.
      Reads the directory directly, which is safe: it takes no lock and writes
      nothing

  janus-identity issuers -evidence <dir>
      List the OIDC issuers and key ids the log currently trusts. An empty list
      means no approval can carry an identity, which is what every deployment
      looked like before an issuer could be trusted

`)
	return errUsage
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "revoke":
		return revoke(args[1:])
	case "revoke-issuer":
		return revokeIssuer(args[1:])
	case "credentials":
		return list(args[1:])
	case "issuers":
		return listIssuers(args[1:])
	default:
		return usage()
	}
}

func revoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:7777", "address of the janus-orchd that owns the log")
	id := fs.String("id", "", "credential id to withdraw")
	reason := fs.String("reason", "", "why it is being withdrawn; required")
	timeout := fs.Duration("timeout", 10*time.Second, "how long to wait for the daemon")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return errors.New("-id is required: a revocation naming nothing withdraws nothing")
	}
	// Checked here as well as in the daemon so that the operator learns it
	// before a round trip, and so the requirement survives somebody using this
	// package's client against a different server.
	if *reason == "" {
		return errors.New(`-reason is required: "lost laptop" and "employee left" call for ` +
			`different follow-up, and the difference is not recoverable later`)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", *addr, err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := orchd.NewClient(conn).RevokeCredential(ctx, *id, *reason); err != nil {
		return fmt.Errorf("revoking %s: %w", *id, err)
	}
	// The reference is not printed. It would be the daemon's own, and an
	// operator's next move is to check the credential is gone from the list
	// below — which reads the log rather than trusting this process's report of
	// what it asked for.
	fmt.Printf("revoked %s: %s\n", *id, *reason)
	fmt.Printf("confirm with: janus-identity credentials -evidence <dir>\n")
	return nil
}

func list(args []string) error {
	fs := flag.NewFlagSet("credentials", flag.ContinueOnError)
	dir := fs.String("evidence", "./janus-evidence", "evidence directory to read")
	if err := fs.Parse(args); err != nil {
		return err
	}
	trust, err := identity.LoadTrust(*dir)
	if err != nil {
		return fmt.Errorf("reading %s: %w", *dir, err)
	}
	if len(trust.Credentials) == 0 {
		fmt.Println("no credentials are trusted in this log")
		return nil
	}
	fmt.Printf("%-40s  %s\n", "CREDENTIAL", "SUBJECT")
	for id, cred := range trust.Credentials {
		fmt.Printf("%-40s  %s\n", id, cred.Subject)
	}
	return nil
}

// revokeIssuer withdraws one signing key of one OIDC issuer.
//
// One key rather than a whole issuer, and that is deliberate. An issuer rotating
// a compromised key goes on working with its others, so a command that meant
// "distrust everything from this issuer" would be the wrong default and would
// take an approval path down for a problem with one key. An operator who does
// mean all of them runs this once per key id, and the log then says which keys
// were withdrawn and when.
func revokeIssuer(args []string) error {
	fs := flag.NewFlagSet("revoke-issuer", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:7777", "address of the janus-orchd that owns the log")
	issuer := fs.String("issuer", "", `the issuer, as it appears in a token's "iss" claim`)
	kid := fs.String("kid", "", `the key id ("kid") to withdraw`)
	reason := fs.String("reason", "", "why it is being withdrawn; required")
	timeout := fs.Duration("timeout", 10*time.Second, "how long to wait for the daemon")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *issuer == "" {
		return errors.New("-issuer is required: keys are trusted per issuer, so a key id " +
			"alone does not say which trust to withdraw")
	}
	if *kid == "" {
		return errors.New("-kid is required: to distrust an issuer entirely, revoke its " +
			"keys one by one, so the log says which were withdrawn and when")
	}
	if *reason == "" {
		return errors.New("-reason is required: a rotation and a compromise look identical " +
			"without one, and they call for opposite responses to every approval this key " +
			"verified")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", *addr, err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := orchd.NewClient(conn).RevokeIssuerKey(ctx, *issuer, *kid, *reason); err != nil {
		return fmt.Errorf("revoking %s key %s: %w", *issuer, *kid, err)
	}
	fmt.Printf("revoked key %s of issuer %s: %s\n", *kid, *issuer, *reason)
	fmt.Printf("confirm with: janus-identity issuers -evidence <dir>\n")
	fmt.Printf("\nApprovals already given stay valid: they were valid when they were given,\n")
	fmt.Printf("and re-verification folds the trust store as it stood then. If this key was\n")
	fmt.Printf("compromised rather than rotated, the approvals it established are what to\n")
	fmt.Printf("review, and the log names them.\n")
	return nil
}

// listIssuers prints the issuers the log trusts.
//
// An empty list is the answer worth spelling out rather than printing nothing,
// because it is not a neutral state: it means no approval can carry an identity
// at all, and it is what every deployment looked like before an issuer could
// be trusted.
func listIssuers(args []string) error {
	fs := flag.NewFlagSet("issuers", flag.ContinueOnError)
	dir := fs.String("evidence", "./janus-evidence", "evidence directory to read")
	if err := fs.Parse(args); err != nil {
		return err
	}
	trust, err := identity.LoadTrust(*dir)
	if err != nil {
		return fmt.Errorf("reading %s: %w", *dir, err)
	}
	var rows int
	for _, byKid := range trust.Issuers {
		rows += len(byKid)
	}
	if rows == 0 {
		fmt.Println("no OIDC issuer is trusted in this log.")
		fmt.Println()
		fmt.Println("That is not a neutral state: identity.Verify requires an ID token and")
		fmt.Println("verifying one requires the issuer's key to be here, so every approval")
		fmt.Println("carrying an assertion is refused. Trust one with:")
		fmt.Println("  janus-orchd -issuer-jwks <issuer-url>=<path to its JWKS>")
		return nil
	}
	issuers := make([]string, 0, len(trust.Issuers))
	for iss := range trust.Issuers {
		issuers = append(issuers, iss)
	}
	sort.Strings(issuers)
	fmt.Printf("%-52s  %s\n", "ISSUER", "KEY ID")
	for _, iss := range issuers {
		kids := make([]string, 0, len(trust.Issuers[iss]))
		for kid := range trust.Issuers[iss] {
			kids = append(kids, kid)
		}
		sort.Strings(kids)
		for _, kid := range kids {
			fmt.Printf("%-52s  %s\n", iss, kid)
		}
	}
	return nil
}
