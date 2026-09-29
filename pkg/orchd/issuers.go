package orchd

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"sort"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/identity"
)

// Trusting an OIDC issuer's signing keys, from the daemon's own configuration.
//
// # Why this is not an RPC
//
// A caller that can add a trusted issuer can mint tokens establishing
// any role it likes, which is a larger authority than anything else this service
// grants. Registering a *credential* is bounded — verification requires the
// credential's subject to match the subject of a verified ID token — and
// revoking anything moves the system fail-closed. Trusting an issuer is neither.
//
// So it takes the shape `declareStandbyKeys` already established: a declaration
// made from the daemon's start-up configuration, idempotent across restarts. A
// stolen console session cannot reach the daemon's command line, which is the
// property that matters here — issuer trust belongs to whoever controls the host,
// not to whoever holds a cookie.
//
// # Why it had to be built at all
//
// `identity.Verify` requires an ID token and verifying one requires the issuer's
// key to be in the log's trust store. `TrustIssuerKey` had existed since Phase 5b
// with **no production caller**, so no deployment could put a key there and every
// assertion-bearing approval was refused with "is not an issuer this log trusts".
// Issuer trust was meant to "stay an operator action, out of band" and no
// out-of-band mechanism was ever built.
//
// # The cost, stated where somebody will hit it
//
// A new issuer key needs a daemon restart. OIDC providers rotate their JWKS
// routinely, so that is a real operational burden and it is the deliberate
// price of not fetching: a daemon that pulled a JWKS at start-up would put an
// outbound network dependency in the identity path, and Janus requires
// air-gapped operation with no mandatory external SaaS. Declare both the old and
// the new key across a rotation and the restart stops being urgent.
func (s *Server) declareIssuerKeys(byIssuer map[string][]identity.IssuerKey) error {
	if len(byIssuer) == 0 {
		return nil
	}
	// What the log already trusts, read from the log rather than remembered:
	// the daemon that made the first declaration may not be this process.
	trust, err := identity.LoadTrust(s.dir)
	if err != nil {
		return fmt.Errorf("orchd: reading the identity trust store: %w", err)
	}

	rec := identity.NewRecorder(s.app, evidence.ParticipantRef{
		ID: "sys_orchd", Kind: "SYSTEM", Principal: "pr_operator",
	})

	// Sorted, so that a restart records the same events in the same order and
	// two logs of the same configuration are comparable.
	issuers := make([]string, 0, len(byIssuer))
	for iss := range byIssuer {
		issuers = append(issuers, iss)
	}
	sort.Strings(issuers)

	for _, issuer := range issuers {
		keys := byIssuer[issuer]
		sort.Slice(keys, func(i, j int) bool { return keys[i].KeyID < keys[j].KeyID })
		for _, k := range keys {
			known, ok := trust.Issuers[issuer][k.KeyID]
			if ok {
				// Same id and same key material: a repeat, and recording it
				// would be a rotation that did not happen.
				same, err := sameKey(known, k.Key)
				if err != nil {
					return fmt.Errorf("orchd: comparing issuer %s key %s: %w", issuer, k.KeyID, err)
				}
				if same {
					continue
				}
				// Same id, different key. This is the case worth refusing
				// rather than silently overwriting: an issuer that reused a
				// `kid` for a new key, or a JWKS that is not the one this log
				// was configured with. Either way somebody should look, and
				// the fix is to revoke the old key deliberately.
				return fmt.Errorf("orchd: issuer %q already trusts a DIFFERENT key under id "+
					"%q. A reused key id is either an issuer that rotated without changing "+
					"the id, or a JWKS from somewhere else. Revoke the old key first "+
					"(janus-identity revoke-issuer) so the change is recorded as a decision "+
					"rather than applied as a silent overwrite", issuer, k.KeyID)
			}
			if err := rec.TrustIssuerKey(context.Background(), issuer, k.KeyID,
				k.Algorithm, k.Key); err != nil {
				return fmt.Errorf("orchd: trusting issuer %s key %s: %w", issuer, k.KeyID, err)
			}
			log.Printf("orchd: trusting %s signing key %s of issuer %s; approvals may now "+
				"carry an identity established by a token this key signed",
				k.Algorithm, k.KeyID, issuer)
		}
	}
	return nil
}

// sameKey reports whether two public keys are the same key.
//
// Compared by their encoded form rather than by type-switching, because that is
// what the log stores and what a later fold will hand back: two keys are the
// same key exactly when the log cannot tell them apart.
func sameKey(a, b any) (bool, error) {
	ea, err := identity.EncodePublicKey(a)
	if err != nil {
		return false, err
	}
	eb, err := identity.EncodePublicKey(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(ea, eb), nil
}
