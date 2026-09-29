# DPIA input: erasure of personal data held in an immutable evidence log

**Scope:** the crypto-shredding mechanism in `pkg/evidence/crypto`, as it stands
after Phase 1c.

**Status:** engineering input to a Data Protection Impact Assessment, not a
completed DPIA and not legal advice. It describes what the system does, what it
does not do, and what residual risk remains, so that a controller's data
protection officer can assess it. The assessment itself, and the decision that
the residual risk is acceptable, belong to the controller.

---

## 1. The conflict being resolved

Two obligations apply to the same records and point in opposite directions.

**Erase.** GDPR Art. 17 (and KVKK Art. 7, and comparable provisions elsewhere)
gives a data subject the right to have personal data concerning them erased.

**Keep, unaltered.** EU AI Act Art. 12 and 19 require automatic logging of
high-risk AI system activity and its retention. MiFID II RTS 6, SEC 17a-4, and
BaFin's Revisionssicherheit expectations require records to be kept for years in
a form that cannot be altered.

Janus makes the second obligation structural: records are hash-chained, so each
one commits to its predecessor. Removing bytes from the middle of that chain
breaks every link after them, destroying the integrity of records belonging to
other people and other matters. Erasure by deletion is therefore not available.

## 2. What the system does instead

Payloads that a caller marks as containing personal data are encrypted before
they enter the log, under a key held per data subject. Erasure destroys that key.

The record stays exactly where it was. The chain still verifies. The log still
shows that something happened, when, by which participant, and in what sequence.
What is gone is the content.

Concretely:

| | |
|---|---|
| Cipher | AES-256-GCM, one data encryption key per data subject |
| Key wrapping | Each DEK is encrypted under a master key held outside the log |
| Binding | The subject, saga, step, and event kind are authenticated as additional data, so a ciphertext cannot be moved to another event |
| Erasure | The DEK is overwritten and unlinked; a tombstone records the act |
| Record of erasure | A `SHRED` event in the log names the subject, the reason, the approver, the time, and a fingerprint of the destroyed key |

## 3. The design decision that matters most

**The chain commits to the hash of the ciphertext, not of the plaintext.**

This was a deliberate choice and it is the difference between erasure being
complete and being approximate.

Had the chain committed to a hash of the plaintext, that hash would survive
erasure permanently, in a record that is by design immutable and widely copied
(to the WORM tier, into exported evidence bundles, potentially to a regulator).
Anyone holding a candidate value could confirm it by hashing and comparing.

For personal data this is not a theoretical weakness. The values in question are
often drawn from small or enumerable spaces: an account number, a date of birth,
a postcode, a decision outcome, a name from a known customer list. Confirming a
guess against a stored hash is cheap, and confirmation is itself a disclosure —
it converts a suspicion into a certainty about an identified person.

A hash of ciphertext carries no such risk. Once the key is destroyed, the
ciphertext is computationally indistinguishable from random data, and its hash
therefore reveals nothing about the plaintext to any adversary without the key.

**Consequence, stated plainly:** after erasure nobody can prove what the
plaintext was — not the operator, not the controller, not a regulator. That is
not a limitation to be minimised; it is what erasure means. What survives is
proof that a record existed at a point in the chain, when it was written, by
whom, and that it has not been altered since. That is what the retention regimes
require of the log, and it is preserved intact.

## 4. Residual risks

Each of these should be assessed by the controller against its own context. None
is fully mitigated by the mechanism alone.

### 4.1 Metadata is not encrypted

The event envelope stays in the clear: sequence number, timestamps, saga and step
identifiers, participant identity, the data subject identifier, and labels. This is necessary — the log has to
be traversable and verifiable without keys — but it means the *fact* of activity
concerning a subject remains visible after erasure, along with its timing and the
participants involved.

The subject identifier is recorded on every encrypted record and persists after
erasure. That is unavoidable rather than incidental: the payload is encrypted
under that subject's key and bound to the subject as additional authenticated
data, so a reader that does not know it can neither select the key nor decrypt.
Omitting it would make encrypted payloads permanently unreadable, including by
the controller. A controller that treats the subject identifier as personal data should
use a pseudonymous identifier in Janus and hold the mapping elsewhere, under its
own retention rules.

### 4.2 Erasure depends on key destruction actually destroying the key

The claim rests on the key being unrecoverable. Three things can undermine it:

- **Backups.** A backup taken before erasure contains the key. Erasure is not
  complete until the key is gone from every copy, which is an operational duty
  the mechanism cannot discharge on its own. Key material should be backed up on
  a schedule short enough that erasure can be honoured within the response
  period, or not at all.
- **Storage media.** The file-backed key ring overwrites a key before unlinking
  it, but on a copy-on-write filesystem, or any SSD with wear levelling,
  overwriting in place does not reliably erase the underlying blocks. The
  overwrite is defence in depth against casual recovery, not the guarantee.
  Deployments requiring a strong guarantee should hold the master key in a KMS
  or HSM able to destroy it, and use full-disk encryption underneath.
- **The master key.** Every DEK is wrapped under it. Its compromise before
  erasure exposes everything; its destruction erases everything at once. It
  should be held with the care that implies.

### 4.3 Cryptographic longevity

Records are retained for six to ten years. AES-256-GCM is not currently
considered at risk over that period, including from foreseeable quantum attack,
since Grover's algorithm leaves an effective 128-bit security level. This should
nonetheless be re-assessed rather than assumed: post-quantum dual signatures are
already contemplated, and the same review should cover payload
encryption.

### 4.4 The window between key destruction and its record

Erasure destroys the key and then records a `SHRED` event. A failure between the
two leaves the key genuinely destroyed with no event in the log explaining why
the content is unreadable.

This ordering is deliberate. The alternative — record first, then destroy —
risks the log asserting an erasure that did not happen, which would mean telling
a data subject their data was gone while it remained readable. The chosen
ordering fails towards more erasure rather than less, and is recoverable: the key
ring writes a durable tombstone naming the subject, reason, approver, and time
*before* the key is touched, so the missing event can be reconciled from it.

**Operational requirement:** a deployment must reconcile tombstones against
`SHRED` events after any unclean shutdown, and be able to show it does so.

### 4.5 Erasure does not reach data outside Janus

Janus can only erase what was written through it and marked with a subject. Copies
made by the agent, the tool server, the model provider, or a downstream system are
outside its reach. The controller's erasure procedure has to cover those
separately; Janus's `SHRED` event evidences one part of a wider act.

### 4.6 The caller decides what is personal data

Encryption applies only when a caller sets a subject on the request. Janus cannot
tell whether a tool result contains personal data, and guessing either way would
be worse than being told — guessing high would encrypt records that must stay
readable for audit, guessing low would leave personal data unerasable.

**Operational requirement:** the classification is part of the integration, and
should be reviewed as such. A record that should have been marked and was not
cannot be erased later, because there is no key to destroy.

## 5. What an auditor sees after an erasure

Stated explicitly, because "the data is gone" and "the audit trail is intact"
sound contradictory until the artefacts are laid out.

- The log verifies end to end. Chain hashes, Merkle roots, and segment
  signatures are all unaffected: the bytes never moved.
- The erased records are present, in sequence, with their timestamps,
  participants, and saga context readable.
- Their payloads are ciphertext that no longer decrypts.
- A `SHRED` event states which subject was erased, under what reason, on whose
  authority, when, and which key was destroyed.
- Attempting to read an erased payload reports the key as destroyed, distinctly
  from reporting damage — so an auditor is not sent hunting for a fault that is
  a fulfilled erasure request.

## 6. Open items

- Reconciliation of tombstones against `SHRED` events after unclean shutdown is
  described above but not yet automated.
- The file-backed key ring is complete and usable, but a deployment with a real
  erasure obligation should use a KMS or HSM implementation of the same
  interface. That is Phase 5 work.
- Key rotation is not implemented. A long-lived DEK is a larger exposure than a
  rotated one, though rotation interacts with erasure in ways needing thought:
  every generation of a subject's key must be destroyed together, or erasure is
  partial.
