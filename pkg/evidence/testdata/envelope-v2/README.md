# A log this build cannot read

Six events written by `janus-skeleton` built from a deliberately patched tree:
`EnvelopeVersion` set to 2, and one extra CBOR key (14) on `EventHeader` holding
a string a version-1 build has never heard of. The patch was reverted; only its
output is here.

It exists because the failure it pins is invisible in a struct. CBOR ignores keys
it does not know, so before the version gate a version-1 build read this directory
**silently and completely**:

    evidence.Walk      : 6 events, versions map[2:6], err=<nil>
    saga.ReplaySaga    : sg_skeleton_0001 state=COMMITTED semantics=1 steps=1
    registry.Replay    : ok, 0 participant(s)

and `janus-verify` on `bundle/` printed **`result: PASS`** with six warnings — a
verifier vouching for records it had only partly read.

Nothing here is host-specific: the writer key was generated for the run and is
carried in the bundle, and the timestamps are the run's own.

**Do not regenerate this to make a test pass.** Its whole value is that the bytes
were produced by a real writer rather than assembled by the test that reads them.
