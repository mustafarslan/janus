package callersig_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/callersig"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// The vectors are the contract with the Python SDK: the same messages, the same
// seed, the same canonical bytes and signatures. sdk/python/tests/test_callersig.py
// reads this file too. Ed25519 is deterministic, so the signatures are fixed.
const vectorsPath = "testdata/vectors.json"

var seed = []byte("janus-callersig-test-vector-seed")[:32]

type vector struct {
	Kind      string          `json:"kind"`
	Message   json.RawMessage `json:"message"`
	Canonical string          `json:"canonical_hex"`
	Signature string          `json:"signature_hex"`
}

type vectorFile struct {
	SeedHex   string   `json:"seed_hex"`
	PublicKey string   `json:"public_key"`
	Vectors   []vector `json:"vectors"`
}

func sampleMessages() map[string]proto.Message {
	return map[string]proto.Message{
		"answer": &janusv1.GateAnswer{
			SagaId: "sg_1", StepId: "disburse", RequirementId: "credit-opinion", Attempt: 1,
			Actor:   &janusv1.Actor{Participant: &janusv1.ParticipantRef{Id: "ag_credit_policy"}},
			Verdict: janusv1.Verdict_VERDICT_FAIL, Reason: "amount_minor=2500000 exceeds the mandate",
			Roles: []string{"b-role", "a-role"}, AuthRef: "",
		},
		"result": &janusv1.StepResult{
			SagaId: "sg_1", StepId: "balance", Attempt: 2,
			Outcome:    &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK, Code: "READ", Message: "ok; really"},
			ResultHash: []byte{0xde, 0xad}, ResultRef: "cas:x",
			Facts: []*janusv1.Fact{
				{Key: "z_flag", Value: &janusv1.Fact_Flag{Flag: true}},
				{Key: "balance_minor", Value: &janusv1.Fact_Number{Number: -5}},
				{Key: "ccy", Value: &janusv1.Fact_Text{Text: "EUR:1;2"}},
			},
			Touches: []*janusv1.ResourceTouch{
				{ResourceId: "acct_2", Mode: janusv1.ResourceTouch_MODE_READ},
				{ResourceId: "acct_1", Mode: janusv1.ResourceTouch_MODE_WRITE, FrontierSeq: 7},
			},
		},
		"prepare": &janusv1.PrepareStepRequest{
			SagaId: "sg_1", StepId: "disburse",
			Facts: []*janusv1.Fact{{Key: "amount_minor", Value: &janusv1.Fact_Number{Number: 100}}},
			Spawns: &janusv1.ChildSaga{
				SagaId: "sg_kid", CommitMode: janusv1.ChildCommitMode_CHILD_COMMIT_MODE_CASCADE,
			},
		},
		"begin": &janusv1.SagaBegin{
			SagaId: "sg_1", Mode: "supervised",
			Intent: &janusv1.Intent{IntentId: "in_1", Principal: "pr_bank", Originator: "sdk:python",
				MandateRef: "mandate:loans", Scope: "one loan", ExpiresAtUnixNanos: 1790000000000000000},
			Plan: []*janusv1.PlannedStep{{
				StepId: "disburse", Participant: "tool_payments", Action: "payments.disburse",
				EffectClass: janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE, DependsOn: []string{"underwrite"},
				CompensationAction: "payments.refund", MaxRetries: 2,
			}},
			ManifestPins: map[string]string{"tool_payments": "1.0.0", "ag_intake": "1.0.0"},
		},
	}
}

func canonicalOf(kind string, m proto.Message) []byte {
	switch kind {
	case "answer":
		return callersig.Answer(m.(*janusv1.GateAnswer))
	case "result":
		return callersig.Result(m.(*janusv1.StepResult))
	case "prepare":
		p := m.(*janusv1.PrepareStepRequest)
		return callersig.Prepare(p.GetSagaId(), p.GetStepId(), p.GetFacts(), p.GetSpawns())
	case "begin":
		return callersig.Begin(m.(*janusv1.SagaBegin))
	}
	panic(kind)
}

// TestTheVectorsHold is the cross-language contract. Regenerate deliberately,
// with JANUS_UPDATE_VECTORS=1, and only when the encoding is meant to change --
// which also breaks every signature already in a log.
func TestTheVectorsHold(t *testing.T) {
	key := ed25519.NewKeyFromSeed(seed)
	signer := callersig.Signer{Participant: "ag_credit_policy", Key: key}
	msgs := sampleMessages()
	order := []string{"answer", "result", "prepare", "begin"}

	if os.Getenv("JANUS_UPDATE_VECTORS") != "" {
		out := vectorFile{
			SeedHex:   hex.EncodeToString(seed),
			PublicKey: callersig.EncodeKey(key.Public().(ed25519.PublicKey)),
		}
		for _, k := range order {
			js, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(msgs[k])
			if err != nil {
				t.Fatal(err)
			}
			c := canonicalOf(k, msgs[k])
			out.Vectors = append(out.Vectors, vector{Kind: k, Message: js,
				Canonical: hex.EncodeToString(c), Signature: hex.EncodeToString(signer.Sign(c).GetSignature())})
		}
		blob, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(vectorsPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorsPath, append(blob, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	blob, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("reading the vectors: %v (regenerate with JANUS_UPDATE_VECTORS=1)", err)
	}
	var file vectorFile
	if err := json.Unmarshal(blob, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) != len(order) {
		t.Fatalf("%d vectors on disk, want %d", len(file.Vectors), len(order))
	}
	for _, v := range file.Vectors {
		c := canonicalOf(v.Kind, msgs[v.Kind])
		if got := hex.EncodeToString(c); got != v.Canonical {
			t.Errorf("%s: the canonical encoding changed; every signature already recorded over "+
				"a %s would stop verifying.\n got %s\nwant %s", v.Kind, v.Kind, got, v.Canonical)
		}
		if got := hex.EncodeToString(signer.Sign(c).GetSignature()); got != v.Signature {
			t.Errorf("%s: signature differs from the vector", v.Kind)
		}
	}
}

// TestFactOrderIsNotPartOfTheSignature: the fold reads facts as a map, so two
// declarations listing the same facts in another order are one declaration.
func TestFactOrderIsNotPartOfTheSignature(t *testing.T) {
	a := []*janusv1.Fact{
		{Key: "a", Value: &janusv1.Fact_Number{Number: 1}},
		{Key: "b", Value: &janusv1.Fact_Text{Text: "x"}},
	}
	b := []*janusv1.Fact{a[1], a[0]}
	if string(callersig.Prepare("s", "t", a, nil)) != string(callersig.Prepare("s", "t", b, nil)) {
		t.Fatal("the same facts in another order encode differently")
	}
}

// TestALengthPrefixMakesFieldsUnambiguous: "ab"+"c" and "a"+"bc" are different
// answers and must not encode alike.
func TestALengthPrefixMakesFieldsUnambiguous(t *testing.T) {
	x := callersig.Answer(&janusv1.GateAnswer{SagaId: "ab", StepId: "c"})
	y := callersig.Answer(&janusv1.GateAnswer{SagaId: "a", StepId: "bc"})
	if string(x) == string(y) {
		t.Fatal("two different answers encode to the same bytes")
	}
}

func TestVerifyRefusesEachWayASignatureCanBeWrong(t *testing.T) {
	key := ed25519.NewKeyFromSeed(seed)
	other := ed25519.NewKeyFromSeed([]byte("another-participant-seed-32bytes"))
	declared := []string{callersig.EncodeKey(key.Public().(ed25519.PublicKey))}
	msg := callersig.Answer(&janusv1.GateAnswer{SagaId: "sg", Reason: "ok for 100"})
	good := callersig.Signer{Participant: "ag_v", Key: key}.Sign(msg)

	if err := callersig.Verify(good, "ag_v", declared, msg); err != nil {
		t.Fatalf("a good signature was refused: %v", err)
	}
	for name, c := range map[string]struct {
		sig  *janusv1.ParticipantSignature
		who  string
		msg  []byte
		want error
	}{
		"none":                  {nil, "ag_v", msg, callersig.ErrUnsigned},
		"another participant's": {callersig.Signer{Participant: "ag_x", Key: key}.Sign(msg), "ag_v", msg, callersig.ErrWrongSigner},
		"an undeclared key":     {callersig.Signer{Participant: "ag_v", Key: other}.Sign(msg), "ag_v", msg, callersig.ErrUndeclaredKey},
		"over another message": {good, "ag_v",
			callersig.Answer(&janusv1.GateAnswer{SagaId: "sg", Reason: "ok for 1000000"}), callersig.ErrBadSignature},
	} {
		if err := callersig.Verify(c.sig, c.who, declared, c.msg); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
}

// TestThePythonSDKReadsTheSameVectors: the SDK's test suite runs in a container
// that mounts only sdk/python, so it keeps a copy. The copy must be this file.
func TestThePythonSDKReadsTheSameVectors(t *testing.T) {
	ours, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := os.ReadFile("../../sdk/python/tests/callersig_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(ours) != string(theirs) {
		t.Fatal("sdk/python/tests/callersig_vectors.json differs from the Go vectors; the SDK " +
			"is being tested against a contract the daemon does not hold. Copy the file over.")
	}
}

// TestAKeyJanusKeysWroteLoadsAsTheSameKey: a participant's key is made the way
// a writer's is, and what signs must be what the manifest declares.
func TestAKeyJanusKeysWroteLoadsAsTheSameKey(t *testing.T) {
	k, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "p.key")
	if err := k.Save(path); err != nil {
		t.Fatal(err)
	}
	s, err := callersig.LoadSigner("ag_x", path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := callersig.EncodeKey(s.Key.Public().(ed25519.PublicKey)), callersig.EncodeKey(k.Public()); got != want {
		t.Fatalf("the loaded key is %s; janus-keys wrote %s", got, want)
	}
}
