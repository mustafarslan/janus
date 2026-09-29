package gate_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/mustafarslan/janus/pkg/gate"
)

func facts() gate.Facts {
	return gate.Facts{
		"amount_minor": gate.NumberValue(250000),
		"currency":     gate.TextValue("EUR"),
		"approved":     gate.FlagValue(true),
		"sanctioned":   gate.FlagValue(false),
	}
}

func TestExpressionsEvaluate(t *testing.T) {
	cases := []struct {
		expr string
		want bool
	}{
		{`amount_minor == 250000`, true},
		{`amount_minor != 250000`, false},
		{`amount_minor < 1000000`, true},
		{`amount_minor <= 250000`, true},
		{`amount_minor > 1000000`, false},
		{`amount_minor >= 250000`, true},
		{`currency == "EUR"`, true},
		{`currency in ["GBP", "EUR", "USD"]`, true},
		{`currency in ["GBP", "USD"]`, false},
		{`approved`, true},
		{`not sanctioned`, true},
		{`not not approved`, true},
		{`approved and not sanctioned`, true},
		{`approved and sanctioned`, false},
		{`approved or sanctioned`, true},
		{`sanctioned or amount_minor > 1000000`, false},
		{`(approved or sanctioned) and currency == "EUR"`, true},
		{`approved == true`, true},
		{`sanctioned == false`, true},
		{`amount_minor > -1`, true},
		{`true`, true},
		{`false`, false},

		// "and" binds tighter than "or", so this is (false and false) or true.
		{`sanctioned and approved or currency == "EUR"`, true},
	}

	for _, c := range cases {
		t.Run(c.expr, func(t *testing.T) {
			e, err := gate.Compile(c.expr)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			got, err := e.Eval(facts())
			if err != nil {
				t.Fatalf("eval: %v", err)
			}
			if got != c.want {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

// An expression that cannot be evaluated is not false: it is unanswered, and a
// gate treats unanswered as a refusal. Returning false instead would
// make a misspelled fact name silently permit whatever it was meant to stop.
func TestUnanswerableExpressionsFailRatherThanReturningFalse(t *testing.T) {
	cases := []struct {
		name string
		expr string
		want error
	}{
		{"misspelled fact", `amount_minr < 1000`, gate.ErrUnknownFact},
		{"fact that is simply absent", `beneficiary_ok`, gate.ErrUnknownFact},
		{"absent fact inside a disjunction that would otherwise pass",
			`approved or nonexistent == 1`, gate.ErrUnknownFact},
		{"absent fact inside a conjunction that would otherwise fail",
			`sanctioned and nonexistent == 1`, gate.ErrUnknownFact},
		{"number against text", `amount_minor == "250000"`, gate.ErrType},
		{"text ordering", `currency < "EUR"`, gate.ErrType},
		{"flag ordering", `approved > false`, gate.ErrType},
		{"boolean operator on a number", `amount_minor and approved`, gate.ErrType},
		{"not on a number", `not amount_minor`, gate.ErrType},
		{"a bare non-boolean is not a decision", `amount_minor`, gate.ErrType},
		{"mixed list", `currency in ["EUR", 3]`, gate.ErrType},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, err := gate.Compile(c.expr)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			got, err := e.Eval(facts())
			if err == nil {
				t.Fatalf("evaluated to %v; an unanswerable expression must fail", got)
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

// Both sides of a boolean operator are evaluated even when the first settles
// the answer, so a policy's meaning does not depend on the order its clauses
// happen to be written in.
func TestBooleansDoNotShortCircuitPastABrokenClause(t *testing.T) {
	for _, expr := range []string{
		`sanctioned and typo_here`, // left is false: "and" is already decided
		`approved or typo_here`,    // left is true: "or" is already decided
		`typo_here and sanctioned`, // the broken clause first
		`typo_here or approved`,    //
	} {
		e, err := gate.Compile(expr)
		if err != nil {
			t.Fatalf("%s: compile: %v", expr, err)
		}
		if _, err := e.Eval(facts()); !errors.Is(err, gate.ErrUnknownFact) {
			t.Fatalf("%s: got %v, want the broken clause to be reported wherever it sits", expr, err)
		}
	}
}

func TestSyntaxErrorsAreRejectedAtCompileTime(t *testing.T) {
	cases := []struct {
		name string
		expr string
		// hint is a fragment the message must contain, so the error is useful
		// to whoever wrote the policy rather than merely present.
		hint string
	}{
		{"assignment mistaken for comparison", `currency = "EUR"`, `"=="`},
		{"negation mistaken for inequality", `approved ! false`, `"!="`},
		{"unclosed string", `currency == "EUR`, "never closed"},
		{"unclosed parenthesis", `(approved and not sanctioned`, `expected ")"`},
		{"unclosed list", `currency in ["EUR"`, `expected "]"`},
		{"in without a list", `currency in "EUR"`, "needs a list"},
		{"trailing operator", `approved and`, "expected a fact name or a literal"},
		{"empty expression", ``, "expected a fact name or a literal"},
		{"stray text", `approved true`, "unexpected"},
		{"unknown character", `approved & sanctioned`, "unexpected character"},
		{"unknown escape", `currency == "E\nUR"`, "unknown escape"},
		{"integer too large", `amount_minor < 99999999999999999999`, "64-bit"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := gate.Compile(c.expr)
			if !errors.Is(err, gate.ErrSyntax) {
				t.Fatalf("got %v, want a syntax error", err)
			}
			if !strings.Contains(err.Error(), c.hint) {
				t.Fatalf("message does not mention %q: %v", c.hint, err)
			}
		})
	}
}

func TestEscapesInStringLiterals(t *testing.T) {
	e, err := gate.Compile(`note == "say \"hi\" \\ done"`)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := e.Eval(gate.Facts{"note": gate.TextValue(`say "hi" \ done`)})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("escaped quotes and backslashes did not round-trip")
	}
}

// Names is what lets a policy be checked against a schema before either is
// deployed: every fact an expression reads should be one the schema declares.
func TestNamesListsEveryFactAnExpressionReads(t *testing.T) {
	e, err := gate.Compile(`amount_minor < 100 and (currency in ["EUR"] or not sanctioned)`)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(e.Names(), ",")
	if want := "amount_minor,currency,sanctioned"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// ---- relative thresholds ------------------------------------------------------

// The one relative form the language has. It exists because the first thing a
// real policy wants that a constant cannot express is a threshold relative to
// something else, and refusing that would push the comparison into whatever is
// being gated.
func TestPercentageComparisonsAreExact(t *testing.T) {
	f := gate.Facts{
		"amount":  gate.NumberValue(100),
		"balance": gate.NumberValue(1000),
		// A base that does not divide evenly by the percentage, which is where
		// a division-based implementation would start rounding.
		"odd":  gate.NumberValue(1005),
		"zero": gate.NumberValue(0),
	}
	cases := []struct {
		expr string
		want bool
	}{
		{`amount <= 10 percent of balance`, true}, // exactly a tenth
		{`amount < 10 percent of balance`, false}, // and not less than one
		{`amount >= 10 percent of balance`, true},
		{`amount > 10 percent of balance`, false},
		{`amount == 10 percent of balance`, true},
		{`amount != 10 percent of balance`, false},
		{`amount <= 5 percent of balance`, false},
		{`amount <= 100 percent of balance`, true},
		{`amount > 0 percent of balance`, true},

		// 10% of 1005 is 100.5, and these are the cases that separate an exact
		// comparison from one that divides and truncates. An implementation
		// computing floor(10050/100) = 100 would call 100 neither under the
		// threshold nor over it, getting both of the next two wrong — and it
		// would get them wrong in the direction that refuses a payment the
		// policy permits, which is the kind of bug that gets a control
		// switched off rather than fixed.
		{`amount < 10 percent of odd`, true},
		{`amount >= 10 percent of odd`, false},
		{`amount <= 10 percent of odd`, true},
		{`101 <= 10 percent of odd`, false},

		// A percentage of nothing is nothing, and zero is not negative.
		{`amount > 50 percent of zero`, true},
		{`zero <= 50 percent of zero`, true},
	}

	for _, c := range cases {
		t.Run(c.expr, func(t *testing.T) {
			e, err := gate.Compile(c.expr)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			got, err := e.Eval(f)
			if err != nil {
				t.Fatalf("eval: %v", err)
			}
			if got != c.want {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestPercentagesRefuseWhatTheyCannotAnswer(t *testing.T) {
	f := gate.Facts{
		"amount":    gate.NumberValue(100),
		"balance":   gate.NumberValue(1000),
		"overdrawn": gate.NumberValue(-1000),
		"currency":  gate.TextValue("EUR"),
		"huge":      gate.NumberValue(1 << 62),
	}
	cases := []struct {
		name string
		expr string
		hint string
	}{
		{"a percentage of a negative quantity", `amount > 10 percent of overdrawn`,
			"no meaning as a threshold"},
		{"a percentage of something that is not a quantity", `amount > 10 percent of currency`,
			"is not a quantity"},
		{"comparing text against a percentage", `currency > 10 percent of balance`,
			"a percentage compares numbers"},
		{"a percentage of a fact that does not exist", `amount > 10 percent of nonexistent`,
			"not declared by this step"},
		{"operands too large to compare", `huge > 10 percent of huge`, "overflows"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, err := gate.Compile(c.expr)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			got, err := e.Eval(f)
			if err == nil {
				t.Fatalf("evaluated to %v; an unanswerable comparison must fail", got)
			}
			if !strings.Contains(err.Error(), c.hint) {
				t.Fatalf("message does not mention %q: %v", c.hint, err)
			}
		})
	}
}

func TestMalformedPercentagesAreRejectedAtCompileTime(t *testing.T) {
	cases := []struct {
		name string
		expr string
		hint string
	}{
		{"percent without of", `amount > 10 percent balance`, `must be followed by "of"`},
		{"percent without a number", `amount > balance percent of balance`,
			`must follow a whole number`},
		{"percent of nothing", `amount > 10 percent of`, "expected a fact name or a literal"},
		{"a percentage written as text", `amount > "ten" percent of balance`,
			"must be a whole number, not text"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := gate.Compile(c.expr)
			if !errors.Is(err, gate.ErrSyntax) {
				t.Fatalf("got %v, want a syntax error", err)
			}
			if !strings.Contains(err.Error(), c.hint) {
				t.Fatalf("message does not mention %q: %v", c.hint, err)
			}
		})
	}
}

// Names has to see through the relative form too, or a policy could reference a
// fact no schema declares and nobody would notice until it refused something.
func TestNamesSeesFactsInsideARelativeThreshold(t *testing.T) {
	e, err := gate.Compile(`amount_minor <= 10 percent of result.balance.available_minor`)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(e.Names(), ",")
	if want := "amount_minor,result.balance.available_minor"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
