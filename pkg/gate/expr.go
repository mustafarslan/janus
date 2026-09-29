package gate

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
)

// The policy expression language.
//
// It is total by construction: comparisons, membership, and boolean
// connectives over typed facts. There are no loops, no function calls, no
// recursion, and no arithmetic. Every expression terminates, and the shape of
// the grammar is small enough to read in one sitting:
//
//	expr       := or
//	or         := and ("or" and)*
//	and        := unary ("and" unary)*
//	unary      := "not" unary | primary
//	primary    := "(" expr ")" | comparison
//	comparison := operand [ ("==" | "!=" | "<" | "<=" | ">" | ">=") rhs
//	                      | "in" "[" operand ("," operand)* "]" ]
//	rhs        := operand | NUMBER "percent" "of" operand
//	operand    := IDENT | NUMBER | STRING | "true" | "false"
//
// The absence of arithmetic is the deliberate part. Once a language can
// compute, "what did the policy say" stops being answerable by reading it, and
// an auditor asking why a payment was refused should not have to evaluate a
// program in their head.
//
// # The one relative form, and why it is not arithmetic
//
// `amount_minor > 10 percent of result.balance.available_minor` exists because
// the first thing a real bank policy wants that a constant cannot express is a
// threshold relative to something else — a concentration limit, an exposure
// ratio, a fraction of a balance. Refusing that would push the comparison
// upstream into a participant, which is to say into the thing being gated.
//
// It stays inside the design's promises. There is no expression whose value is
// a computed number: the percentage exists only as one side of a comparison,
// which is evaluated by cross-multiplying integers (`left * 100` against
// `pct * right`) so nothing is ever divided, rounded, or represented as a
// float. Overflow is a refusal rather than a wraparound. And it still reads as
// the sentence a policy author meant.
//
// The percentage goes on the right of the comparison. Allowing it on either
// side would need a value type with a denominator, which is the first step
// towards the general arithmetic this deliberately does not have.
//
// Evaluation never returns a "don't know". An expression either yields a
// boolean or fails, and it fails on anything ambiguous: an unknown fact, a
// comparison between different types, an ordering on something that has no
// order. Callers treat failure as a refusal, which is what makes a
// misspelled fact name stop a payment rather than quietly permit one.

// Value is a typed value the expression language works over.
type Value struct {
	Type janusv1.FactType
	Text string
	Num  int64
	Flag bool
}

// TextValue constructs a text value.
func TextValue(s string) Value { return Value{Type: janusv1.FactType_FACT_TYPE_TEXT, Text: s} }

// NumberValue constructs a number value.
func NumberValue(n int64) Value { return Value{Type: janusv1.FactType_FACT_TYPE_NUMBER, Num: n} }

// FlagValue constructs a boolean value.
func FlagValue(b bool) Value { return Value{Type: janusv1.FactType_FACT_TYPE_FLAG, Flag: b} }

// String renders a value the way it would be written in a policy.
func (v Value) String() string {
	switch v.Type {
	case janusv1.FactType_FACT_TYPE_TEXT:
		return strconv.Quote(v.Text)
	case janusv1.FactType_FACT_TYPE_NUMBER:
		return strconv.FormatInt(v.Num, 10)
	case janusv1.FactType_FACT_TYPE_FLAG:
		return strconv.FormatBool(v.Flag)
	default:
		return "<untyped>"
	}
}

func typeName(t janusv1.FactType) string {
	switch t {
	case janusv1.FactType_FACT_TYPE_TEXT:
		return "text"
	case janusv1.FactType_FACT_TYPE_NUMBER:
		return "number"
	case janusv1.FactType_FACT_TYPE_FLAG:
		return "flag"
	default:
		return "untyped"
	}
}

// Errors from compiling and evaluating expressions. Every one of them means the
// same thing to a gate: refuse.
var (
	// ErrSyntax means the expression could not be parsed.
	ErrSyntax = errors.New("gate: expression syntax")
	// ErrUnknownFact means the expression named something the step does not
	// declare. It is an error rather than a false, because "the fact is absent"
	// and "the fact is false" are different situations and only one of them is
	// safe to act on.
	ErrUnknownFact = errors.New("gate: unknown fact")
	// ErrType means the expression compared values that cannot be compared.
	ErrType = errors.New("gate: type mismatch")
)

// Facts is what an expression is evaluated against.
type Facts map[string]Value

// Expr is a compiled expression.
type Expr struct {
	src  string
	root node
}

// Source returns the text the expression was compiled from.
func (e *Expr) Source() string { return e.src }

// Names lists every fact the expression reads, sorted, so a policy can be
// checked against a schema before either is deployed.
func (e *Expr) Names() []string {
	seen := map[string]struct{}{}
	e.root.names(seen)
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

// Compile parses an expression. Doing this at admission rather than at gate
// time is what turns a typo in a policy into a rejected policy rather than a
// refused payment at three in the morning.
func Compile(src string) (*Expr, error) {
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks, src: src}
	root, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	if !p.at(tokEOF) {
		return nil, fmt.Errorf("%w: unexpected %s at position %d in %q",
			ErrSyntax, p.peek().describe(), p.peek().pos, src)
	}
	return &Expr{src: src, root: root}, nil
}

// Eval evaluates the expression against a set of facts.
func (e *Expr) Eval(f Facts) (bool, error) {
	v, err := e.root.eval(f)
	if err != nil {
		return false, err
	}
	if v.Type != janusv1.FactType_FACT_TYPE_FLAG {
		return false, fmt.Errorf("%w: expression %q yields %s, and a gate needs a yes or no",
			ErrType, e.src, typeName(v.Type))
	}
	return v.Flag, nil
}

// ---- tokens -------------------------------------------------------------------

type tokKind int

const (
	tokEOF tokKind = iota
	tokIdent
	tokNumber
	tokString
	tokOp
	tokKeyword
	tokPunct
)

type token struct {
	kind tokKind
	text string
	num  int64
	pos  int
}

func (t token) describe() string {
	if t.kind == tokEOF {
		return "end of expression"
	}
	return strconv.Quote(t.text)
}

var keywords = map[string]bool{
	"and": true, "or": true, "not": true, "in": true, "true": true, "false": true,
	"percent": true, "of": true,
}

func lex(src string) ([]token, error) {
	var out []token
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(' || c == ')' || c == '[' || c == ']' || c == ',':
			out = append(out, token{kind: tokPunct, text: string(c), pos: i})
			i++
		case c == '=' || c == '!' || c == '<' || c == '>':
			start := i
			op := string(c)
			if i+1 < len(src) && src[i+1] == '=' {
				op += "="
				i++
			}
			i++
			if op == "=" || op == "!" {
				return nil, fmt.Errorf("%w: %q at position %d is not an operator; did you mean %q?",
					ErrSyntax, op, start, op+"=")
			}
			out = append(out, token{kind: tokOp, text: op, pos: start})
		case c == '"':
			s, next, err := lexString(src, i)
			if err != nil {
				return nil, err
			}
			out = append(out, token{kind: tokString, text: s, pos: i})
			i = next
		case c >= '0' && c <= '9', c == '-':
			start := i
			if c == '-' {
				i++
			}
			digits := i
			for i < len(src) && src[i] >= '0' && src[i] <= '9' {
				i++
			}
			if i == digits {
				return nil, fmt.Errorf("%w: %q at position %d is not a number",
					ErrSyntax, src[start:i], start)
			}
			n, err := strconv.ParseInt(src[start:i], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%w: %q at position %d does not fit in a 64-bit integer",
					ErrSyntax, src[start:i], start)
			}
			out = append(out, token{kind: tokNumber, num: n, text: src[start:i], pos: start})
		case isIdentStart(c):
			start := i
			for i < len(src) && (isIdentPart(src[i]) || src[i] == '.') {
				i++
			}
			word := src[start:i]
			kind := tokIdent
			if keywords[word] {
				kind = tokKeyword
			}
			out = append(out, token{kind: kind, text: word, pos: start})
		default:
			return nil, fmt.Errorf("%w: unexpected character %q at position %d",
				ErrSyntax, string(c), i)
		}
	}
	return append(out, token{kind: tokEOF, pos: len(src)}), nil
}

func lexString(src string, i int) (string, int, error) {
	var b strings.Builder
	start := i
	i++ // opening quote
	for i < len(src) {
		switch src[i] {
		case '\\':
			if i+1 >= len(src) {
				return "", 0, fmt.Errorf("%w: string starting at position %d ends in a backslash",
					ErrSyntax, start)
			}
			switch src[i+1] {
			case '"', '\\':
				b.WriteByte(src[i+1])
			default:
				return "", 0, fmt.Errorf("%w: unknown escape %q at position %d; only \\\" and \\\\ "+
					"are recognised", ErrSyntax, src[i:i+2], i)
			}
			i += 2
		case '"':
			return b.String(), i + 1, nil
		default:
			b.WriteByte(src[i])
			i++
		}
	}
	return "", 0, fmt.Errorf("%w: string starting at position %d is never closed", ErrSyntax, start)
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool { return isIdentStart(c) || (c >= '0' && c <= '9') }

// ---- ast ----------------------------------------------------------------------

type node interface {
	eval(Facts) (Value, error)
	names(map[string]struct{})
}

type literalNode struct{ v Value }

func (n literalNode) eval(Facts) (Value, error) { return n.v, nil }
func (n literalNode) names(map[string]struct{}) {}

type factNode struct{ name string }

func (n factNode) eval(f Facts) (Value, error) {
	v, ok := f[n.name]
	if !ok {
		return Value{}, fmt.Errorf("%w: %q is not declared by this step, so there is nothing to "+
			"decide on", ErrUnknownFact, n.name)
	}
	return v, nil
}

func (n factNode) names(set map[string]struct{}) { set[n.name] = struct{}{} }

type notNode struct{ inner node }

func (n notNode) eval(f Facts) (Value, error) {
	v, err := n.inner.eval(f)
	if err != nil {
		return Value{}, err
	}
	if v.Type != janusv1.FactType_FACT_TYPE_FLAG {
		return Value{}, fmt.Errorf("%w: \"not\" applied to %s", ErrType, typeName(v.Type))
	}
	return FlagValue(!v.Flag), nil
}

func (n notNode) names(set map[string]struct{}) { n.inner.names(set) }

type boolNode struct {
	op          string // "and" | "or"
	left, right node
}

func (n boolNode) eval(f Facts) (Value, error) {
	// Both sides are evaluated even when the first settles the answer.
	//
	// Short-circuiting would make a policy's meaning depend on the order its
	// clauses happen to be written in: `false and typo_in_fact_name` would
	// quietly pass while `typo_in_fact_name and false` refused. A policy that
	// names a fact which does not exist is broken either way, and the gate
	// should say so either way.
	left, lerr := n.left.eval(f)
	right, rerr := n.right.eval(f)
	if lerr != nil {
		return Value{}, lerr
	}
	if rerr != nil {
		return Value{}, rerr
	}
	if left.Type != janusv1.FactType_FACT_TYPE_FLAG || right.Type != janusv1.FactType_FACT_TYPE_FLAG {
		return Value{}, fmt.Errorf("%w: %q applied to %s and %s",
			ErrType, n.op, typeName(left.Type), typeName(right.Type))
	}
	if n.op == "and" {
		return FlagValue(left.Flag && right.Flag), nil
	}
	return FlagValue(left.Flag || right.Flag), nil
}

func (n boolNode) names(set map[string]struct{}) {
	n.left.names(set)
	n.right.names(set)
}

type compareNode struct {
	op          string
	left, right node
}

func (n compareNode) eval(f Facts) (Value, error) {
	left, err := n.left.eval(f)
	if err != nil {
		return Value{}, err
	}
	right, err := n.right.eval(f)
	if err != nil {
		return Value{}, err
	}
	if left.Type != right.Type {
		return Value{}, fmt.Errorf("%w: cannot compare %s with %s (%s %s %s)",
			ErrType, typeName(left.Type), typeName(right.Type), left, n.op, right)
	}

	switch n.op {
	case "==":
		return FlagValue(equal(left, right)), nil
	case "!=":
		return FlagValue(!equal(left, right)), nil
	}

	// Ordering is defined on numbers only. Text has no ordering a policy should
	// rely on — "does this account id sort before that one" is never the
	// question anyone means — and booleans have none at all.
	if left.Type != janusv1.FactType_FACT_TYPE_NUMBER {
		return Value{}, fmt.Errorf("%w: %q needs numbers, and %s has no ordering",
			ErrType, n.op, typeName(left.Type))
	}
	switch n.op {
	case "<":
		return FlagValue(left.Num < right.Num), nil
	case "<=":
		return FlagValue(left.Num <= right.Num), nil
	case ">":
		return FlagValue(left.Num > right.Num), nil
	default:
		return FlagValue(left.Num >= right.Num), nil
	}
}

func (n compareNode) names(set map[string]struct{}) {
	n.left.names(set)
	n.right.names(set)
}

func equal(a, b Value) bool {
	switch a.Type {
	case janusv1.FactType_FACT_TYPE_TEXT:
		return a.Text == b.Text
	case janusv1.FactType_FACT_TYPE_NUMBER:
		return a.Num == b.Num
	default:
		return a.Flag == b.Flag
	}
}

// percentNode compares a value against a percentage of another value.
//
// It never computes the percentage. `left OP pct% of base` is decided by
// comparing `left * 100` with `pct * base`, which is exact: no division, no
// rounding, and no way for the answer to depend on which side the remainder
// fell. `amount > 10 percent of balance` means what it says at every value
// rather than at most of them.
type percentNode struct {
	op      string
	left    node
	percent int64
	base    node
}

func (n percentNode) eval(f Facts) (Value, error) {
	left, err := n.left.eval(f)
	if err != nil {
		return Value{}, err
	}
	base, err := n.base.eval(f)
	if err != nil {
		return Value{}, err
	}
	if left.Type != janusv1.FactType_FACT_TYPE_NUMBER {
		return Value{}, fmt.Errorf("%w: %q is %s, and a percentage compares numbers",
			ErrType, left, typeName(left.Type))
	}
	if base.Type != janusv1.FactType_FACT_TYPE_NUMBER {
		return Value{}, fmt.Errorf("%w: a percentage of %s is not a quantity",
			ErrType, typeName(base.Type))
	}
	if base.Num < 0 {
		// "10 percent of minus four hundred" has an arithmetic answer and no
		// useful meaning as a limit, and guessing which direction the author
		// intended is not something a gate should do.
		return Value{}, fmt.Errorf("%w: a percentage of a negative quantity (%d) has no meaning "+
			"as a threshold", ErrType, base.Num)
	}

	scaled, err := mul(left.Num, 100)
	if err != nil {
		return Value{}, err
	}
	share, err := mul(n.percent, base.Num)
	if err != nil {
		return Value{}, err
	}
	return FlagValue(orderedBy(n.op, scaled, share)), nil
}

func (n percentNode) names(set map[string]struct{}) {
	n.left.names(set)
	n.base.names(set)
}

// mul multiplies without wrapping. An overflow is a refusal: a comparison whose
// operands do not fit is not a comparison that came out false.
func mul(a, b int64) (int64, error) {
	if a == 0 || b == 0 {
		return 0, nil
	}
	p := a * b
	if p/b != a {
		return 0, fmt.Errorf("%w: comparing %d against a percentage of a quantity this large "+
			"overflows a 64-bit integer, so the comparison has no answer", ErrType, a)
	}
	return p, nil
}

func orderedBy(op string, a, b int64) bool {
	switch op {
	case "==":
		return a == b
	case "!=":
		return a != b
	case "<":
		return a < b
	case "<=":
		return a <= b
	case ">":
		return a > b
	default:
		return a >= b
	}
}

type inNode struct {
	left node
	set  []node
}

func (n inNode) eval(f Facts) (Value, error) {
	left, err := n.left.eval(f)
	if err != nil {
		return Value{}, err
	}

	// The whole list is checked before any membership test, so a mistyped entry
	// is caught wherever it sits. Returning on the first match would make
	// `currency in ["EUR", 3]` pass quietly for EUR and fail only for the
	// currencies that reached the end — a list that means different things
	// depending on what is being looked up in it.
	found := false
	for _, item := range n.set {
		v, err := item.eval(f)
		if err != nil {
			return Value{}, err
		}
		if v.Type != left.Type {
			return Value{}, fmt.Errorf("%w: %q is %s but the list holds %s",
				ErrType, left, typeName(left.Type), typeName(v.Type))
		}
		if equal(left, v) {
			found = true
		}
	}
	return FlagValue(found), nil
}

func (n inNode) names(set map[string]struct{}) {
	n.left.names(set)
	for _, item := range n.set {
		item.names(set)
	}
}

// ---- parser -------------------------------------------------------------------

type parser struct {
	toks []token
	i    int
	src  string
}

func (p *parser) peek() token { return p.toks[p.i] }

func (p *parser) at(k tokKind) bool { return p.toks[p.i].kind == k }

func (p *parser) atKeyword(w string) bool {
	return p.toks[p.i].kind == tokKeyword && p.toks[p.i].text == w
}

func (p *parser) atPunct(w string) bool {
	return p.toks[p.i].kind == tokPunct && p.toks[p.i].text == w
}

func (p *parser) next() token {
	t := p.toks[p.i]
	if t.kind != tokEOF {
		p.i++
	}
	return t
}

func (p *parser) parseExpr() (node, error) { return p.parseOr() }

func (p *parser) parseOr() (node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.atKeyword("or") {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = boolNode{op: "or", left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.atKeyword("and") {
		p.next()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = boolNode{op: "and", left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseUnary() (node, error) {
	if p.atKeyword("not") {
		p.next()
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return notNode{inner: inner}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (node, error) {
	if p.atPunct("(") {
		p.next()
		inner, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if !p.atPunct(")") {
			return nil, fmt.Errorf("%w: expected \")\" at position %d, found %s",
				ErrSyntax, p.peek().pos, p.peek().describe())
		}
		p.next()
		return inner, nil
	}
	return p.parseComparison()
}

func (p *parser) parseComparison() (node, error) {
	left, err := p.parseOperand()
	if err != nil {
		return nil, err
	}
	switch {
	case p.at(tokOp):
		op := p.next()
		right, err := p.parseOperand()
		if err != nil {
			return nil, err
		}
		// A number followed by "percent of" makes the right-hand side a
		// fraction of another fact rather than a constant.
		if n, ok := right.(literalNode); ok && p.atKeyword("percent") {
			p.next()
			if !p.atKeyword("of") {
				return nil, fmt.Errorf("%w: \"percent\" must be followed by \"of\" at position %d, "+
					"found %s", ErrSyntax, p.peek().pos, p.peek().describe())
			}
			p.next()
			base, err := p.parseOperand()
			if err != nil {
				return nil, err
			}
			if n.v.Type != janusv1.FactType_FACT_TYPE_NUMBER {
				return nil, fmt.Errorf("%w: a percentage must be a whole number, not %s",
					ErrSyntax, typeName(n.v.Type))
			}
			return percentNode{op: op.text, left: left, percent: n.v.Num, base: base}, nil
		}
		if p.atKeyword("percent") {
			return nil, fmt.Errorf("%w: \"percent\" must follow a whole number at position %d",
				ErrSyntax, p.peek().pos)
		}
		return compareNode{op: op.text, left: left, right: right}, nil
	case p.atKeyword("in"):
		p.next()
		return p.parseInList(left)
	default:
		// A bare operand stands on its own only if it is a boolean. Whether it
		// is cannot be known until evaluation, so the check lives there.
		return left, nil
	}
}

func (p *parser) parseInList(left node) (node, error) {
	if !p.atPunct("[") {
		return nil, fmt.Errorf("%w: \"in\" needs a list at position %d, found %s",
			ErrSyntax, p.peek().pos, p.peek().describe())
	}
	p.next()
	var set []node
	for {
		item, err := p.parseOperand()
		if err != nil {
			return nil, err
		}
		set = append(set, item)
		if p.atPunct(",") {
			p.next()
			continue
		}
		break
	}
	if !p.atPunct("]") {
		return nil, fmt.Errorf("%w: expected \"]\" at position %d, found %s",
			ErrSyntax, p.peek().pos, p.peek().describe())
	}
	p.next()
	return inNode{left: left, set: set}, nil
}

func (p *parser) parseOperand() (node, error) {
	t := p.peek()
	switch {
	case t.kind == tokIdent:
		p.next()
		return factNode{name: t.text}, nil
	case t.kind == tokNumber:
		p.next()
		return literalNode{v: NumberValue(t.num)}, nil
	case t.kind == tokString:
		p.next()
		return literalNode{v: TextValue(t.text)}, nil
	case p.atKeyword("true"):
		p.next()
		return literalNode{v: FlagValue(true)}, nil
	case p.atKeyword("false"):
		p.next()
		return literalNode{v: FlagValue(false)}, nil
	default:
		return nil, fmt.Errorf("%w: expected a fact name or a literal at position %d, found %s",
			ErrSyntax, t.pos, t.describe())
	}
}
