// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package metricalert

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
)

// Expr is a compiled calc/warn/crit expression. The language is a small
// subset of Netdata's: numbers, $variables, + - * / %, comparisons,
// && || !, the ternary ?:, parentheses and abs()/min()/max(). Any
// comparison involving NaN is false, so an expression over missing data
// never raises an alert.
type Expr struct {
	src  string
	root node
}

// Vars resolves $name references. Unknown names evaluate to NaN.
type Vars func(name string) float64

type node interface{ eval(Vars) float64 }

type num float64
type variable string
type unary struct {
	op string
	x  node
}
type binary struct {
	op   string
	l, r node
}
type ternary struct{ c, t, f node }
type call struct {
	fn   string
	args []node
}

func (n num) eval(Vars) float64         { return float64(n) }
func (v variable) eval(vs Vars) float64 { return vs(string(v)) }

func truth(v float64) bool { return !math.IsNaN(v) && v != 0 }

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func (u unary) eval(vs Vars) float64 {
	x := u.x.eval(vs)
	if u.op == "!" {
		return b2f(!truth(x))
	}
	return -x
}

func (b binary) eval(vs Vars) float64 {
	switch b.op {
	case "&&":
		return b2f(truth(b.l.eval(vs)) && truth(b.r.eval(vs)))
	case "||":
		return b2f(truth(b.l.eval(vs)) || truth(b.r.eval(vs)))
	}
	l, r := b.l.eval(vs), b.r.eval(vs)
	switch b.op {
	case "+":
		return l + r
	case "-":
		return l - r
	case "*":
		return l * r
	case "/":
		if r == 0 {
			return math.NaN()
		}
		return l / r
	case "%":
		if r == 0 {
			return math.NaN()
		}
		return math.Mod(l, r)
	}
	if math.IsNaN(l) || math.IsNaN(r) {
		if b.op == "!=" {
			return b2f(math.IsNaN(l) != math.IsNaN(r))
		}
		return 0
	}
	switch b.op {
	case ">":
		return b2f(l > r)
	case ">=":
		return b2f(l >= r)
	case "<":
		return b2f(l < r)
	case "<=":
		return b2f(l <= r)
	case "==":
		return b2f(l == r)
	case "!=":
		return b2f(l != r)
	}
	return math.NaN()
}

func (t ternary) eval(vs Vars) float64 {
	if truth(t.c.eval(vs)) {
		return t.t.eval(vs)
	}
	return t.f.eval(vs)
}

func (c call) eval(vs Vars) float64 {
	a := make([]float64, len(c.args))
	for i, x := range c.args {
		a[i] = x.eval(vs)
	}
	switch c.fn {
	case "abs":
		return math.Abs(a[0])
	case "min":
		return math.Min(a[0], a[1])
	case "max":
		return math.Max(a[0], a[1])
	}
	return math.NaN()
}

// Eval evaluates e. A nil expression is NaN.
func (e *Expr) Eval(vs Vars) float64 {
	if e == nil || e.root == nil {
		return math.NaN()
	}
	return e.root.eval(vs)
}

func (e *Expr) String() string {
	if e == nil {
		return ""
	}
	return e.src
}

// Compile parses src. An empty src gives a nil Expr.
func Compile(src string) (*Expr, error) {
	src = strings.TrimSpace(src)
	if src == "" {
		return nil, nil
	}
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	n, err := p.expr(0)
	if err != nil {
		return nil, fmt.Errorf("%q: %w", src, err)
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("%q: unexpected %q", src, p.toks[p.pos])
	}
	return &Expr{src: src, root: n}, nil
}

func lex(s string) ([]string, error) {
	var out []string
	for i := 0; i < len(s); {
		c := rune(s[i])
		switch {
		case unicode.IsSpace(c):
			i++
		case c == '$':
			j := i + 1
			if j < len(s) && s[j] == '{' {
				k := strings.IndexByte(s[j:], '}')
				if k < 0 {
					return nil, fmt.Errorf("unterminated ${")
				}
				out = append(out, "$"+s[j+1:j+k])
				i = j + k + 1
				continue
			}
			for j < len(s) && (isIdent(rune(s[j]))) {
				j++
			}
			if j == i+1 {
				return nil, fmt.Errorf("empty variable at %d", i)
			}
			out = append(out, s[i:j])
			i = j
		case unicode.IsDigit(c) || c == '.':
			j := i
			for j < len(s) && (unicode.IsDigit(rune(s[j])) || s[j] == '.' || s[j] == 'e' || s[j] == 'E' ||
				((s[j] == '-' || s[j] == '+') && j > i && (s[j-1] == 'e' || s[j-1] == 'E'))) {
				j++
			}
			out = append(out, s[i:j])
			i = j
		case unicode.IsLetter(c):
			j := i
			for j < len(s) && isIdent(rune(s[j])) {
				j++
			}
			out = append(out, strings.ToLower(s[i:j]))
			i = j
		default:
			if i+1 < len(s) {
				two := s[i : i+2]
				switch two {
				case ">=", "<=", "==", "!=", "&&", "||":
					out = append(out, two)
					i += 2
					continue
				}
			}
			if strings.ContainsRune("+-*/%()<>!?:,", c) {
				out = append(out, string(c))
				i++
				continue
			}
			return nil, fmt.Errorf("unexpected character %q", c)
		}
	}
	return out, nil
}

func isIdent(c rune) bool { return unicode.IsLetter(c) || unicode.IsDigit(c) || c == '_' }

type parser struct {
	toks []string
	pos  int
}

func (p *parser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *parser) next() string {
	t := p.peek()
	p.pos++
	return t
}

var precedence = map[string]int{
	"?": 1, "||": 2, "&&": 3,
	"==": 4, "!=": 4,
	">": 5, ">=": 5, "<": 5, "<=": 5,
	"+": 6, "-": 6,
	"*": 7, "/": 7, "%": 7,
}

// keyword aliases accepted for readability: "and", "or", "not".
var aliases = map[string]string{"and": "&&", "or": "||"}

func (p *parser) expr(minPrec int) (node, error) {
	left, err := p.unary()
	if err != nil {
		return nil, err
	}
	for {
		op := p.peek()
		if a, ok := aliases[op]; ok {
			op = a
		}
		prec, ok := precedence[op]
		if !ok || prec <= minPrec {
			return left, nil
		}
		p.next()
		if op == "?" {
			t, err := p.expr(0)
			if err != nil {
				return nil, err
			}
			if p.next() != ":" {
				return nil, fmt.Errorf("ternary without ':'")
			}
			f, err := p.expr(prec - 1)
			if err != nil {
				return nil, err
			}
			left = ternary{left, t, f}
			continue
		}
		right, err := p.expr(prec)
		if err != nil {
			return nil, err
		}
		left = binary{op, left, right}
	}
}

func (p *parser) unary() (node, error) {
	t := p.next()
	switch {
	case t == "":
		return nil, fmt.Errorf("unexpected end of expression")
	case t == "-" || t == "!" || t == "not":
		x, err := p.unary()
		if err != nil {
			return nil, err
		}
		op := t
		if op == "not" {
			op = "!"
		}
		return unary{op, x}, nil
	case t == "+":
		return p.unary()
	case t == "(":
		n, err := p.expr(0)
		if err != nil {
			return nil, err
		}
		if p.next() != ")" {
			return nil, fmt.Errorf("missing ')'")
		}
		return n, nil
	case strings.HasPrefix(t, "$"):
		return variable(t[1:]), nil
	case t == "abs" || t == "min" || t == "max":
		if p.next() != "(" {
			return nil, fmt.Errorf("%s needs '('", t)
		}
		var args []node
		for {
			a, err := p.expr(0)
			if err != nil {
				return nil, err
			}
			args = append(args, a)
			sep := p.next()
			if sep == ")" {
				break
			}
			if sep != "," {
				return nil, fmt.Errorf("bad argument list for %s", t)
			}
		}
		want := 2
		if t == "abs" {
			want = 1
		}
		if len(args) != want {
			return nil, fmt.Errorf("%s takes %d argument(s)", t, want)
		}
		return call{t, args}, nil
	case t == "nan":
		return num(math.NaN()), nil
	case t == "inf":
		return num(math.Inf(1)), nil
	}
	f, err := strconv.ParseFloat(t, 64)
	if err != nil {
		return nil, fmt.Errorf("unexpected %q", t)
	}
	return num(f), nil
}
