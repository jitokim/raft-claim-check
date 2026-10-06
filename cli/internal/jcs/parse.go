package jcs

import (
	"errors"
	"fmt"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxDepth is the deepest nesting of arrays and objects that Parse accepts.
const MaxDepth = 64

// SyntaxError reports why and where Parse refused its input.
type SyntaxError struct {
	Offset int    // byte offset into the input
	Msg    string // human-readable reason
	Cause  error  // ErrDuplicateKey, ErrNotInteger, ErrIntRange or nil
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("jcs: invalid JSON at byte %d: %s", e.Offset, e.Msg)
}

func (e *SyntaxError) Unwrap() error { return e.Cause }

// Sentinel causes, matched with errors.Is on a *SyntaxError.
var (
	ErrDuplicateKey = errors.New("duplicate object key")
	ErrNotInteger   = errors.New("number is not an integer")
	ErrIntRange     = errors.New("integer outside ±2^53")
)

// Parse decodes one JSON value strictly. It refuses:
//   - invalid UTF-8 anywhere, a byte-order mark, and trailing data;
//   - duplicate object keys at any depth (compared after unescaping);
//   - any number with a fraction or exponent, and integers outside ±MaxInt;
//   - unpaired UTF-16 surrogates in \u escapes;
//   - nesting deeper than MaxDepth.
//
// "-0" is accepted and yields 0, as JavaScript's JCS produces "0" for it.
func Parse(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, &SyntaxError{Offset: 0, Msg: "input is not valid UTF-8"}
	}
	p := &parser{data: data}
	p.skipSpace()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.pos != len(p.data) {
		return nil, p.fail("trailing data after the JSON value")
	}
	return v, nil
}

type parser struct {
	data []byte
	pos  int
}

func (p *parser) fail(msg string) error { return &SyntaxError{Offset: p.pos, Msg: msg} }

func (p *parser) failCause(cause error, msg string) error {
	return &SyntaxError{Offset: p.pos, Msg: msg, Cause: cause}
}

func (p *parser) skipSpace() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) (any, error) {
	if p.pos >= len(p.data) {
		return nil, p.fail("unexpected end of input")
	}
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.object(depth + 1)
	case c == '[':
		return p.array(depth + 1)
	case c == '"':
		return p.string()
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	default:
		for _, lit := range []struct {
			text string
			v    any
		}{{"true", true}, {"false", false}, {"null", nil}} {
			if p.hasPrefix(lit.text) {
				p.pos += len(lit.text)
				return lit.v, nil
			}
		}
		return nil, p.fail(fmt.Sprintf("unexpected character %q", c))
	}
}

func (p *parser) hasPrefix(s string) bool {
	return len(p.data)-p.pos >= len(s) && string(p.data[p.pos:p.pos+len(s)]) == s
}

func (p *parser) object(depth int) (any, error) {
	if depth > MaxDepth {
		return nil, p.fail("nesting too deep")
	}
	p.pos++ // '{'
	obj := map[string]any{}
	p.skipSpace()
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		return obj, nil
	}
	for {
		p.skipSpace()
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return nil, p.fail("expected a string object key")
		}
		keyAt := p.pos
		k, err := p.string()
		if err != nil {
			return nil, err
		}
		if _, dup := obj[k]; dup {
			p.pos = keyAt
			return nil, p.failCause(ErrDuplicateKey, fmt.Sprintf("duplicate object key %q", k))
		}
		p.skipSpace()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return nil, p.fail("expected ':' after object key")
		}
		p.pos++
		p.skipSpace()
		v, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		obj[k] = v
		p.skipSpace()
		if p.pos >= len(p.data) {
			return nil, p.fail("unterminated object")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return obj, nil
		default:
			return nil, p.fail("expected ',' or '}' in object")
		}
	}
}

func (p *parser) array(depth int) (any, error) {
	if depth > MaxDepth {
		return nil, p.fail("nesting too deep")
	}
	p.pos++ // '['
	arr := []any{}
	p.skipSpace()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		return arr, nil
	}
	for {
		p.skipSpace()
		v, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
		p.skipSpace()
		if p.pos >= len(p.data) {
			return nil, p.fail("unterminated array")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return arr, nil
		default:
			return nil, p.fail("expected ',' or ']' in array")
		}
	}
}

func (p *parser) number() (any, error) {
	start := p.pos
	if p.data[p.pos] == '-' {
		p.pos++
	}
	switch {
	case p.pos < len(p.data) && p.data[p.pos] == '0':
		p.pos++
	case p.pos < len(p.data) && p.data[p.pos] >= '1' && p.data[p.pos] <= '9':
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
	default:
		return nil, p.fail("invalid number")
	}
	if p.pos < len(p.data) {
		switch p.data[p.pos] {
		case '.', 'e', 'E':
			return nil, p.failCause(ErrNotInteger, "numbers must be integers (no fraction or exponent)")
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			return nil, p.fail("leading zero in number")
		}
	}
	n, err := strconv.ParseInt(string(p.data[start:p.pos]), 10, 64)
	if err != nil || n > MaxInt || n < -MaxInt {
		p.pos = start
		return nil, p.failCause(ErrIntRange, "integer outside ±2^53")
	}
	return n, nil
}

func (p *parser) string() (string, error) {
	p.pos++ // opening quote
	var out []byte
	for {
		if p.pos >= len(p.data) {
			return "", p.fail("unterminated string")
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			p.pos++
			return string(out), nil
		case c < 0x20:
			return "", p.fail("unescaped control character in string")
		case c != '\\':
			out = append(out, c)
			p.pos++
			continue
		}
		// Escape sequence.
		if p.pos+1 >= len(p.data) {
			return "", p.fail("unterminated escape")
		}
		e := p.data[p.pos+1]
		p.pos += 2
		switch e {
		case '"', '\\', '/':
			out = append(out, e)
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, err := p.unicodeEscape()
			if err != nil {
				return "", err
			}
			out = utf8.AppendRune(out, r)
		default:
			p.pos -= 2
			return "", p.fail(fmt.Sprintf("invalid escape \\%c", e))
		}
	}
}

// unicodeEscape reads the 4 hex digits after "\u" (and a low surrogate escape
// if the first was a high surrogate) and returns the code point.
func (p *parser) unicodeEscape() (rune, error) {
	r1, ok := p.hex4()
	if !ok {
		return 0, p.fail("invalid \\u escape")
	}
	if !utf16.IsSurrogate(r1) {
		return r1, nil
	}
	if r1 >= 0xDC00 || !p.hasPrefix(`\u`) {
		return 0, p.fail("unpaired UTF-16 surrogate in \\u escape")
	}
	p.pos += 2
	r2, ok := p.hex4()
	if !ok {
		return 0, p.fail("invalid \\u escape")
	}
	r := utf16.DecodeRune(r1, r2)
	if r == utf8.RuneError {
		return 0, p.fail("unpaired UTF-16 surrogate in \\u escape")
	}
	return r, nil
}

func (p *parser) hex4() (rune, bool) {
	if len(p.data)-p.pos < 4 {
		return 0, false
	}
	var r rune
	for _, c := range p.data[p.pos : p.pos+4] {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			r |= rune(c - 'A' + 10)
		default:
			return 0, false
		}
	}
	p.pos += 4
	return r, true
}
