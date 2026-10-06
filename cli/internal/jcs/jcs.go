// Package jcs implements the RFC 8785 JSON Canonicalization Scheme for the
// integer-only JSON that Claim Check signs, plus a strict parser.
//
// A JSON value is represented by these Go types only:
//
//	null    -> nil
//	boolean -> bool
//	number  -> int64 (an integer within ±MaxInt)
//	string  -> string (valid UTF-8)
//	array   -> []any
//	object  -> map[string]any
//
// Parse produces exactly these types, and Encode accepts them (plus int for
// convenience). Floats are refused everywhere: the design allows no
// floating-point numbers in a signed payload.
package jcs

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxInt is the largest magnitude of an integer that Parse and Encode accept:
// 2^53. The design says every number is an integer within ±2^53, and the
// bounds are inclusive.
const MaxInt int64 = 1 << 53

// ErrUnsupported is returned by Encode for a value outside the JSON model
// above, such as a float or an integer outside ±MaxInt.
var ErrUnsupported = errors.New("jcs: unsupported value")

// Encode returns the RFC 8785 canonical serialization of v.
func Encode(v any) ([]byte, error) {
	var buf []byte
	return appendValue(buf, v)
}

// Canonicalize parses data strictly and returns its canonical serialization.
func Canonicalize(data []byte) ([]byte, error) {
	v, err := Parse(data)
	if err != nil {
		return nil, err
	}
	return Encode(v)
}

// Marshal converts a Go value (typically a struct with json tags) to JSON with
// encoding/json, re-parses it strictly, and returns the canonical bytes. The
// strict re-parse means a value that would not survive verification (for
// example an integer beyond ±MaxInt) is refused before anything is signed.
func Marshal(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Canonicalize(raw)
}

func appendValue(buf []byte, v any) ([]byte, error) {
	switch x := v.(type) {
	case nil:
		return append(buf, "null"...), nil
	case bool:
		if x {
			return append(buf, "true"...), nil
		}
		return append(buf, "false"...), nil
	case int64:
		return appendInt(buf, x)
	case int:
		return appendInt(buf, int64(x))
	case string:
		return appendString(buf, x)
	case []any:
		buf = append(buf, '[')
		for i, e := range x {
			if i > 0 {
				buf = append(buf, ',')
			}
			var err error
			if buf, err = appendValue(buf, e); err != nil {
				return nil, err
			}
		}
		return append(buf, ']'), nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		buf = append(buf, '{')
		for i, k := range keys {
			if i > 0 {
				buf = append(buf, ',')
			}
			var err error
			if buf, err = appendString(buf, k); err != nil {
				return nil, err
			}
			buf = append(buf, ':')
			if buf, err = appendValue(buf, x[k]); err != nil {
				return nil, err
			}
		}
		return append(buf, '}'), nil
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupported, v)
	}
}

func appendInt(buf []byte, n int64) ([]byte, error) {
	if n > MaxInt || n < -MaxInt {
		return nil, fmt.Errorf("%w: integer %d outside ±2^53", ErrUnsupported, n)
	}
	return strconv.AppendInt(buf, n, 10), nil
}

// appendString writes s as RFC 8785 requires: the two-character escapes for
// \b \f \n \r \t \" \\, \u00XX (lowercase hex) for the other C0 controls, and
// every other character literally as UTF-8. No HTML escaping.
func appendString(buf []byte, s string) ([]byte, error) {
	if !utf8.ValidString(s) {
		return nil, fmt.Errorf("%w: string is not valid UTF-8", ErrUnsupported)
	}
	const hex = "0123456789abcdef"
	buf = append(buf, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\b':
			buf = append(buf, '\\', 'b')
		case '\f':
			buf = append(buf, '\\', 'f')
		case '\n':
			buf = append(buf, '\\', 'n')
		case '\r':
			buf = append(buf, '\\', 'r')
		case '\t':
			buf = append(buf, '\\', 't')
		case '"':
			buf = append(buf, '\\', '"')
		case '\\':
			buf = append(buf, '\\', '\\')
		default:
			if c < 0x20 {
				buf = append(buf, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
			} else {
				buf = append(buf, c)
			}
		}
	}
	return append(buf, '"'), nil
}

// lessUTF16 orders strings by their UTF-16 code units, as RFC 8785 section
// 3.2.3 requires. This differs from byte and code-point order for characters
// above U+FFFF, whose surrogates (D800-DFFF) sort before U+E000-U+FFFF.
func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}
