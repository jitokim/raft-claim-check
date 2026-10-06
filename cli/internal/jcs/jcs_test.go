package jcs

import (
	"errors"
	"strings"
	"testing"
)

func canon(t *testing.T, in string) string {
	t.Helper()
	out, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatalf("Canonicalize(%q): %v", in, err)
	}
	return string(out)
}

func TestNonASCIIKeyOrdering(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`{"é":1,"z":2}`, `{"z":2,"é":1}`},
		// U+FFFD (FFFD) vs U+10000 (D800 DC00): UTF-16 puts U+10000 first,
		// although byte and code-point order would put U+FFFD first.
		{"{\"�\":1,\"\U00010000\":2}", "{\"\U00010000\":2,\"�\":1}"},
		// U+E000 vs U+1F600 (D83D DE00): the emoji sorts first in UTF-16.
		{"{\"\":1,\"\U0001F600\":2}", "{\"\U0001F600\":2,\"\":1}"},
		// A prefix sorts before a longer key.
		{`{"ab":1,"a":2}`, `{"a":2,"ab":1}`},
	} {
		if got := canon(t, tc.in); got != tc.want {
			t.Errorf("Canonicalize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestEncodeStrings(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"\b\f\n\r\t\"\\", `"\b\f\n\r\t\"\\"`},
		{"\x00\x01\x1f", `"\u0000\u0001\u001f"`},
		{"\x7f/<>& é😀", "\"\x7f/<>& é😀\""},
	} {
		got, err := Encode(tc.in)
		if err != nil || string(got) != tc.want {
			t.Errorf("Encode(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	if _, err := Encode("\xff"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Encode(invalid UTF-8) error = %v, want ErrUnsupported", err)
	}
}

func TestEncodeRejectsFloatsAndRange(t *testing.T) {
	for _, v := range []any{1.5, float32(1), MaxInt + 1, -MaxInt - 1, map[string]any{"a": []any{2.0}}, struct{}{}} {
		if _, err := Encode(v); !errors.Is(err, ErrUnsupported) {
			t.Errorf("Encode(%#v) error = %v, want ErrUnsupported", v, err)
		}
	}
	for _, v := range []any{MaxInt, -MaxInt, int64(0), 7} {
		if _, err := Encode(v); err != nil {
			t.Errorf("Encode(%#v): %v", v, err)
		}
	}
}

func TestParseRejectsDuplicateKeys(t *testing.T) {
	for _, in := range []string{
		`{"a":1,"a":2}`,
		`{"a":1,"b":2,"a":1}`,
		`{"a":"x","a":"y"}`, // equal after unescaping
		`{"outer":{"k":1,"k":1}}`,
		`[{"ok":1},{"x":[{"d":1,"d":2}]}]`,
	} {
		_, err := Parse([]byte(in))
		if !errors.Is(err, ErrDuplicateKey) {
			t.Errorf("Parse(%s) error = %v, want ErrDuplicateKey", in, err)
		}
		var se *SyntaxError
		if !errors.As(err, &se) {
			t.Errorf("Parse(%s) error is not a *SyntaxError", in)
		}
	}
}

func TestParseRejectsNonIntegers(t *testing.T) {
	for _, in := range []string{`1.5`, `1.0`, `1e3`, `1E3`, `-0.0`, `[0.1]`, `{"a":2e-1}`} {
		if _, err := Parse([]byte(in)); !errors.Is(err, ErrNotInteger) {
			t.Errorf("Parse(%s) error = %v, want ErrNotInteger", in, err)
		}
	}
}

func TestParseIntegerRange(t *testing.T) {
	for _, in := range []string{`9007199254740993`, `-9007199254740993`, `99999999999999999999999`} {
		if _, err := Parse([]byte(in)); !errors.Is(err, ErrIntRange) {
			t.Errorf("Parse(%s) error = %v, want ErrIntRange", in, err)
		}
	}
	for in, want := range map[string]int64{`9007199254740992`: MaxInt, `-9007199254740992`: -MaxInt, `-0`: 0} {
		v, err := Parse([]byte(in))
		if err != nil || v != want {
			t.Errorf("Parse(%s) = %v, %v; want %d", in, v, err, want)
		}
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	for name, in := range map[string]string{
		"invalid UTF-8 in string": "\"\xff\"",
		"invalid UTF-8 in key":    "{\"\xc3\x28\":1}",
		"trailing data":           `{"a":1} {}`,
		"trailing comma":          `[1,]`,
		"two values":              `1 2`,
		"BOM":                     "\xef\xbb\xbf{}",
		"leading zero":            `012`,
		"plus sign":               `+1`,
		"lone high surrogate":     `"\ud800"`,
		"lone low surrogate":      `"\udc00"`,
		"high then non-low":       `"\ud800A"`,
		"raw control char":        "\"a\x01b\"",
		"bad escape":              `"\x41"`,
		"single quotes":           `{'a':1}`,
		"unquoted key":            `{a:1}`,
		"empty input":             ``,
		"NaN":                     `NaN`,
		"unterminated":            `{"a":[1`,
		"too deep":                strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1),
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: Parse(%q) succeeded, want an error", name, in)
		}
	}
	ok := strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth)
	if _, err := Parse([]byte(ok)); err != nil {
		t.Errorf("depth %d should parse: %v", MaxDepth, err)
	}
}

func TestMarshalStruct(t *testing.T) {
	type inner struct {
		Z string `json:"z"`
		A *int64 `json:"a"`
	}
	type outer struct {
		Tail  string  `json:"tail"`
		Inner inner   `json:"inner"`
		List  []int64 `json:"list"`
	}
	got, err := Marshal(outer{Tail: "<b>&</b>", Inner: inner{Z: "é"}, List: []int64{3, 1}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"inner":{"a":null,"z":"é"},"list":[3,1],"tail":"<b>&</b>"}`
	if string(got) != want {
		t.Errorf("Marshal = %s, want %s", got, want)
	}
	if _, err := Marshal(struct {
		F float64 `json:"f"`
	}{1.5}); !errors.Is(err, ErrNotInteger) {
		t.Errorf("Marshal(float) error = %v, want ErrNotInteger", err)
	}
	if _, err := Marshal(struct {
		N int64 `json:"n"`
	}{MaxInt + 1}); !errors.Is(err, ErrIntRange) {
		t.Errorf("Marshal(2^53+1) error = %v, want ErrIntRange", err)
	}
}
