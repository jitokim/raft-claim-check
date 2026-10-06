// Package redact implements the design's "## Redaction policy": the masks
// applied to output tails and argv before signing. Redaction is best-effort.
//
// The rule list below is versioned with the CLI: the cli.version recorded in
// a receipt identifies exactly which patterns were applied.
package redact

import (
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Rule names, as they appear in "[REDACTED:<rule>]".
const (
	RulePrivateKey          = "private_key"
	RuleBearer              = "bearer"
	RuleKnownToken          = "known_token"
	RuleJWT                 = "jwt"
	RuleURLUserinfo         = "url_userinfo"
	RuleSensitiveAssignment = "sensitive_assignment"
	RuleEnvValue            = "env_value"
	RuleSensitiveFlag       = "sensitive_flag"
	RuleRedactArg           = "redact_arg"
)

// Sizes from the design.
const (
	WindowBytes = 8 * 1024 // raw scan window kept per stream
	TailBytes   = 2048     // tail kept after redaction
	MinEnvValue = 8        // shortest environment value used for env_value
)

// sensitiveName is the design's NAME pattern.
const sensitiveName = `(?:pass(?:word)?|secret|token|api[_-]?key|private[_-]?key|credential|auth)`

var sensitiveNameRe = regexp.MustCompile(`(?i)` + sensitiveName)

// IsSensitiveName reports whether a variable or flag name matches the
// design's sensitive-name pattern.
func IsSensitiveName(name string) bool { return sensitiveNameRe.MatchString(name) }

// Marker returns the replacement text for rule.
func Marker(rule string) string { return "[REDACTED:" + rule + "]" }

type rule struct {
	name  string
	re    *regexp.Regexp
	group int // submatch to mask; 0 masks the whole match
	// skip, if set, drops a match (start and end of the whole match).
	skip func(s string, start, end int) bool
}

// nameChars are the characters allowed around the sensitive word in NAME.
const nameChars = `[A-Za-z0-9_.\-]*`

// baseRules are in priority order: when two matches overlap, they are merged
// into one mask named after the higher-priority rule.
var baseRules = []rule{
	// A whole PEM private-key block, through its footer or the end of the
	// text when the footer is not in the window.
	{RulePrivateKey, regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)`), 0, nil},
	// A footer whose header scrolled out of the window: mask from the start.
	{RulePrivateKey, regexp.MustCompile(`(?s)\A.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`), 0,
		func(s string, start, end int) bool { return strings.Contains(s[start:end], "-----BEGIN ") }},
	// Authorization header values, then "Bearer <token>" anywhere.
	{RuleBearer, regexp.MustCompile(`(?i)\bauthorization"?[ \t]*:[ \t]*"?([^"\r\n]+)`), 1, nil},
	{RuleBearer, regexp.MustCompile(`(?i)\bbearer[ \t]+([A-Za-z0-9\-._~+/]+=*)`), 1, nil},
	// Vendor tokens by documented fixed prefix.
	// GitHub: ghp_ (personal), gho_ (OAuth), ghu_ (user-to-server),
	// ghs_ (server-to-server), ghr_ (refresh), github_pat_ (fine-grained).
	{RuleKnownToken, regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,255}\b`), 0, nil},
	{RuleKnownToken, regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,255}\b`), 0, nil},
	// Slack: xoxb- (bot), xoxa-/xapp- (app), xoxp- (user), xoxr-/xoxe- (refresh).
	{RuleKnownToken, regexp.MustCompile(`\bxox(?:[abposr]|e(?:\.xox[bp])?)-[A-Za-z0-9\-]{10,}`), 0, nil},
	{RuleKnownToken, regexp.MustCompile(`\bxapp-[0-9]+-[A-Za-z0-9\-]{10,}`), 0, nil},
	// AWS access key IDs.
	{RuleKnownToken, regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16}\b`), 0, nil},
	// Anthropic (sk-ant-) and OpenAI-style (sk-, sk-proj-, sk-svcacct-, sk-admin-) keys.
	{RuleKnownToken, regexp.MustCompile(`\bsk-(?:ant-|proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}`), 0, nil},
	// npm access tokens.
	{RuleKnownToken, regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), 0, nil},
	// JWT: three base64url segments, the first starting with eyJ.
	{RuleJWT, regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+`), 0, nil},
	// user:password@ in a scheme:// URL.
	{RuleURLUserinfo, regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9+.\-]*://([^/\s:@]*:[^/\s@]*@)`), 1, nil},
	// "NAME": "value", then NAME=value and NAME: value.
	{RuleSensitiveAssignment, regexp.MustCompile(`(?i)"` + nameChars + sensitiveName + nameChars + `"[ \t]*:[ \t]*"((?:[^"\\\n]|\\.)+)"`), 1, nil},
	{RuleSensitiveAssignment, regexp.MustCompile(`(?i)\b` + nameChars + sensitiveName + nameChars + `(?:=|:[ \t]*)("[^"\n]*"|'[^'\n]*'|[^\s"',;&]+)`), 1, nil},
}

// Redactor applies the rules. Build one per process with New.
type Redactor struct {
	rules []rule
}

// New builds a Redactor. environ is the process environment as KEY=VALUE
// strings; values of sensitive-named variables of 8 or more bytes are
// matched exactly (env_value). They are held only in memory.
func New(environ []string) *Redactor {
	rules := slices.Clone(baseRules)
	var values []string
	for _, kv := range environ {
		name, value, ok := strings.Cut(kv, "=")
		if ok && len(value) >= MinEnvValue && IsSensitiveName(name) {
			values = append(values, value)
		}
	}
	if len(values) > 0 {
		sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
		quoted := make([]string, len(values))
		for i, v := range values {
			quoted[i] = regexp.QuoteMeta(v)
		}
		rules = append(rules, rule{RuleEnvValue, regexp.MustCompile(strings.Join(quoted, "|")), 0, nil})
	}
	return &Redactor{rules: rules}
}

type span struct {
	start, end int
	rule       string
}

// spans finds every match of every rule and merges overlapping ones. A merged
// span keeps the name of its highest-priority rule.
func (r *Redactor) spans(s string) []span {
	var accepted []span
	for _, ru := range r.rules {
		for _, m := range ru.re.FindAllStringSubmatchIndex(s, -1) {
			start, end := m[2*ru.group], m[2*ru.group+1]
			if start < 0 || start == end || ru.skip != nil && ru.skip(s, m[0], m[1]) {
				continue
			}
			accepted = merge(accepted, span{start, end, ru.name})
		}
	}
	sort.Slice(accepted, func(i, j int) bool { return accepted[i].start < accepted[j].start })
	return accepted
}

// merge adds n to spans (which never overlap each other). Spans that n
// overlaps are folded into one, named after the earliest-accepted of them.
func merge(spans []span, n span) []span {
	out := spans[:0:0]
	name := ""
	for _, s := range spans {
		if s.start < n.end && n.start < s.end {
			n.start, n.end = min(n.start, s.start), max(n.end, s.end)
			if name == "" {
				name = s.rule
			}
			continue
		}
		out = append(out, s)
	}
	if name != "" {
		n.rule = name
	}
	return append(out, n)
}

// Result is redacted text and where each mask landed in it.
type Result struct {
	Text  string
	Marks [][2]int // [start, end) byte offsets of each marker in Text
}

// Redact masks s.
func (r *Redactor) Redact(s string) Result {
	var b strings.Builder
	var marks [][2]int
	last := 0
	for _, sp := range r.spans(s) {
		b.WriteString(s[last:sp.start])
		start := b.Len()
		b.WriteString(Marker(sp.rule))
		marks = append(marks, [2]int{start, b.Len()})
		last = sp.end
	}
	b.WriteString(s[last:])
	return Result{Text: b.String(), Marks: marks}
}

// Text masks s and returns the result and the number of masks.
func (r *Redactor) Text(s string) (string, int) {
	res := r.Redact(s)
	return res.Text, len(res.Marks)
}

var ansi = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[PX^_][^\x1b]*(?:\x1b\\)?|\x1b[ -/]*[0-~]`)

// Clean decodes raw as UTF-8 (each invalid byte becomes U+FFFD), strips ANSI
// escape sequences, and drops control characters other than \n and \t.
func Clean(raw []byte) string {
	var b strings.Builder
	b.Grow(len(raw))
	for len(raw) > 0 {
		r, size := utf8.DecodeRune(raw)
		b.WriteRune(r) // RuneError for an invalid byte is U+FFFD
		raw = raw[size:]
	}
	s := ansi.ReplaceAllString(b.String(), "")
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
			return -1
		}
		return r
	}, s)
}

// Tail turns a stream's scan window (its last bytes, at most WindowBytes)
// into the recorded tail. droppedFront says whether the stream had bytes
// before the window. It returns the tail (at most TailBytes, cut at a
// character boundary and never inside a marker), whether anything was
// dropped from the front, and the number of masks inside the tail.
func (r *Redactor) Tail(window []byte, droppedFront bool) (tail string, truncated bool, redactions int) {
	if droppedFront {
		// Skip a character split by the window's start.
		for i := 0; i < utf8.UTFMax-1 && len(window) > 0 && !utf8.RuneStart(window[0]); i++ {
			window = window[1:]
		}
	}
	res := r.Redact(Clean(window))
	cut := 0
	if len(res.Text) > TailBytes {
		cut = len(res.Text) - TailBytes
		for cut < len(res.Text) && !utf8.RuneStart(res.Text[cut]) {
			cut++
		}
	}
	for _, m := range res.Marks {
		if m[0] < cut && cut < m[1] {
			cut = m[1]
		}
	}
	for _, m := range res.Marks {
		if m[0] >= cut {
			redactions++
		}
	}
	return res.Text[cut:], droppedFront || cut > 0, redactions
}

var (
	flagWithValue = regexp.MustCompile(`^(-{1,2}[A-Za-z0-9][^=\s]*)=(.*)$`)
	flagAlone     = regexp.MustCompile(`^-{1,2}[A-Za-z0-9][A-Za-z0-9_.\-]*$`)
)

// Argv masks the child's argv. redactIdx are the --redact-arg indexes into
// argv (counting from 0), masked in full. A flag whose name is sensitive has
// its value masked in --name=value form and the next element masked in
// --name value form. Every element also gets the text rules. The count is
// the number of elements that were masked.
func (r *Redactor) Argv(argv []string, redactIdx []int) ([]string, int) {
	out := make([]string, len(argv))
	count := 0
	maskNext := false
	for i, a := range argv {
		masked := true
		switch {
		case slices.Contains(redactIdx, i):
			out[i] = Marker(RuleRedactArg)
		case maskNext:
			out[i] = Marker(RuleSensitiveFlag)
		default:
			if m := flagWithValue.FindStringSubmatch(a); m != nil && m[2] != "" && IsSensitiveName(m[1]) {
				out[i] = m[1] + "=" + Marker(RuleSensitiveFlag)
				break
			}
			var n int
			out[i], n = r.Text(a)
			masked = n > 0
		}
		maskNext = flagAlone.MatchString(a) && IsSensitiveName(a)
		if masked {
			count++
		}
	}
	return out, count
}

// ParseIndex parses a --redact-arg value.
func ParseIndex(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, strconv.ErrSyntax
	}
	return n, nil
}
