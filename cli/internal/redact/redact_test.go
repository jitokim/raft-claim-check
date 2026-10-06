package redact

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Fake secrets assembled at runtime so no literal token sits in the source.
var (
	ghp    = "ghp_" + strings.Repeat("a1B2", 9)
	ghFine = "github_pat_" + strings.Repeat("Ab3_", 8)
	slack  = "xoxb-" + "123456789012-abcdefABCDEF"
	aws    = "AKIA" + "ABCDEFGHIJKLMNOP"
	openai = "sk-proj-" + strings.Repeat("x9Y8", 6)
	anth   = "sk-ant-" + strings.Repeat("q7W6", 6)
	npm    = "npm_" + strings.Repeat("Zz09", 9)
	jwt    = "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxIn0" + "." + "c2lnbmF0dXJl"
)

// pem assembles a PEM private-key armor line at runtime, e.g. pem("BEGIN", "RSA");
// an empty kind yields the bare form with no kind word.
func pem(edge, kind string) string {
	if kind != "" {
		kind += " "
	}
	return "-----" + edge + " " + kind + "PRIVATE" + " KEY-----"
}

func TestEachRule(t *testing.T) {
	r := New([]string{"MY_API_TOKEN=s3cr3t-env-value", "SHORT_TOKEN=abc", "PATH=/usr/bin:/bin"})
	cases := []struct {
		name, in, want string
	}{
		{"private_key", "a\n" + pem("BEGIN", "RSA") + "\nMIIBOgIBAAJB\n" + pem("END", "RSA") + "\nb",
			"a\n[REDACTED:private_key]\nb"},
		{"private_key without footer", "x\n" + pem("BEGIN", "OPENSSH") + "\nb3BlbnNzaC1rZXk\nAAAA",
			"x\n[REDACTED:private_key]"},
		{"private_key footer only", "zzzz\nyyyy\n" + pem("END", "") + "\nafter", "[REDACTED:private_key]\nafter"},
		{"bearer header", "Authorization: Basic dXNlcjpwYXNz\nnext", "Authorization: [REDACTED:bearer]\nnext"},
		{"bearer token", "curl -H 'X: Bearer abc.def-123'", "curl -H 'X: Bearer [REDACTED:bearer]'"},
		{"known_token github", "token " + ghp + " end", "token [REDACTED:known_token] end"},
		{"known_token github fine-grained", ghFine, "[REDACTED:known_token]"},
		{"known_token slack", "s=" + slack, "s=[REDACTED:known_token]"},
		{"known_token aws", "id " + aws + ".", "id [REDACTED:known_token]."},
		{"known_token openai", "k " + openai, "k [REDACTED:known_token]"},
		{"known_token anthropic", "k " + anth, "k [REDACTED:known_token]"},
		{"known_token npm", "k " + npm, "k [REDACTED:known_token]"},
		{"jwt", "t " + jwt + " x", "t [REDACTED:jwt] x"},
		{"url_userinfo", "clone https://bob:hunter2@example.com/r.git", "clone https://[REDACTED:url_userinfo]example.com/r.git"},
		{"sensitive_assignment eq", "DB_PASSWORD=hunter2 next", "DB_PASSWORD=[REDACTED:sensitive_assignment] next"},
		{"sensitive_assignment colon", "client_secret: abc123", "client_secret: [REDACTED:sensitive_assignment]"},
		{"sensitive_assignment json", `{"apiKey": "abc123", "user": "u"}`, `{"apiKey": "[REDACTED:sensitive_assignment]", "user": "u"}`},
		{"env_value", "printed s3cr3t-env-value here", "printed [REDACTED:env_value] here"},
		{"short env value untouched", "abc", "abc"},
		{"plain text untouched", "ok  \texample.com/x\t1.2s\n", "ok  \texample.com/x\t1.2s\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, n := r.Text(c.in)
			if got != c.want {
				t.Fatalf("Text(%q)\n got %q\nwant %q", c.in, got, c.want)
			}
			if want := strings.Count(c.want, "[REDACTED:"); n != want {
				t.Fatalf("count = %d, want %d", n, want)
			}
		})
	}
}

func TestOverlappingMatchesMergeIntoOne(t *testing.T) {
	r := New(nil)
	got, n := r.Text("GITHUB_TOKEN=" + ghp)
	if n != 1 || strings.Contains(got, "ghp_") {
		t.Fatalf("got %q (%d masks)", got, n)
	}
	got, n = r.Text("Authorization: Bearer " + ghp)
	if got != "Authorization: [REDACTED:bearer]" || n != 1 {
		t.Fatalf("got %q (%d masks)", got, n)
	}
}

func TestCleanStripsANSIAndControls(t *testing.T) {
	in := []byte("\x1b[31mred\x1b[0m\r\nbell\x07 \x1b]0;title\x07tab\tok\xff\n")
	want := "red\nbell tab\tok�\n"
	if got := Clean(in); got != want {
		t.Fatalf("Clean = %q, want %q", got, want)
	}
}

func TestTailCapAndTruncation(t *testing.T) {
	r := New(nil)
	short, trunc, n := r.Tail([]byte("hello\n"), false)
	if short != "hello\n" || trunc || n != 0 {
		t.Fatalf("short tail = %q %v %d", short, trunc, n)
	}
	big := []byte(strings.Repeat("é", 3000)) // 6000 bytes
	tail, trunc, _ := r.Tail(big, false)
	if len(tail) > TailBytes || !trunc || !utf8.ValidString(tail) {
		t.Fatalf("len %d trunc %v valid %v", len(tail), trunc, utf8.ValidString(tail))
	}
	// A window that starts inside a character, after dropped bytes.
	tail, trunc, _ = r.Tail([]byte("\xa9abc"), true)
	if tail != "abc" || !trunc {
		t.Fatalf("tail = %q trunc %v", tail, trunc)
	}
}

func TestTailMasksSecretStraddlingTailStart(t *testing.T) {
	r := New(nil)
	// The token starts before the last 2048 bytes and ends inside them.
	window := "x\n" + ghp + "\n" + strings.Repeat("y", TailBytes-10)
	tail, trunc, n := r.Tail([]byte(window), false)
	if strings.Contains(tail, ghp[len(ghp)-6:]) || strings.Contains(tail, "REDACTED") || tail[0] != '\n' {
		t.Fatalf("secret or partial marker leaked: %q", tail[:40])
	}
	if !trunc || n != 0 || len(tail) > TailBytes {
		t.Fatalf("trunc %v n %d len %d", trunc, n, len(tail))
	}
	// A marker fully inside the tail is counted.
	tail, _, n = r.Tail([]byte(strings.Repeat("z", 5000)+" "+ghp+" end"), true)
	if n != 1 || !strings.HasSuffix(tail, "[REDACTED:known_token] end") {
		t.Fatalf("n %d tail suffix %q", n, tail[len(tail)-40:])
	}
}

func TestArgv(t *testing.T) {
	r := New([]string{"SERVICE_PASSWORD=env-only-secret"})
	cases := []struct {
		name   string
		in     []string
		idx    []int
		want   []string
		masked int
	}{
		{"--name=value", []string{"go", "test", "./...", "-token=abc"}, nil,
			[]string{"go", "test", "./...", "-token=[REDACTED:sensitive_flag]"}, 1},
		{"--name value", []string{"tool", "--api-key", "abc", "--verbose"}, nil,
			[]string{"tool", "--api-key", "[REDACTED:sensitive_flag]", "--verbose"}, 1},
		{"--redact-arg", []string{"tool", "pos-secret", "keep"}, []int{1},
			[]string{"tool", "[REDACTED:redact_arg]", "keep"}, 1},
		{"text rules per element", []string{"curl", "https://u:p@host/x", "-H", "Authorization: Bearer abc"}, nil,
			[]string{"curl", "https://[REDACTED:url_userinfo]host/x", "-H", "Authorization: [REDACTED:bearer]"}, 2},
		{"env value", []string{"echo", "env-only-secret"}, nil, []string{"echo", "[REDACTED:env_value]"}, 1},
		{"flag at end", []string{"tool", "--password"}, nil, []string{"tool", "--password"}, 0},
		{"non-sensitive flag", []string{"go", "test", "-run", "TestX"}, nil, []string{"go", "test", "-run", "TestX"}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, n := r.Argv(c.in, c.idx)
			if strings.Join(got, "\x00") != strings.Join(c.want, "\x00") || n != c.masked {
				t.Fatalf("Argv(%q) = %q, %d; want %q, %d", c.in, got, n, c.want, c.masked)
			}
		})
	}
}

func TestMaskHome(t *testing.T) {
	cases := []struct {
		name, in, home, want string
	}{
		{"path under home", "/Users/bob/x", "/Users/bob", "~/x"},
		{"home alone", "/Users/bob", "/Users/bob", "~"},
		{"longer segment", "/Users/bobby/x", "/Users/bob", "/Users/bobby/x"},
		{"dot suffix", "/Users/bob.old", "/Users/bob", "/Users/bob.old"},
		{"dash and underscore suffix", "/Users/bob-2 /Users/bob_x", "/Users/bob", "/Users/bob-2 /Users/bob_x"},
		{"non-ASCII suffix", "/Users/bobé/x", "/Users/bob", "/Users/bobé/x"},
		{"semicolon", "cd /Users/bob; ls", "/Users/bob", "cd ~; ls"},
		{"file url", "file:///Users/bob/x.git", "/Users/bob", "file://~/x.git"},
		{"trailing-slash home", "/Users/bob/x and /Users/bob", "/Users/bob/", "~/x and ~"},
		{"trailing-slash home boundary", "/Users/bobby/x", "/Users/bob/", "/Users/bobby/x"},
		{"several occurrences", "a=/Users/bob:/Users/bob/bin,'/Users/bob'\t\"/Users/bob\"\n(/Users/bob)",
			"/Users/bob", "a=~:~/bin,'~'\t\"~\"\n(~)"},
		{"masked after a skipped one", "/Users/bobby /Users/bob", "/Users/bob", "/Users/bobby ~"},
		{"other boundaries", "[/Users/bob]{/Users/bob}</Users/bob>|/Users/bob&`/Users/bob`", "/Users/bob",
			"[~]{~}<~>|~&`~`"},
		{"empty home", "/Users/bob/x", "", "/Users/bob/x"},
		{"root home", "/Users/bob/x", "/", "/Users/bob/x"},
		{"no occurrence", "nothing here", "/Users/bob", "nothing here"},
		{"inside a longer path", "/mnt/Users/bob/x", "/Users/bob", "/mnt/Users/bob/x"},
		{"inside a longer path at the end", "/Volumes/b/Users/bob", "/Users/bob", "/Volumes/b/Users/bob"},
		{"after file url slashes", "file:///Users/bob/r.git", "/Users/bob", "file://~/r.git"},
		{"after equals", "x=/Users/bob/y", "/Users/bob", "x=~/y"},
		{"after a space", "cd /Users/bob/x", "/Users/bob", "cd ~/x"},
		{"at the start", "/Users/bob", "/Users/bob", "~"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := MaskHome(c.in, c.home); got != c.want {
				t.Fatalf("MaskHome(%q, %q)\n got %q\nwant %q", c.in, c.home, got, c.want)
			}
		})
	}
}

func TestWithHomeLeavesOriginalUnchanged(t *testing.T) {
	r := New(nil)
	_ = r.WithHome("/Users/bob")
	if tail, _, n := r.Tail([]byte("/Users/bob/x"), false); tail != "/Users/bob/x" || n != 0 {
		t.Fatalf("tail %q n %d", tail, n)
	}
}

func TestTailMasksHome(t *testing.T) {
	r := New(nil).WithHome("/Users/bob/")
	tail, trunc, n := r.Tail([]byte("open /Users/bob/a\n\x1b[1m/Users/bob\x1b[0m /Users/bobby\n"), false)
	if tail != "open ~/a\n~ /Users/bobby\n" || trunc || n != 2 {
		t.Fatalf("tail %q trunc %v n %d", tail, trunc, n)
	}
	// Home masks and rule masks are both counted.
	tail, _, n = r.Tail([]byte("/Users/bob/k "+ghp+" /Users/bob"), false)
	if tail != "~/k [REDACTED:known_token] ~" || n != 3 {
		t.Fatalf("tail %q n %d", tail, n)
	}
	// A home mask inside a rule mask is not counted on its own.
	tail, _, n = r.Tail([]byte("DB_PASSWORD=/Users/bob/pw end"), false)
	if tail != "DB_PASSWORD=[REDACTED:sensitive_assignment] end" || n != 1 {
		t.Fatalf("tail %q n %d", tail, n)
	}
	// No home: unchanged behaviour.
	tail, _, n = New(nil).Tail([]byte("/Users/bob/a"), false)
	if tail != "/Users/bob/a" || n != 0 {
		t.Fatalf("tail %q n %d", tail, n)
	}
}

func TestTailMasksHomeBeforeCap(t *testing.T) {
	r := New(nil).WithHome("/Users/bob")
	// Unmasked, the window is 2 bytes over the cap and the cut would fall
	// inside the home path; masked, it fits whole.
	pad := strings.Repeat("y", TailBytes-len("/Users/bob/x")+2)
	window := "/Users/bob/x" + pad
	tail, trunc, n := r.Tail([]byte(window), false)
	if tail != "~/x"+pad || trunc || n != 1 {
		t.Fatalf("tail prefix %q trunc %v n %d len %d", tail[:10], trunc, n, len(tail))
	}
	// A home mask cut off by the cap is not counted; the kept one is.
	window = "/Users/bob/old\n" + strings.Repeat("z", TailBytes) + " /Users/bob"
	tail, trunc, n = r.Tail([]byte(window), false)
	if !strings.HasSuffix(tail, "z ~") || strings.Contains(tail, "old") || !trunc || n != 1 || len(tail) != TailBytes {
		t.Fatalf("tail suffix %q trunc %v n %d len %d", tail[len(tail)-10:], trunc, n, len(tail))
	}
}

func TestArgvMasksHome(t *testing.T) {
	r := New([]string{"SERVICE_PASSWORD=env-only-secret"}).WithHome("/Users/bob")
	cases := []struct {
		name   string
		in     []string
		idx    []int
		want   []string
		masked int
	}{
		{"home paths", []string{"/Users/bob/bin/tool", "--out=/Users/bob/o", "/Users/bobby/x"}, nil,
			[]string{"~/bin/tool", "--out=~/o", "/Users/bobby/x"}, 2},
		{"home and rule in one element counted once", []string{"cp", "/Users/bob/env-only-secret"}, nil,
			[]string{"cp", "~/[REDACTED:env_value]"}, 1},
		{"sensitive flag with home value", []string{"tool", "--token=/Users/bob/t"}, nil,
			[]string{"tool", "--token=[REDACTED:sensitive_flag]"}, 1},
		{"redact-arg wins", []string{"tool", "/Users/bob/s"}, []int{1},
			[]string{"tool", "[REDACTED:redact_arg]"}, 1},
		{"nothing to mask", []string{"go", "test", "./..."}, nil, []string{"go", "test", "./..."}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, n := r.Argv(c.in, c.idx)
			if strings.Join(got, "\x00") != strings.Join(c.want, "\x00") || n != c.masked {
				t.Fatalf("Argv(%q) = %q, %d; want %q, %d", c.in, got, n, c.want, c.masked)
			}
		})
	}
}
