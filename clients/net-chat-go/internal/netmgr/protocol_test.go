package netmgr

import (
	"reflect"
	"testing"
)

// Golden fixtures: every case here MUST round-trip against Perl's
// NetMgr::Protocol on the net-mgr side. When adding a case, verify
// with:
//
//	cd /usr/local/src/net-mgr
//	perl -Ilib -MNetMgr::Protocol -e 'use Data::Dumper; my $c = NetMgr::Protocol::parse_line(shift); print Dumper($c)' -- 'INPUT LINE'
//
// The Go behaviour is: same tokens, same escape decode, same map.
//
// TODO(codegen): a tiny helper script under scripts/gen_fixtures.pl that
// dumps a batch of (line -> {verb, kv, where}) triples as JSON would make
// this table maintain itself.

func TestQuote(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", `""`},
		{"hello", "hello"},                // no reserved chars
		{"a b", `"a b"`},                  // space forces quoting
		{`a"b`, `"a""b"`},                 // doubled quote
		{`a\b`, `"a\\b"`},                 // backslash escape
		{"line1\nline2", `"line1\nline2"`}, // newline
		{"has=eq", `"has=eq"`},            // equals forces quoting
		{"(paren)", `"(paren)"`},          // parens force quoting
	}
	for _, c := range cases {
		got := Quote(c.in)
		if got != c.want {
			t.Errorf("Quote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestUnquote(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`""`, ``},
		{`"hello"`, `hello`},
		{`"a b"`, `a b`},
		{`"a""b"`, `a"b`},
		{`"a\\b"`, `a\b`},
		{`"line1\nline2"`, "line1\nline2"},
		{`"line1\rline2"`, "line1\rline2"},
	}
	for _, c := range cases {
		got, next, err := Unquote(c.in, 0)
		if err != nil {
			t.Errorf("Unquote(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("Unquote(%q) = %q, want %q", c.in, got, c.want)
		}
		if next != len(c.in) {
			t.Errorf("Unquote(%q): next=%d, want %d", c.in, next, len(c.in))
		}
	}
}

func TestQuoteRoundTrip(t *testing.T) {
	// Any string must survive Quote -> Unquote back to itself.
	cases := []string{
		"", "hello", "a b c", `has"quotes`, `back\slash`,
		"tab\there", "cr\rand\nlf", "==", "()", `""`, `\\`,
	}
	for _, s := range cases {
		q := Quote(s)
		if q == s && !needsQuoting(s) {
			// Value passed through unquoted — nothing to unquote.
			continue
		}
		got, _, err := Unquote(q, 0)
		if err != nil {
			t.Errorf("round-trip Unquote(%q): %v", q, err)
			continue
		}
		if got != s {
			t.Errorf("round-trip %q -> %q -> %q", s, q, got)
		}
	}
}

func TestFormatKV(t *testing.T) {
	got := FormatKV(map[string]string{
		"b": "two",
		"a": "one",
		"c": "with space",
	})
	want := `a=one b=two c="with space"`
	if got != want {
		t.Errorf("FormatKV = %q, want %q", got, want)
	}
}

func TestFormatEmpty(t *testing.T) {
	if got := Format("BYE", nil); got != "BYE\n" {
		t.Errorf("Format bare verb = %q, want %q", got, "BYE\n")
	}
}

func TestParseVerbAndKV(t *testing.T) {
	c, err := Parse(`HELLO client=net-chat-go version=0.0.1`)
	if err != nil {
		t.Fatal(err)
	}
	if c.Verb != "HELLO" {
		t.Errorf("Verb = %q, want HELLO", c.Verb)
	}
	want := map[string]string{"client": "net-chat-go", "version": "0.0.1"}
	if !reflect.DeepEqual(c.KV, want) {
		t.Errorf("KV = %v, want %v", c.KV, want)
	}
}

func TestParseQuotedBody(t *testing.T) {
	c, err := Parse(`OBSERVE kind=chat_msg body="hello\nworld" session=General`)
	if err != nil {
		t.Fatal(err)
	}
	if c.KV["body"] != "hello\nworld" {
		t.Errorf("body decode: got %q, want %q", c.KV["body"], "hello\nworld")
	}
	if c.KV["session"] != "General" {
		t.Errorf("session: got %q, want General", c.KV["session"])
	}
}

func TestParseSubscribeWhere(t *testing.T) {
	c, err := Parse(`SUBSCRIBE table=chat_messages WHERE session='General'`)
	if err != nil {
		t.Fatal(err)
	}
	if c.Verb != "SUBSCRIBE" {
		t.Errorf("Verb = %q", c.Verb)
	}
	if c.KV["table"] != "chat_messages" {
		t.Errorf("table = %q", c.KV["table"])
	}
	if c.Where != `session='General'` {
		t.Errorf("Where = %q", c.Where)
	}
}

func TestParseComment(t *testing.T) {
	c, err := Parse(`# a comment`)
	if err != nil {
		t.Fatal(err)
	}
	if c != nil {
		t.Errorf("comment produced Command %+v, want nil", c)
	}
}

func TestFormatParseRoundTrip(t *testing.T) {
	// Bodies containing arbitrary characters — including newlines — must
	// survive Format -> Parse back to the same KV map. This is the case
	// the current Perl daemon has a bug on ("unterminated quoted string"
	// when the CLI passes a literal LF); the Go client encodes to \n so
	// the wire frame stays single-line.
	orig := map[string]string{
		"body":    "line1\nline2\nline3",
		"session": "General",
		"sender":  "dkc",
	}
	line := Format("OBSERVE", orig)
	c, err := Parse(line)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.KV, orig) {
		t.Errorf("round-trip:\n  in:  %v\n  out: %v", orig, c.KV)
	}
}
