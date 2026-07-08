// Package netmgr — Go port of net-mgr's line-based wire protocol.
// Straight translation of Perl NetMgr::Protocol (lib/NetMgr/Protocol.pm)
// in the kev-cam/net-mgr repo. Frame is one command per LF-terminated line:
//
//	VERB k1=v1 k2="quoted value"
//
// Values are quoted when they contain any of the reserved characters
// (space, tab, ", =, (, ), \). Escapes inside quoted values: \\, \r, \n,
// and a doubled "" for a literal ". An empty value is written as "".
//
// This file is the CANONICAL Go implementation. Golden fixtures in
// protocol_test.go must round-trip against the Perl side bit-for-bit.
package netmgr

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// Command is a parsed line from the wire.
type Command struct {
	Verb string            // uppercased
	KV   map[string]string // key/value pairs after the verb

	// Verb-specific extras. Populated only when Verb is one of the
	// special-cased verbs; otherwise nil/empty.
	Where string   // SUBSCRIBE ... WHERE <clause>
	Args  []string // positional trailing args (e.g. TRIGGER <name>)
}

// Quote encodes a single value for the wire. Mirrors Perl
// _quote_if_needed: an empty value becomes "", a value containing any
// reserved char is quoted with the \\, \r, \n, "" escape scheme.
func Quote(v string) string {
	if v == "" {
		return `""`
	}
	if !needsQuoting(v) {
		return v
	}
	var b strings.Builder
	b.Grow(len(v) + 2)
	b.WriteByte('"')
	for _, r := range v {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '\r':
			b.WriteString(`\r`)
		case '\n':
			b.WriteString(`\n`)
		case '"':
			b.WriteString(`""`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func needsQuoting(v string) bool {
	for _, r := range v {
		if r == '"' || r == '=' || r == '(' || r == ')' || r == '\\' {
			return true
		}
		if unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

// Unquote reads a quoted value starting at s[i]. Returns the decoded
// value and the index of the first byte AFTER the closing quote.
// Mirrors Perl _read_quoted: doubled "" -> literal ", and \\, \r, \n
// escapes decode. Any other backslash sequence passes through literally
// (matches the Perl behavior — unknown escapes aren't errors, they just
// aren't decoded).
func Unquote(s string, i int) (string, int, error) {
	if i >= len(s) || s[i] != '"' {
		return "", i, fmt.Errorf(`expected '"' at offset %d`, i)
	}
	i++
	var b strings.Builder
	for i < len(s) {
		c := s[i]
		if c == '"' {
			if i+1 < len(s) && s[i+1] == '"' {
				b.WriteByte('"')
				i += 2
				continue
			}
			return b.String(), i + 1, nil
		}
		if c == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n':
				b.WriteByte('\n')
				i += 2
				continue
			case 'r':
				b.WriteByte('\r')
				i += 2
				continue
			case '\\':
				b.WriteByte('\\')
				i += 2
				continue
			}
		}
		b.WriteByte(c)
		i++
	}
	return "", i, errors.New("unterminated quoted string")
}

// FormatKV renders a key/value map as a wire-formatted string with
// keys in sorted order (matches the Perl format_kv). Empty map -> "".
func FormatKV(kv map[string]string) string {
	if len(kv) == 0 {
		return ""
	}
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(Quote(kv[k]))
	}
	return b.String()
}

// Format assembles a full wire line: "VERB k1=v1 k2=v2\n". The trailing
// newline is included so callers can write directly to a bufio.Writer.
func Format(verb string, kv map[string]string) string {
	tail := FormatKV(kv)
	if tail == "" {
		return strings.ToUpper(verb) + "\n"
	}
	return strings.ToUpper(verb) + " " + tail + "\n"
}

// Parse decodes a single line (with or without the trailing LF) into a
// Command. Comments (leading '#') and empty lines return (nil, nil).
func Parse(line string) (*Command, error) {
	line = strings.TrimRight(line, "\r\n")
	line = strings.TrimLeft(line, " \t")
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, nil
	}

	// SUBSCRIBE has a WHERE clause tail that isn't kv-shaped; strip
	// before tokenising. Case-insensitive on both keywords.
	var where string
	if strings.EqualFold(firstToken(line), "SUBSCRIBE") {
		if idx := indexKeywordCI(line, "WHERE"); idx >= 0 {
			where = strings.TrimSpace(line[idx+len("WHERE"):])
			line = strings.TrimRight(line[:idx], " \t")
		}
	}

	toks, err := tokenize(line)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return nil, errors.New("empty command")
	}

	cmd := &Command{Verb: strings.ToUpper(toks[0]), Where: where}
	rest := toks[1:]

	// TRIGGER is (name, kv...) with an optional standalone WAIT token.
	// Other verbs are pure kv-only for now — mirror Perl's dispatch.
	if cmd.Verb == "TRIGGER" && len(rest) > 0 {
		cmd.Args = append(cmd.Args, rest[0])
		rest = rest[1:]
		var kvToks []string
		for _, t := range rest {
			if strings.EqualFold(t, "WAIT") {
				cmd.Args = append(cmd.Args, "WAIT")
				continue
			}
			kvToks = append(kvToks, t)
		}
		rest = kvToks
	}

	cmd.KV = make(map[string]string, len(rest))
	for _, t := range rest {
		k, v, err := splitKV(t)
		if err != nil {
			return nil, fmt.Errorf("token %q: %w", t, err)
		}
		cmd.KV[k] = v
	}
	return cmd, nil
}

// tokenize splits a line into (possibly quoted) tokens. A bare token
// may embed a quoted value after '=' — those are kept together so
// downstream splitKV can trivially recover the key. Mirrors Perl
// _tokenize.
func tokenize(line string) ([]string, error) {
	var toks []string
	i := 0
	for i < len(line) {
		c := line[i]
		if c == ' ' || c == '\t' {
			i++
			continue
		}
		if c == '"' {
			v, next, err := Unquote(line, i)
			if err != nil {
				return nil, err
			}
			toks = append(toks, v)
			i = next
			continue
		}
		// bare token: scan until whitespace or an =" pair.
		start := i
		var head strings.Builder
		for i < len(line) {
			cc := line[i]
			if cc == ' ' || cc == '\t' {
				break
			}
			if cc == '=' && i+1 < len(line) && line[i+1] == '"' {
				key := line[start:i]
				v, next, err := Unquote(line, i+1)
				if err != nil {
					return nil, err
				}
				toks = append(toks, key+"\x00"+v)
				i = next
				start = -1
				break
			}
			head.WriteByte(cc)
			i++
		}
		if start >= 0 {
			toks = append(toks, head.String())
		}
	}
	return toks, nil
}

// splitKV turns a raw token into (key, value). Tokens produced by the
// tokenizer for a quoted value carry a NUL separator between the key
// and the pre-unquoted value; bare tokens contain a literal '='.
func splitKV(tok string) (string, string, error) {
	if idx := strings.IndexByte(tok, '\x00'); idx >= 0 {
		return tok[:idx], tok[idx+1:], nil
	}
	if idx := strings.IndexByte(tok, '='); idx >= 0 {
		return tok[:idx], tok[idx+1:], nil
	}
	// Bare positional token (e.g. TRIGGER's name arg after the fast
	// path has consumed it). Callers typically special-case these
	// before reaching splitKV; we treat as a key with empty value.
	return tok, "", nil
}

// firstToken returns the first whitespace-delimited chunk of a line
// without allocating a full token slice — cheap enough to run once
// before the SUBSCRIBE/WHERE probe.
func firstToken(line string) string {
	for i, r := range line {
		if unicode.IsSpace(r) {
			return line[:i]
		}
	}
	return line
}

// indexKeywordCI finds the byte offset of a bare keyword (surrounded by
// whitespace or at end-of-string) in a line, case-insensitive. Returns
// -1 if absent. The Perl side matches `\bKW\b`; \b in Go's regexp is
// available but this hand-rolled version avoids the regexp overhead.
func indexKeywordCI(line, kw string) int {
	kwLen := len(kw)
	up := strings.ToUpper(line)
	kwUp := strings.ToUpper(kw)
	from := 0
	for {
		idx := strings.Index(up[from:], kwUp)
		if idx < 0 {
			return -1
		}
		abs := from + idx
		lhs := abs == 0 || isSpaceByte(line[abs-1])
		rhs := abs+kwLen == len(line) || isSpaceByte(line[abs+kwLen])
		if lhs && rhs {
			return abs
		}
		from = abs + 1
	}
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t'
}
