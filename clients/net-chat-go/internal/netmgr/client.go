package netmgr

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sync"
	"time"
)

// Client speaks the net-mgr wire protocol. Not safe for concurrent
// writes — hold Client.mu across a send if another goroutine may also
// send. Reads are serial (one Recv-goroutine at a time).
type Client struct {
	conn net.Conn
	br   *bufio.Reader
	bw   *bufio.Writer

	mu      sync.Mutex // guards writes + subSeq
	greeted bool
	as      string // consumer/sender name
	closed  bool
	subSeq  int // monotonic client-allocated SUBSCRIBE id
}

// Dial opens a TCP connection to the daemon.
func Dial(addr string, timeout time.Duration) (*Client, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	c := &Client{
		conn: conn,
		br:   bufio.NewReaderSize(conn, 1<<16),
		bw:   bufio.NewWriterSize(conn, 1<<16),
	}
	return c, nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}

// SetAs remembers the consumer/sender name so subsequent verbs can
// carry it (matches Perl NetMgr::Client's `as` slot).
func (c *Client) SetAs(as string) { c.as = as }

// Send writes one framed line. Blocks until the write is flushed.
func (c *Client) Send(line string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := io.WriteString(c.bw, line); err != nil {
		return err
	}
	if line == "" || line[len(line)-1] != '\n' {
		if _, err := c.bw.WriteString("\n"); err != nil {
			return err
		}
	}
	return c.bw.Flush()
}

// SendVerb formats and sends one verb + kv frame.
func (c *Client) SendVerb(verb string, kv map[string]string) error {
	return c.Send(Format(verb, kv))
}

// Recv reads one line and parses it. Blocks until a full LF-terminated
// line arrives or the connection closes.
func (c *Client) Recv() (*Command, string, error) {
	line, err := c.br.ReadString('\n')
	if err != nil {
		if line == "" {
			return nil, "", err
		}
		// Return whatever we managed to read alongside the error so a
		// caller diagnosing a truncated frame can see it.
	}
	cmd, perr := Parse(line)
	if perr != nil {
		return nil, line, perr
	}
	return cmd, line, err
}

// Hello sends the initial HELLO frame and consumes the OK reply. The
// Perl daemon requires HELLO before any AUTH/POST. Idempotent — a
// second call is a no-op.
func (c *Client) Hello(consumer string) error {
	if c.greeted {
		return nil
	}
	kv := map[string]string{"client": "net-chat-go", "version": "0.0.1"}
	if consumer != "" {
		kv["consumer"] = consumer
	}
	if err := c.SendVerb("HELLO", kv); err != nil {
		return err
	}
	cmd, raw, err := c.Recv()
	if err != nil {
		return fmt.Errorf("HELLO: recv reply: %w (raw=%q)", err, raw)
	}
	if cmd == nil {
		return errors.New("HELLO: no reply")
	}
	if cmd.Verb == "ERR" {
		return fmt.Errorf("HELLO: %s", raw)
	}
	if cmd.Verb != "OK" {
		return fmt.Errorf("HELLO: unexpected reply %q", raw)
	}
	c.greeted = true
	return nil
}

// SubscribeChat writes SUBSCRIBE for a chat_messages session and
// returns the sub id used (client-allocated; matches Perl behavior).
// Convenience wrapper over SubscribeStream.
func (c *Client) SubscribeChat(session string) (string, error) {
	return c.SubscribeStream("chat_messages",
		fmt.Sprintf("session = '%s'", escapeSQLLiteral(session)))
}

// SubscribeBitChatPeers subscribes to the bitchat_peers table so the
// caller sees the current roster plus live updates as peers announce
// / drop / rename.
func (c *Client) SubscribeBitChatPeers() (string, error) {
	return c.SubscribeStream("bitchat_peers", "")
}

// SubscribeStream fires a `SUBSCRIBE mode=snapshot+stream FROM <table>`
// with an optional WHERE clause and returns the client-allocated sub
// id. After this returns the daemon streams snapshot ROWs followed by
// an EOS frame, then keeps streaming live inserts/updates. The caller
// reads via Recv() in a loop. Same frame shape bin/net-chat uses at
// line 472.
func (c *Client) SubscribeStream(table, where string) (string, error) {
	subID := c.nextSubID()
	line := "SUBSCRIBE sub=" + subID + " mode=snapshot+stream FROM " + table
	if where != "" {
		line += " WHERE " + where
	}
	if err := c.Send(line + "\n"); err != nil {
		return "", err
	}
	return subID, nil
}

// Post sends a chat message via OBSERVE kind=chat_msg. The `as` field
// is honoured by the daemon only for loopback connections; remote
// posts get the verified key_id stamped instead. Returns the OK reply
// kv (typically empty). Mirrors Perl NetMgr::Client::chat_post.
func (c *Client) Post(session, body string) (map[string]string, error) {
	if session == "" || body == "" {
		return nil, errors.New("post: session and body are required")
	}
	kv := map[string]string{
		"kind":    "chat_msg",
		"session": session,
		"body":    body,
	}
	if c.as != "" {
		kv["as"] = c.as
	}
	if err := c.SendVerb("OBSERVE", kv); err != nil {
		return nil, fmt.Errorf("post: send: %w", err)
	}
	cmd, raw, err := c.Recv()
	if err != nil {
		return nil, fmt.Errorf("post: recv: %w (raw=%q)", err, raw)
	}
	if cmd == nil {
		return nil, errors.New("post: no reply")
	}
	if cmd.Verb == "ERR" {
		return nil, fmt.Errorf("post: %s", raw)
	}
	if cmd.Verb != "OK" {
		return nil, fmt.Errorf("post: unexpected reply %q", raw)
	}
	return cmd.KV, nil
}

func (c *Client) nextSubID() string {
	c.mu.Lock()
	c.subSeq++
	n := c.subSeq
	c.mu.Unlock()
	return fmt.Sprintf("%d", n)
}

// Unsubscribe cancels a live subscription. No reply is expected — the
// daemon just stops emitting ROWs for that sub id.
func (c *Client) Unsubscribe(subID string) error {
	if subID == "" {
		return nil
	}
	return c.Send("UNSUB sub=" + subID + "\n")
}

// Snapshot performs a one-shot read of `table` (optionally filtered
// via a SQL WHERE clause) and returns every row seen before EOS. This
// is how the Perl client fetches the session list, the roster, and
// paging history. Blocks until EOS or an error; drains the trailing
// OK ack the daemon emits after the snapshot completes. The subID
// used is client-allocated and not exposed — callers don't need it
// because snapshot mode closes the sub server-side.
func (c *Client) Snapshot(table, where string) ([]map[string]string, error) {
	subID := c.nextSubID()
	line := "SUBSCRIBE sub=" + subID + " mode=snapshot FROM " + table
	if where != "" {
		line += " WHERE " + where
	}
	if err := c.Send(line + "\n"); err != nil {
		return nil, err
	}
	var rows []map[string]string
	for {
		cmd, raw, err := c.Recv()
		if err != nil {
			return nil, fmt.Errorf("snapshot %s: recv: %w (raw=%q)", table, err, raw)
		}
		if cmd == nil {
			continue
		}
		switch cmd.Verb {
		case "ROW":
			// Guard against the tiny chance a live-stream row for a
			// different sub squeezes in (shouldn't happen mid-
			// snapshot on the same connection, but the check is cheap).
			if cmd.KV["sub"] != "" && cmd.KV["sub"] != subID {
				continue
			}
			rows = append(rows, cmd.KV)
		case "EOS":
			// Drain the trailing OK ack the daemon sends after
			// closing out the snapshot — matches Perl behaviour.
			if _, _, err := c.Recv(); err != nil {
				return rows, nil // ack drop isn't fatal
			}
			return rows, nil
		case "ERR":
			return nil, fmt.Errorf("snapshot %s: %s", table, raw)
		}
	}
}

// ChatPut streams `r` to the daemon as a chunked upload, storing it
// under `session/name`. Returns the final byte count (from the last
// OK's size= field). Chunks are 48 KB each — matches Perl bin/net-chat
// upload path so the daemon-side reassembly logic sees the same shape.
// Callers MUST hold exclusive use of the connection during the upload:
// the daemon's OK ack for each chunk is read inline via Recv(), so a
// concurrent read loop on this connection will steal the reply. The
// canonical pattern (matching Perl bin/net-chat) is a separate
// "control" connection for POST/CHAT_*, distinct from the streaming
// SUBSCRIBE connection.
func (c *Client) ChatPut(session, name string, r io.Reader) (int64, error) {
	const chunkSize = 48 * 1024
	var (
		offset int64
		buf    = make([]byte, chunkSize)
		size   int64
	)
	for {
		n, rerr := io.ReadFull(r, buf)
		if rerr != nil && rerr != io.ErrUnexpectedEOF && rerr != io.EOF {
			return 0, fmt.Errorf("chat_put: read: %w", rerr)
		}
		eof := rerr != nil || n < chunkSize
		kv := map[string]string{
			"session": session,
			"file":    name,
			"offset":  fmt.Sprintf("%d", offset),
			"data":    base64.StdEncoding.EncodeToString(buf[:n]),
		}
		if eof {
			kv["eof"] = "1"
		}
		if err := c.SendVerb("CHAT_PUT", kv); err != nil {
			return 0, fmt.Errorf("chat_put: send: %w", err)
		}
		cmd, raw, err := c.Recv()
		if err != nil {
			return 0, fmt.Errorf("chat_put: recv: %w", err)
		}
		if cmd == nil {
			return 0, errors.New("chat_put: no reply")
		}
		if cmd.Verb == "ERR" {
			return 0, fmt.Errorf("chat_put: %s", raw)
		}
		if cmd.Verb != "OK" {
			return 0, fmt.Errorf("chat_put: unexpected reply %q", raw)
		}
		if v := cmd.KV["size"]; v != "" {
			// Daemon reports total accumulated size after each chunk;
			// the final OK's value is what the CLI prints as "N bytes".
			fmt.Sscanf(v, "%d", &size)
		}
		offset += int64(n)
		if eof {
			if size == 0 {
				size = offset
			}
			return size, nil
		}
	}
}

// ChatGet downloads `session/name` and streams it into w. Chunks are
// requested until eof=1 or empty data. Same concurrency contract as
// ChatPut — exclusive use of the connection.
func (c *Client) ChatGet(session, name string, w io.Writer) (int64, error) {
	var offset int64
	for {
		kv := map[string]string{
			"session": session,
			"file":    name,
			"offset":  fmt.Sprintf("%d", offset),
		}
		if err := c.SendVerb("CHAT_GET", kv); err != nil {
			return offset, fmt.Errorf("chat_get: send: %w", err)
		}
		cmd, raw, err := c.Recv()
		if err != nil {
			return offset, fmt.Errorf("chat_get: recv: %w", err)
		}
		if cmd == nil {
			return offset, errors.New("chat_get: no reply")
		}
		if cmd.Verb == "ERR" {
			return offset, fmt.Errorf("chat_get: %s", raw)
		}
		if cmd.Verb != "OK" {
			return offset, fmt.Errorf("chat_get: unexpected reply %q", raw)
		}
		var chunk []byte
		if v := cmd.KV["data"]; v != "" {
			b, derr := base64.StdEncoding.DecodeString(v)
			if derr != nil {
				return offset, fmt.Errorf("chat_get: b64: %w", derr)
			}
			chunk = b
		}
		if len(chunk) > 0 {
			if _, werr := w.Write(chunk); werr != nil {
				return offset, fmt.Errorf("chat_get: write: %w", werr)
			}
			offset += int64(len(chunk))
		}
		if cmd.KV["eof"] == "1" || len(chunk) == 0 {
			return offset, nil
		}
	}
}

// FileInfo describes one file returned by ChatLs.
type FileInfo struct {
	Name string
	Size int64
}

// ChatLs returns the file list for a session. The daemon encodes it as
// a base64 JSON array of {name, size} objects on the OK reply's files=
// field — same wire shape Perl bin/net-chat uses.
func (c *Client) ChatLs(session string) ([]FileInfo, error) {
	if err := c.SendVerb("CHAT_LS", map[string]string{"session": session}); err != nil {
		return nil, fmt.Errorf("chat_ls: send: %w", err)
	}
	cmd, raw, err := c.Recv()
	if err != nil {
		return nil, fmt.Errorf("chat_ls: recv: %w", err)
	}
	if cmd == nil {
		return nil, errors.New("chat_ls: no reply")
	}
	if cmd.Verb == "ERR" {
		return nil, fmt.Errorf("chat_ls: %s", raw)
	}
	if cmd.Verb != "OK" {
		return nil, fmt.Errorf("chat_ls: unexpected reply %q", raw)
	}
	v := cmd.KV["files"]
	if v == "" {
		return nil, nil
	}
	jsonBytes, derr := base64.StdEncoding.DecodeString(v)
	if derr != nil {
		return nil, fmt.Errorf("chat_ls: b64: %w", derr)
	}
	var files []FileInfo
	if err := json.Unmarshal(jsonBytes, &files); err != nil {
		return nil, fmt.Errorf("chat_ls: json: %w", err)
	}
	return files, nil
}

// ChatRm deletes a stored file from the session.
func (c *Client) ChatRm(session, name string) error {
	if err := c.SendVerb("CHAT_RM", map[string]string{
		"session": session, "file": name,
	}); err != nil {
		return fmt.Errorf("chat_rm: send: %w", err)
	}
	cmd, raw, err := c.Recv()
	if err != nil {
		return fmt.Errorf("chat_rm: recv: %w", err)
	}
	if cmd == nil {
		return errors.New("chat_rm: no reply")
	}
	if cmd.Verb == "ERR" {
		return fmt.Errorf("chat_rm: %s", raw)
	}
	if cmd.Verb != "OK" {
		return fmt.Errorf("chat_rm: unexpected reply %q", raw)
	}
	return nil
}

// ListChatSessions returns every open chat session on the daemon.
// Convenience wrapper around Snapshot. Fields on each map: name,
// access_mode, status, created_by, topic, last_activity.
func (c *Client) ListChatSessions(includeAll bool) ([]map[string]string, error) {
	where := ""
	if !includeAll {
		where = "status = 'open'"
	}
	return c.Snapshot("chat_sessions", where)
}

// escapeSQLLiteral doubles any embedded single-quote for a SQL string
// literal. Session names in practice never contain quotes, but be safe.
func escapeSQLLiteral(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			out = append(out, '\'', '\'')
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}

// DefaultKeyID returns "$USER@$hostname" — matches Perl _default_key_id.
func DefaultKeyID() string {
	u, err := user.Current()
	name := "unknown"
	if err == nil {
		name = u.Username
	}
	if v := os.Getenv("USER"); v != "" {
		name = v
	}
	host, herr := os.Hostname()
	if herr != nil || host == "" {
		host = "localhost"
	}
	return name + "@" + host
}

// DefaultKeyFile returns the first readable of ~/.ssh/id_ed25519,
// ~/.ssh/id_rsa, ~/.ssh/id_ecdsa — matches Perl _default_key_file.
func DefaultKeyFile() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	for _, name := range []string{"id_ed25519", "id_rsa", "id_ecdsa"} {
		p := filepath.Join(home, ".ssh", name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("no ~/.ssh/id_ed25519|id_rsa|id_ecdsa found")
}

// Auth performs the two-step AUTH / AUTH_RESPONSE handshake against
// the daemon. keyID is the identity (e.g. "dkc@bigsony") and keyFile
// is a private SSH key ssh-keygen can sign with. We shell out to
// ssh-keygen -Y sign — same as the Perl client. The daemon side
// validates against ~/.ssh/authorized_keys-shaped state on nas3.
func (c *Client) Auth(keyID, keyFile string) error {
	if keyID == "" {
		return errors.New("auth: empty key_id")
	}
	if _, err := os.Stat(keyFile); err != nil {
		return fmt.Errorf("auth: key_file: %w", err)
	}
	if !c.greeted {
		if err := c.Hello(c.as); err != nil {
			return fmt.Errorf("auth: HELLO: %w", err)
		}
	}
	// Step 1: AUTH key_id=X  →  READY nonce=Y
	if err := c.SendVerb("AUTH", map[string]string{"key_id": keyID}); err != nil {
		return fmt.Errorf("auth: send AUTH: %w", err)
	}
	cmd, raw, err := c.Recv()
	if err != nil {
		return fmt.Errorf("auth: recv READY: %w (raw=%q)", err, raw)
	}
	if cmd == nil {
		return errors.New("auth: no reply to AUTH")
	}
	if cmd.Verb == "ERR" {
		return fmt.Errorf("auth: %s", raw)
	}
	if cmd.Verb != "READY" {
		return fmt.Errorf("auth: unexpected reply %q", raw)
	}
	nonce := cmd.KV["nonce"]
	if nonce == "" {
		return errors.New("auth: READY missing nonce=")
	}
	// Step 2: ssh-keygen -Y sign the nonce, then AUTH_RESPONSE sig=<b64>.
	sigB64, err := signWithSSHKeygen(keyFile, []byte(nonce))
	if err != nil {
		return fmt.Errorf("auth: sign: %w", err)
	}
	if err := c.SendVerb("AUTH_RESPONSE", map[string]string{"sig": sigB64}); err != nil {
		return fmt.Errorf("auth: send AUTH_RESPONSE: %w", err)
	}
	cmd2, raw2, err := c.Recv()
	if err != nil {
		return fmt.Errorf("auth: recv OK: %w (raw=%q)", err, raw2)
	}
	if cmd2 == nil {
		return errors.New("auth: no reply to AUTH_RESPONSE")
	}
	if cmd2.Verb == "ERR" {
		return fmt.Errorf("auth: %s", raw2)
	}
	if cmd2.Verb != "OK" {
		return fmt.Errorf("auth: unexpected reply %q", raw2)
	}
	return nil
}

// signWithSSHKeygen invokes `ssh-keygen -Y sign -n net-mgr -f <keyFile>`
// with the nonce on stdin and returns the base64-encoded signature.
// Uses `timeout` + `setsid` to avoid a passphrase prompt hanging the
// process — same fallbacks as the Perl side.
func signWithSSHKeygen(keyFile string, nonce []byte) (string, error) {
	// Write the nonce to a tempfile; ssh-keygen -Y sign reads its
	// message from stdin (piped) so a file isn't strictly required,
	// but the Perl side uses tempfiles and we mirror to reduce
	// behavioural divergence.
	nf, err := os.CreateTemp("", "nc-nonce-*")
	if err != nil {
		return "", fmt.Errorf("tempfile: %w", err)
	}
	defer os.Remove(nf.Name())
	if _, err := nf.Write(nonce); err != nil {
		nf.Close()
		return "", err
	}
	nf.Close()

	sf, err := os.CreateTemp("", "nc-sig-*.sig")
	if err != nil {
		return "", err
	}
	sfPath := sf.Name()
	sf.Close()
	defer os.Remove(sfPath)

	// Assemble the shell fragment. Use setsid + timeout when available
	// so a passphrase-protected key doesn't hang forever on /dev/tty.
	args := []string{}
	if _, err := exec.LookPath("timeout"); err == nil {
		args = append(args, "timeout", "8")
	}
	if _, err := exec.LookPath("setsid"); err == nil {
		args = append(args, "setsid")
	}
	sh := fmt.Sprintf(
		"ssh-keygen -q -Y sign -n net-mgr -f %s < %s > %s 2>/dev/null",
		shellQuote(keyFile), shellQuote(nf.Name()), shellQuote(sfPath),
	)
	args = append(args, "sh", "-c", sh)

	cmd := exec.Command(args[0], args[1:]...)
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 124 {
			return "", fmt.Errorf(
				"ssh-keygen sign timed out (8s). Is %q passphrase-protected? "+
					"ssh-add it or drop the passphrase.", keyFile)
		}
		return "", fmt.Errorf("ssh-keygen sign: %w", err)
	}
	sig, err := os.ReadFile(sfPath)
	if err != nil {
		return "", fmt.Errorf("read sig: %w", err)
	}
	if len(sig) == 0 {
		return "", errors.New("ssh-keygen produced empty signature")
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// shellQuote wraps a value in single quotes for /bin/sh, escaping any
// embedded single quotes via '\'' — matches Perl _shq.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '_' || c == '.' || c == '/' || c == '=':
		case c == ',' || c == '@' || c == ':' || c == '-':
		default:
			safe = false
		}
		if !safe {
			break
		}
	}
	if safe {
		return s
	}
	// Replace ' with '\''
	out := make([]byte, 0, len(s)+2)
	out = append(out, '\'')
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			out = append(out, '\'', '\\', '\'', '\'')
			continue
		}
		out = append(out, s[i])
	}
	out = append(out, '\'')
	return string(out)
}
