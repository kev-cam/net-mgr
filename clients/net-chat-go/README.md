# net-chat-go

Go port of the Perl `net-chat` client from
[kev-cam/net-mgr](https://github.com/kev-cam/net-mgr). Target platforms:
Windows native (single .exe), Android (APK via Fyne), Linux (native).

**Status:** scaffold. Wire codec + a stub CLI that connects and prints
frames. UI not implemented yet.

## Layout

```
cmd/net-chat/main.go              entry: dial + stream frames to stdout
internal/netmgr/
  protocol.go                     wire codec (Format/Parse/Quote/Unquote)
  protocol_test.go                golden fixtures — round-trip vs Perl
Makefile                          native / windows / android build targets
go.mod
```

## Build

```
make build         # ./bin/net-chat
make test          # unit tests
make run           # smoke: dial 127.0.0.1:7531, print frames
```

Cross-compile:

```
make windows       # bin/net-chat.exe
make android       # bin/net-chat.apk (needs the Fyne toolchain)
```

## Wire compatibility

`internal/netmgr/protocol.go` is a straight port of Perl
`NetMgr::Protocol` (lib/NetMgr/Protocol.pm in kev-cam/net-mgr). Golden
fixtures in `protocol_test.go` MUST round-trip against the Perl side
bit-for-bit — regenerate with:

```
cd /usr/local/src/net-mgr
perl -Ilib -MNetMgr::Protocol -MData::Dumper \
  -e 'print Dumper(NetMgr::Protocol::parse_line(shift))' -- 'INPUT LINE'
```

The current Perl daemon has a "unterminated quoted string" bug on
CLI-posted bodies containing a literal LF (branch
`netchat-multiline-escape` in net-mgr). The Go client encodes newlines
as `\n` so the wire frame stays single-line — matches what the daemon
already accepts on the read side.

## Next steps

1. AUTH — port ed25519 handshake from Perl `NetMgr::Client::auth`.
2. SUBSCRIBE — long-lived read of `chat_messages WHERE session=X`.
3. CLI subcommand parity (post, read, join, ls).
4. Fyne UI under `internal/ui/` behind a `-tags gui` build tag.
5. Inline QR rendering for `WIFI:...;;` bodies via `go-qrcode`.
