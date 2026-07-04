package NetMgr::Protocol;
# Line-based wire protocol for net-mgr.
#
# Verbs (client → server):
#   HELLO     source=<n> [pid=N]            -- producer identification
#   HELLO     consumer=<n> [pid=N]          -- subscriber identification
#   OBSERVE   k=v ...                       -- producer observation
#   GONE      k=v ...                       -- producer explicit disappearance
#   TRIGGER   <name> [k=v ...] [WAIT]       -- async, kicks off a producer
#   POLL      <name> [k=v ...]              -- sync RPC: server runs a
#                                              whitelisted local probe,
#                                              returns OK output=<b64>
#   SUBSCRIBE sub=N mode=<m> FROM <table> [WHERE <expr>]
#   UNSUB     sub=N
#   FORWARD   slot=PORT target=IP:PORT       -- daemon installs an
#                                              iptables/socat forward
#                                              from loopback:PORT to the
#                                              given LAN target. Lives
#                                              for this connection.
#   UNFORWARD slot=PORT                      -- remove a prior forward
#   NAT_MASQUERADE iface=NAME state=on|off [boot=1]
#                                            -- toggle MASQUERADE on
#                                              POSTROUTING for an
#                                              egress interface.
#                                              Persistent (no per-conn
#                                              cleanup); boot=1 also
#                                              writes through to
#                                              /etc/iptables.
#   SET_GATEWAY action=set via=IP [dev=NAME] [metric=N]
#   SET_GATEWAY action=clear           [metric=N]
#                                            -- install (or remove)
#                                              a low-metric default
#                                              route. Default
#                                              metric=1 wins over
#                                              DHCP defaults; clear
#                                              reverts cleanly.
#   AUTH key-id=ID                          -- begin SSH-key auth.
#                                              Server replies READY
#                                              with a one-shot nonce.
#   AUTH_RESPONSE sig=base64(sshsig)        -- complete auth. Server
#                                              verifies via
#                                              ssh-keygen -Y verify;
#                                              on OK the connection
#                                              is privileged for
#                                              FORWARD / NAT_MASQUERADE
#                                              / SET_GATEWAY.
#   CHAT_OPEN  name=N [mode=open|list|request] [topic="..."]
#                                            -- create a named chat
#                                              session (authorized
#                                              peers only). Creator
#                                              becomes owner.
#   CHAT_SET   name=N [mode=...] [topic="..."]  -- owner edits a session
#   CHAT_CLOSE name=N                           -- owner closes a session
#   CHAT_JOIN  session=N                         -- join; reply OK or
#                                              OK state=requested on a
#                                              request-mode session
#   CHAT_LEAVE session=N                         -- drop presence
#   CHAT_ALLOW   session=N principal=ID          -- owner: add to list
#   CHAT_DENY    session=N principal=ID          -- owner: revoke
#   CHAT_APPROVE session=N principal=ID          -- owner: OK a request
#   CHAT_REJECT  session=N principal=ID          -- owner: deny a request
#   CHAT_PUT session=N file=F offset=O [eof=1] data=base64  -- upload a chunk
#   CHAT_GET session=N file=F [offset=O]         -- download (base64 chunk)
#   CHAT_LS  session=N                            -- list uploaded files
#   CHAT_KEYS session=N                           -- owner: list the chat's
#                                                    authorized SSH keys
#   CHAT_DELETE name=N                            -- owner: delete a chat +
#                                                    its whole archive (destructive)
#   (messages are posted with OBSERVE kind=chat_msg session=N body="...")
#   REPAIR    action=<name> [iface=<name>] [name=<conn>]
#                                            -- loopback-only. Allowlisted
#                                              interface / connection
#                                              maintenance actions the daemon
#                                              performs on the caller's behalf
#                                              (so an unprivileged tool like
#                                              net-diag can drive them via the
#                                              root daemon). Actions:
#                                                wifi_cycle      iface=IF
#                                                ethernet_cycle  iface=IF
#                                                dhcp_cycle      iface=IF
#                                                conn_up         name=CONN
#                                                conn_down       name=CONN
#                                              Each action can be individually
#                                              disabled via [repair]
#                                              prohibit_<action> in the
#                                              daemon's config (default:
#                                              allow all).
#   TRACEROUTE target=<HOST_OR_IP> [max_hops=15] [timeout_s=2] [src_iface=IF]
#                                            -- default-allow diagnostic. The
#                                              daemon runs traceroute -n on the
#                                              caller's behalf and ships back a
#                                              per-hop summary (base64 TSV in
#                                              hops_b64) plus reached/count/
#                                              duration_ms. Admission mirrors
#                                              REPAIR: [diag] prohibit_remote /
#                                              prohibit_unauth / prohibit_all /
#                                              prohibit_traceroute all default
#                                              off, so any caller reaches the
#                                              runner unless the operator
#                                              tightens the gate.
#   BYE
#
# Replies (server → client):
#   OK [k=v ...]
#   ERR  <msg>
#   READY [sub=N] [k=v ...]
#   ROW   sub=N table=<t> op=<insert|update|delete|snapshot> k=v ...
#   EOS   sub=N
#
# `sub=N` (subscription handle) is used everywhere instead of `id=N` so
# it can't clash with a row's own `id` column when serialised in ROW.
#
# Tokens are whitespace-separated. Values may be bare (no whitespace,
# no quote, no '=', no parens) or double-quoted with "" to escape ".
# Bare values may contain commas (for things like ports=22,80) — the
# parser doesn't split on them.
#
# WHERE clause: everything after the WHERE token, passed verbatim to
# NetMgr::Where for parsing.

use strict;
use warnings;
use Carp qw(croak);
use Exporter 'import';

our @EXPORT_OK = qw(parse_line format_ok format_err format_ready
                    format_row format_eos format_kv);

sub parse_line {
    my ($line) = @_;
    return undef unless defined $line;
    $line =~ s/[\r\n]+\z//;
    $line =~ s/^\s+//;
    return undef if $line eq '' || $line =~ /^#/;

    # SUBSCRIBE has WHERE-clause tail; strip it before kv parsing
    my $where_clause;
    if ($line =~ /^\s*SUBSCRIBE\b/i && $line =~ /\bWHERE\b/i) {
        if ($line =~ s/\s+WHERE\s+(.*)$//i) {
            $where_clause = $1;
        }
    }

    my @toks = _tokenize($line);
    croak "empty command" unless @toks;

    my $verb = uc shift @toks;
    my $cmd  = { verb => $verb };

    if    ($verb eq 'HELLO')     { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'OBSERVE')   { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'GONE')      { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'FORWARD')   { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'UNFORWARD') { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'NAT_MASQUERADE') { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'SET_GATEWAY')    { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'AUTH')           { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'AUTH_RESPONSE')  { $cmd->{kv} = _parse_kv_only(\@toks) }
    # net-chat session control. All kv-only; message body (CHAT-less,
    # it rides OBSERVE kind=chat_msg) and topics travel as quoted values.
    elsif ($verb eq 'CHAT_OPEN')      { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'CHAT_CLOSE')     { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'CHAT_SET')       { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'CHAT_JOIN')      { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'CHAT_LEAVE')     { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'CHAT_ALLOW')     { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'CHAT_DENY')      { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'CHAT_APPROVE')   { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'CHAT_REJECT')    { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'CHAT_PROMOTE')       { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'CHAT_DEMOTE')        { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'CHAT_MEMBER_DELETE') { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'BITCHAT_PEER_UPSERT') { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'BITCHAT_PACKET_RELAY') { $cmd->{kv} = _parse_kv_only(\@toks) }
    # Loopback-only host maintenance (link/DHCP cycle, nmcli conn up/down).
    # Client side is bin/net-diag under --repair when running non-root.
    elsif ($verb eq 'REPAIR')     { $cmd->{kv} = _parse_kv_only(\@toks) }
    # Default-allow read-only diagnostic (traceroute today; mtr/dig later).
    # Same [diag] gate template as REPAIR — kv-only body.
    elsif ($verb eq 'TRACEROUTE') { $cmd->{kv} = _parse_kv_only(\@toks) }
    # net-chat file transfer (data= is base64).
    elsif ($verb eq 'CHAT_PUT')       { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'CHAT_GET')       { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'CHAT_LS')        { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'CHAT_RM')        { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'CHAT_KEYS')      { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'CHAT_DELETE')    { $cmd->{kv} = _parse_kv_only(\@toks) }
    # net-mgr-relay's loopback proxy: pull one subnet's rows from the
    # elected master into the local DB right now (lazy sync otherwise).
    elsif ($verb eq 'REFRESH')        { $cmd->{kv} = _parse_kv_only(\@toks) }
    elsif ($verb eq 'BYE')       { croak "BYE takes no args" if @toks }
    elsif ($verb eq 'STATUS')    { croak "STATUS takes no args" if @toks }
    elsif ($verb eq 'UNSUB') {
        my $kv = _parse_kv_only(\@toks);
        croak "UNSUB requires sub=" unless defined $kv->{sub};
        $cmd->{sub} = $kv->{sub} + 0;
    }
    elsif ($verb eq 'TRIGGER') {
        croak "TRIGGER requires a name" unless @toks;
        $cmd->{name} = shift @toks;
        $cmd->{wait} = 0;
        my @rest;
        for my $t (@toks) {
            if (uc $t eq 'WAIT') { $cmd->{wait} = 1 } else { push @rest, $t }
        }
        $cmd->{kv} = _parse_kv_only(\@rest);
    }
    elsif ($verb eq 'POLL') {
        croak "POLL requires a name" unless @toks;
        $cmd->{name} = shift @toks;
        $cmd->{kv}   = _parse_kv_only(\@toks);
    }
    elsif ($verb eq 'SUBSCRIBE') {
        # Expect: id=N mode=<m> FROM <table>
        # Pre-WHERE the tokenizer keeps FROM as a bare token.
        my $kv = {};
        my $table;
        while (@toks) {
            my $t = shift @toks;
            if (uc $t eq 'FROM') {
                croak "expected table after FROM" unless @toks;
                $table = shift @toks;
            }
            elsif ($t =~ /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s) {
                $kv->{$1} = $2;
            }
            else {
                croak "unexpected SUBSCRIBE token '$t'";
            }
        }
        croak "SUBSCRIBE requires sub="         unless defined $kv->{sub};
        croak "SUBSCRIBE requires mode="        unless defined $kv->{mode};
        croak "SUBSCRIBE requires FROM <table>" unless defined $table;
        my $mode = lc $kv->{mode};
        croak "bad mode '$mode'"
            unless $mode =~ /^(snapshot|stream|snapshot\+stream)$/;
        $cmd->{sub}   = $kv->{sub} + 0;
        $cmd->{mode}  = $mode;
        $cmd->{table} = $table;
        $cmd->{where} = $where_clause if defined $where_clause;
    }
    elsif ($verb eq 'OK' || $verb eq 'ERR' || $verb eq 'READY'
        || $verb eq 'ROW' || $verb eq 'EOS' || $verb eq 'HEARTBEAT') {
        # server-originated; parse for clients that want to consume them.
        # HEARTBEAT belongs here too: the daemon dispatches it to
        # _handle_heartbeat (mesh record), but without it parse_line croaked
        # "unknown verb 'HEARTBEAT'" first, so every mesh heartbeat was rejected
        # with ERR — last_hb_rx never updated and the election never reached
        # quorum.
        if ($verb eq 'ERR') {
            $cmd->{msg} = join ' ', @toks;
        } else {
            $cmd->{kv} = _parse_kv_only(\@toks);
        }
    }
    else {
        croak "unknown verb '$verb'";
    }

    return $cmd;
}

sub _parse_kv_only {
    my ($toks) = @_;
    my %kv;
    for my $t (@$toks) {
        croak "expected k=v, got '$t'"
            unless $t =~ /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s;
        $kv{$1} = $2;
    }
    return \%kv;
}

# Tokenize one logical command line.
# Handles bare tokens (no whitespace/quote/paren), quoted strings ("..."),
# and the equals sign as part of a single token (foo="bar baz").
sub _tokenize {
    my ($line) = @_;
    my @toks;
    my $i = 0;
    my $n = length $line;
    while ($i < $n) {
        my $c = substr($line, $i, 1);
        if ($c =~ /\s/) { $i++; next }
        if ($c eq '"') {
            # standalone quoted token (rare — usually quoted values appear
            # after =), but handle it for robustness
            my ($val, $next) = _read_quoted($line, $i);
            push @toks, $val;
            $i = $next;
            next;
        }
        # bare token, possibly with a key= prefix and a quoted value
        my $start = $i;
        while ($i < $n) {
            my $cc = substr($line, $i, 1);
            last if $cc =~ /\s/;
            if ($cc eq '=' && $i+1 < $n && substr($line,$i+1,1) eq '"') {
                # consume up to and including =, then read quoted value
                my $key = substr($line, $start, $i - $start);
                my ($val, $next) = _read_quoted($line, $i+1);
                push @toks, "$key=$val";
                $i = $next;
                $start = -1;
                last;
            }
            $i++;
        }
        if ($start >= 0) {
            push @toks, substr($line, $start, $i - $start);
        }
    }
    return @toks;
}

sub _read_quoted {
    my ($s, $i) = @_;
    croak "expected '\"'" unless substr($s, $i, 1) eq '"';
    $i++;
    my $val = '';
    my $n = length $s;
    while ($i < $n) {
        my $c = substr($s, $i, 1);
        if ($c eq '"') {
            if ($i+1 < $n && substr($s, $i+1, 1) eq '"') {
                $val .= '"'; $i += 2; next;
            }
            return ($val, $i+1);
        }
        if ($c eq '\\' && $i+1 < $n) {       # decode \n \r \\ (symmetric with _quote_if_needed)
            my $d = substr($s, $i+1, 1);
            if    ($d eq 'n')  { $val .= "\n"; $i += 2; next }
            elsif ($d eq 'r')  { $val .= "\r"; $i += 2; next }
            elsif ($d eq '\\') { $val .= "\\"; $i += 2; next }
        }
        $val .= $c; $i++;
    }
    croak "unterminated quoted string";
}

# ---- formatters ---------------------------------------------------------

sub format_kv {
    my %h = @_;
    my @parts;
    for my $k (sort keys %h) {
        my $v = $h{$k};
        next unless defined $v;
        push @parts, "$k=" . _quote_if_needed($v);
    }
    return join ' ', @parts;
}

sub _quote_if_needed {
    my ($v) = @_;
    return '""' if !length $v;
    if ($v =~ /[\s"=()\\]/) {
        my $q = $v;
        $q =~ s/\\/\\\\/g;   # escape backslash first
        $q =~ s/\r/\\r/g;       # CR -> \r (a literal CR/LF would split the line-based wire frame)
        $q =~ s/\n/\\n/g;       # LF -> \n
        $q =~ s/"/""/g;
        return qq("$q");
    }
    return $v;
}

sub format_ok    { my %h = @_; my $kv = format_kv(%h); return $kv ? "OK $kv" : "OK" }
sub format_err   { my $m = shift // ''; $m =~ s/[\r\n]+/ /g; return "ERR $m" }
sub format_ready { my %h = @_; return "READY " . format_kv(%h) }
sub format_eos   { my ($sub) = @_; return "EOS sub=$sub" }

# format_row($sub_id, $table, $op, %row) — keeps the subscription id
# (`sub=`) separate from the row columns so a row's own `id` column
# doesn't clobber it.
sub format_row {
    my ($sub_id, $table, $op, %row) = @_;
    my $head = "sub=$sub_id table=$table op=$op";
    my $tail = format_kv(%row);
    return $tail ? "ROW $head $tail" : "ROW $head";
}

1;
