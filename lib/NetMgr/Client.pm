package NetMgr::Client;
# Synchronous client for the net-mgr socket protocol.
# Used by net-poll-ap, net-report, and the compat shims.

use strict;
use warnings;
use Carp qw(croak);
use IO::Socket::IP;     # both IPv4 and IPv6, unlike IO::Socket::INET
use NetMgr::Protocol qw(parse_line format_kv);

# Endpoint (host:port) + IPv6-literal handling now lives in NetMgr::Addr. Import
# the names so existing NetMgr::Client::split_hostport / ::join_hostport callers
# (net-reserve, net-chat, net-mgr-relay, net-mgr-setup) keep resolving.
use NetMgr::Addr qw(split_hostport join_hostport);

sub new {
    my ($class, %args) = @_;
    # Auto-discovery: caller opted in with discover=>1 and did not pin an
    # explicit listen=. Walk a candidate ladder ($NET_MGR_LISTEN, the
    # [servers] default, loopback, the on-disk cache, the rest of [servers],
    # then a bounded LAN probe) and return the first daemon we can HELLO.
    # Tools should prefer this over hard-coding '127.0.0.1:7531' so they
    # keep working when the local daemon is asleep but a peer is live.
    if ($args{discover} && !defined $args{listen}) {
        return _discover_new($class, %args);
    }
    my $listen = $args{listen} // $ENV{NET_MGR_LISTEN} // '127.0.0.1:7531';
    # Default port to 7531 so '--listen zmc1' / '--listen zmc1.grfx.com' /
    # '--listen [fd00::1]' all work without spelling out the port. IPv6
    # literals must be bracketed to carry a port ('[fd00::1]:7531').
    my ($host, $port) = split_hostport($listen);
    $host = '127.0.0.1' unless defined $host && length $host;
    $port = 7531        unless defined $port && length $port;
    my $timeout = $args{timeout} // 10;
    my $sock = IO::Socket::IP->new(
        PeerHost => $host,
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => $timeout,
    ) or croak "connect " . join_hostport($host, $port) . ": $!";
    # `as` is a loopback-only self-declared identity stamped onto chat
    # control verbs / posts (the daemon ignores it once AUTH'd).
    # `as_pubkey` is the OpenSSH-format public key auto-attached to chat_join
    # for the see-and-request flow — the daemon stores it on the requested
    # member row, and an active member's approval moves it to the chat's
    # durable authorized-key list (chat-key auth on the next connect).
    return bless { sock => $sock, buf => '', listen => join_hostport($host, $port),
                   as => $args{as}, as_pubkey => $args{as_pubkey},
                   timeout => $timeout }, $class;
}

# --------------------------------------------------------------------------
# Auto-discovery ladder (see new(discover=>1)).
#
# The goal: net-mgr client tools should work out of the box on a fresh box
# without a per-user config. Anyone who's ever reached the cluster gets the
# cheap path (loopback → cached winner). Anyone brand new falls off the
# end onto a bounded LAN probe.
#
# Ladder, first success wins:
#   1. $NET_MGR_LISTEN                    (operator override — highest)
#   2. [servers] default from the config  (--server without an argument)
#   3. 127.0.0.1:7531                     (loopback fast path)
#   4. cached last-successful daemon      (~/.cache/net-mgr/last-daemon)
#   5. every other [servers] entry        (dial each in file order)
#   6. LAN /24 probe on port 7531         (bounded, non-blocking; last resort)
#
# Per-candidate: TCP connect within a short probe timeout, then HELLO.
# Folding HELLO into the probe means a socket that accepts but never
# answers doesn't count as "working". First OK wins, we cache and return.
#
# On success past the loopback fast path we print a friendly one-liner to
# stderr ("[net-mgr] discover: using nas3 …") so the operator knows why
# the tool talked to a remote daemon instead of the local one.
sub _discover_new {
    my ($class, %args) = @_;
    my $long_timeout  = $args{timeout} // 10;
    # Short per-candidate probe to keep worst-case ladder walk bounded.
    # Callers who need per-candidate control override with
    # discover_probe_timeout=; default 2s covers a dead host on the LAN.
    my $probe_timeout = $args{discover_probe_timeout} // 2;
    my $consumer      = $args{consumer};
    my @cands         = _build_candidates();
    my @errors;
    for my $i (0 .. $#cands) {
        my $c = $cands[$i];
        my ($cli, $err) = _probe_endpoint(
            $class,
            host          => $c->{host},
            port          => $c->{port},
            probe_timeout => $probe_timeout,
            timeout       => $long_timeout,
            consumer      => $consumer,
            as            => $args{as},
            as_pubkey     => $args{as_pubkey},
        );
        if ($cli) {
            _cache_write($c->{host}, $c->{port});
            # Only chirp when we fell past the loopback. Silence on
            # "loopback worked" / "$NET_MGR_LISTEN worked" (the operator
            # already told us to use it).
            if ($c->{noisy}) {
                warn sprintf("[net-mgr] discover: using %s (%s)\n",
                             $c->{label}, join_hostport($c->{host}, $c->{port}));
            }
            return $cli;
        }
        push @errors,
            sprintf('%s (%s): %s',
                    $c->{label}, join_hostport($c->{host}, $c->{port}), $err);
    }
    # Step 6: LAN probe. Cheap enough (~2s total, non-blocking connects)
    # that we run it unconditionally when the ladder ran dry. Skip only
    # if the caller explicitly turned it off (discover_lan_probe=>0).
    if ($args{discover_lan_probe} // 1) {
        my $winner = _lan_probe(
            budget => $args{discover_lan_budget} // 2.0,
        );
        if ($winner) {
            my ($cli, $err) = _probe_endpoint(
                $class,
                host          => $winner->{host},
                port          => $winner->{port},
                probe_timeout => $probe_timeout,
                timeout       => $long_timeout,
                consumer      => $consumer,
                as            => $args{as},
                as_pubkey     => $args{as_pubkey},
            );
            if ($cli) {
                _cache_write($winner->{host}, $winner->{port});
                warn sprintf("[net-mgr] discover: LAN probe found %s\n",
                             join_hostport($winner->{host}, $winner->{port}));
                return $cli;
            }
            push @errors,
                sprintf('LAN probe (%s): %s',
                        join_hostport($winner->{host}, $winner->{port}), $err);
        }
    }
    croak "connect: no reachable net-mgr daemon (tried "
        . join('; ', @errors) . ")";
}

# Attempt one host:port. Returns ($blessed_client, undef) on full HELLO
# success or (undef, $err_string) on any failure. Uses probe_timeout for
# the connect (short) and timeout for the returned client's I/O budget.
sub _probe_endpoint {
    my ($class, %args) = @_;
    my $host = $args{host};
    my $port = $args{port};
    my $sock = IO::Socket::IP->new(
        PeerHost => $host,
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => $args{probe_timeout},
    );
    unless ($sock) {
        return (undef, "connect: $!");
    }
    my $self = bless {
        sock    => $sock,
        buf     => '',
        listen  => join_hostport($host, $port),
        as      => $args{as},
        as_pubkey => $args{as_pubkey},
        # Bound the HELLO wait by the probe timeout so a wedged peer
        # doesn't burn our whole ladder budget; restore the caller's
        # requested I/O timeout on success.
        timeout => $args{probe_timeout},
    }, $class;
    my $probe_consumer = $args{consumer} // "discover.$$";
    my $ok = eval { $self->hello(consumer => $probe_consumer); 1 };
    if (!$ok) {
        my $err = $@ || 'HELLO failed';
        chomp $err; $err =~ s/ at \S+ line \d+\.?\z//;
        eval { close $sock };
        return (undef, $err);
    }
    # Restore the caller's steady-state timeout for subsequent verbs.
    $self->{timeout} = $args{timeout};
    return ($self, undef);
}

# Build the ordered candidate list. Deduped by "host:port".
# noisy=>1 means "warn on stderr if this candidate wins" — reserved for
# non-loopback wins so `net-lookup` staying on 127.0.0.1 is silent, but
# a fallover to nas3 is visible.
sub _build_candidates {
    my @cands;
    my %seen;
    my $add = sub {
        my ($label, $addr, %opts) = @_;
        return unless defined $addr && length $addr;
        my ($h, $p) = split_hostport($addr);
        $h = '127.0.0.1' unless defined $h && length $h;
        $p = 7531        unless defined $p && length $p;
        my $key = "$h:$p";
        return if $seen{$key}++;
        push @cands, { label => $label, host => $h, port => $p + 0, %opts };
    };
    # 1. env override (noisy so a stale env var is obvious).
    $add->('$NET_MGR_LISTEN', $ENV{NET_MGR_LISTEN}, noisy => 1);
    # 2. [servers] default. May resolve either a symbolic name or a
    # literal host:port. Not noisy: it's the operator-declared preferred
    # daemon, so hitting it is expected.
    my $config_default = eval {
        require NetMgr::Config;
        NetMgr::Config->resolve_server(undef);
    };
    $add->('config default', $config_default);
    # 3. loopback. Silent on win — the boring common case.
    $add->('loopback', '127.0.0.1:7531');
    # 4. cache. Noisy: falling back onto a cached remote means the local
    # daemon is dead, worth surfacing.
    my $cached = _cache_read();
    if ($cached) {
        my $addr = join_hostport($cached->{host}, $cached->{port});
        $add->('cached', $addr, noisy => 1);
    }
    # 5. every other [servers] entry (in name order). Noisy on win.
    my %srv;
    eval {
        require NetMgr::Config;
        my ($srv) = NetMgr::Config->servers;
        %srv = %{ $srv || {} };
    };
    for my $name (sort keys %srv) {
        $add->("[servers] $name", $srv{$name}, noisy => 1);
    }
    return @cands;
}

# ---- discovery cache: ~/.cache/net-mgr/last-daemon -----------------------
# Small state file storing the most recent successful winner so the next
# invocation goes straight to it. JSON so we can grow ts/name/etc without
# reflowing parsers. Written on every successful discovery (including
# loopback); read on step 4 of the ladder.
sub _cache_path {
    my $base = $ENV{XDG_CACHE_HOME};
    $base ||= "$ENV{HOME}/.cache"
        if defined $ENV{HOME} && length $ENV{HOME};
    return undef unless defined $base && length $base;
    return "$base/net-mgr/last-daemon";
}

sub _cache_read {
    my $p = _cache_path() or return undef;
    return undef unless -r $p;
    open my $fh, '<', $p or return undef;
    local $/;
    my $body = <$fh>;
    close $fh;
    return undef unless defined $body && length $body;
    require JSON::PP;
    my $d = eval { JSON::PP::decode_json($body) };
    return undef if $@ || !$d || ref $d ne 'HASH';
    return undef unless defined $d->{host} && length $d->{host}
                     && defined $d->{port} && $d->{port} =~ /^\d+$/;
    return { host => $d->{host}, port => $d->{port} + 0, ts => $d->{ts} };
}

sub _cache_write {
    my ($host, $port) = @_;
    return unless defined $host && length $host;
    my $p = _cache_path() or return;
    (my $dir = $p) =~ s{/[^/]+$}{};
    if (length $dir && !-d $dir) {
        require File::Path;
        eval { File::Path::make_path($dir) };
        return unless -d $dir;
    }
    require JSON::PP;
    my $body = eval {
        JSON::PP::encode_json({
            host => $host, port => $port + 0, ts => time(),
        });
    } // return;
    my $tmp = "$p.tmp.$$";
    open my $fh, '>', $tmp or return;
    print $fh $body, "\n";
    close $fh;
    rename $tmp, $p or unlink $tmp;
}

# ---- LAN probe (last-resort step 6) --------------------------------------
# Non-blocking connect fan-out across every /24 the host is on. For each
# host that finishes the TCP handshake within the budget we then send a
# blocking HELLO and check for OK. First working peer wins. Returns
# { host => STR, port => INT } or undef.
#
# The point is bootstrap: a brand-new box that has never contacted the
# cluster and has no operator-supplied config. It's slower than the other
# steps so it only runs after 1..5 all fail.
sub _lan_probe {
    my (%args) = @_;
    my $budget = $args{budget} // 2.0;
    my $port   = $args{port}   // 7531;
    require IO::Select;
    require Socket;
    require Time::HiRes;
    my $end = Time::HiRes::time() + $budget;

    # Enumerate this host's /24 (or narrower) IPv4 nets. We only probe
    # inside a /24 — /16 would be 65k IPs and pointless for our purposes.
    my @nets;
    if (open my $fh, '-|', 'ip', '-o', '-4', 'addr', 'show') {
        while (<$fh>) {
            next unless /\binet\s+(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)/;
            my ($a, $b, $c, $d, $pl) = ($1, $2, $3, $4, $5);
            next if $a == 127 || ($a == 169 && $b == 254);
            next if $pl < 24;   # skip /25+ hosts (still fine), reject /16 etc
            push @nets, ["$a.$b.$c", "$a.$b.$c.$d"];
        }
        close $fh;
    }
    return undef unless @nets;

    for my $n (@nets) {
        my ($prefix, $selfip) = @$n;
        my $sel = IO::Select->new;
        my %ipof;
        # Fire off 254 non-blocking connects. The kernel queues them; we
        # then wait for writability (== connect completion) with a budget.
        for my $h (1 .. 254) {
            last if Time::HiRes::time() >= $end;
            my $ip = "$prefix.$h";
            next if $ip eq $selfip;
            my $sock = IO::Socket::IP->new(
                PeerHost => $ip,
                PeerPort => $port,
                Proto    => 'tcp',
                Blocking => 0,
            );
            next unless $sock;
            $sel->add($sock);
            $ipof{fileno($sock)} = $ip;
        }
        my @connected;
        while ($sel->count && Time::HiRes::time() < $end) {
            my $left = $end - Time::HiRes::time();
            last if $left <= 0;
            my $wait = $left > 0.5 ? 0.5 : $left;
            my @ok = $sel->can_write($wait);
            last unless @ok;
            for my $s (@ok) {
                $sel->remove($s);
                # SO_ERROR = 0 confirms the async connect succeeded (a
                # writable non-blocking socket after a connect() call is
                # ambiguous otherwise: it may just mean "connect finished
                # with an error").
                my $err_pkt = getsockopt($s, Socket::SOL_SOCKET(),
                                            Socket::SO_ERROR());
                my $err = defined $err_pkt ? unpack('l', $err_pkt) : -1;
                if ($err == 0) {
                    push @connected, [ $ipof{fileno($s)}, $s ];
                } else {
                    close $s;
                }
            }
        }
        # Discard any pending non-connected sockets so we don't leak fds.
        for my $s ($sel->handles) { close $s; }

        # HELLO-verify candidates until first success. This filters out
        # random port-7531 responders that aren't net-mgr daemons.
        for my $c (@connected) {
            my ($ip, $sock) = @$c;
            eval { $sock->blocking(1); };
            local $\; local $,;
            print { $sock } "HELLO consumer=discover-lan.$$\n";
            my $line = _read_line_bounded($sock, 0.5);
            close $sock;
            if (defined $line && $line =~ /^OK\b/) {
                return { host => $ip, port => $port };
            }
        }
    }
    return undef;
}

# Read one \n-terminated line from $sock, bounded by $timeout seconds.
# Returns the line (sans trailing \n) on success, undef on timeout /
# error / EOF. Used only by _lan_probe — the mainline recv_line owns the
# post-connect stream.
sub _read_line_bounded {
    my ($sock, $timeout) = @_;
    require IO::Select;
    require Time::HiRes;
    my $sel = IO::Select->new($sock);
    my $end = Time::HiRes::time() + $timeout;
    my $buf = '';
    while (index($buf, "\n") < 0) {
        my $left = $end - Time::HiRes::time();
        return undef if $left <= 0;
        my @r = $sel->can_read($left);
        return undef unless @r;
        my $n = sysread($sock, my $chunk, 4096);
        return undef unless $n;
        $buf .= $chunk;
    }
    $buf =~ s/\n.*//s;
    return $buf;
}

sub send_line {
    my ($self, $line) = @_;
    my $data = "$line\n";
    utf8::encode($data) if utf8::is_utf8($data);   # wide chars -> UTF-8 bytes
    print { $self->{sock} } $data;
}

sub recv_line {
    my ($self, $timeout) = @_;
    my $sock = $self->{sock};
    while (index($self->{buf}, "\n") < 0) {
        if (defined $timeout) {
            my $vec = ''; vec($vec, fileno($sock), 1) = 1;
            my $rv = select(my $r = $vec, undef, undef, $timeout);
            return undef if $rv <= 0;
        }
        my $n = sysread($sock, my $buf, 4096);
        return undef if !defined $n || $n == 0;
        $self->{buf} .= $buf;
    }
    $self->{buf} =~ s/^([^\n]*)\n//;
    return $1;
}

# Send a line and return the next reply line. Bounded by the connection's
# timeout so a peer that accepts but never replies (e.g. a wedged proxy) can't
# hang us forever — returns undef on timeout instead.
sub send_recv {
    my ($self, $line) = @_;
    $self->send_line($line);
    return $self->recv_line($self->{timeout});
}

# Convenience: send HELLO, expect OK.
sub hello {
    my ($self, %args) = @_;
    my $r = $self->send_recv("HELLO " . format_kv(%args));
    unless (defined $r && $r =~ /^OK\b/) {
        croak "HELLO failed: "
            . (defined $r ? $r : "no reply (peer closed the connection — "
                                . "is the daemon up behind $self->{listen}?)");
    }
    $self->{greeted} = 1;
    return 1;
}

# Send OBSERVE, expect OK or ERR.
sub observe {
    my ($self, %kv) = @_;
    my $r = $self->send_recv("OBSERVE " . format_kv(%kv));
    return $r;
}

# Subscribe and collect snapshot rows up to EOS, then return arrayref of
# parsed ROW kv hashrefs. Closes the subscription afterwards (snapshot mode).
sub snapshot {
    my ($self, $sub_id, $table, %args) = @_;
    my $where = $args{where};
    my $line = "SUBSCRIBE sub=$sub_id mode=snapshot FROM $table";
    $line .= " WHERE $where" if defined $where;
    $self->send_line($line);
    my @rows;
    while (defined(my $reply = $self->recv_line)) {
        my $cmd = parse_line($reply);
        next unless $cmd;
        if    ($cmd->{verb} eq 'ROW') { push @rows, $cmd->{kv} }
        elsif ($cmd->{verb} eq 'EOS') { last }
        elsif ($cmd->{verb} eq 'ERR') { croak "snapshot: $cmd->{msg}" }
    }
    # Drain the trailing OK ack
    $self->recv_line;
    return \@rows;
}

# TRIGGER verb. With wait=>1, waits for READY.
sub trigger {
    my ($self, $name, %args) = @_;
    my $wait = delete $args{wait};
    my $line = "TRIGGER $name";
    $line .= " " . format_kv(%args) if %args;
    $line .= " WAIT" if $wait;
    $self->send_line($line);
    return $self->recv_line(60);   # generous timeout for WAIT
}

# POLL — synchronous RPC.  The daemon runs a server-whitelisted local
# script and returns its stdout as base64 in the OK reply; this
# decodes it for the caller.  Returns undef if the daemon rejected the
# verb (older build) or the name isn't whitelisted on that daemon.
sub poll {
    my ($self, $name, %args) = @_;
    my $line = "POLL $name";
    $line .= " " . format_kv(%args) if %args;
    my $r = $self->send_recv($line);
    croak "POLL $name: no reply from daemon" unless defined $r;
    my $cmd = eval { parse_line($r) } or croak "POLL $name: bad reply '$r'";
    croak "POLL $name: $cmd->{msg}" if $cmd->{verb} eq 'ERR';
    croak "POLL $name: unexpected reply '$r'" unless $cmd->{verb} eq 'OK';
    my $b64 = ($cmd->{kv} || {})->{output};
    return '' unless defined $b64;
    require MIME::Base64;
    return MIME::Base64::decode_base64($b64);
}

# Ask the daemon for one-line state. Returns a hashref of the kv
# fields from its OK reply, or undef if the daemon doesn't recognise
# the verb (older builds).
sub status {
    my ($self) = @_;
    my $r = $self->send_recv("STATUS");
    return undef unless defined $r;
    my $cmd = eval { parse_line($r) } or return undef;
    return undef unless $cmd->{verb} eq 'OK';
    return $cmd->{kv} || {};
}

# FORWARD slot=N target=IP:PORT — ask the daemon to wire its
# loopback:slot to IP:PORT for the lifetime of this connection.
# Returns the OK kv hashref ({slot, method}) or croaks on ERR.
sub forward {
    my ($self, %args) = @_;
    croak "forward needs slot=" unless defined $args{slot};
    croak "forward needs target=" unless defined $args{target};
    my $r = $self->send_recv(
        "FORWARD " . format_kv(slot => $args{slot}, target => $args{target})
    );
    croak "forward: no reply from daemon" unless defined $r;
    my $cmd = parse_line($r);
    croak "forward: $cmd->{msg}" if $cmd->{verb} eq 'ERR';
    croak "forward: unexpected reply '$r'" unless $cmd->{verb} eq 'OK';
    return $cmd->{kv} || {};
}

# UNFORWARD slot=N — release a forward early; otherwise it's freed
# automatically when the connection closes. Returns 1 on success,
# croaks on ERR.
sub unforward {
    my ($self, %args) = @_;
    croak "unforward needs slot=" unless defined $args{slot};
    my $r = $self->send_recv("UNFORWARD " . format_kv(slot => $args{slot}));
    croak "unforward: no reply from daemon" unless defined $r;
    my $cmd = parse_line($r);
    croak "unforward: $cmd->{msg}" if $cmd->{verb} eq 'ERR';
    return 1;
}

# NAT_MASQUERADE iface=NAME state=on|off [boot=1] — toggle
# MASQUERADE on POSTROUTING for an egress interface. Persistent
# (rule survives this connection's disconnect); boot=1 writes
# through to /etc/iptables (via netfilter-persistent if available).
# Returns the OK kv hashref ({iface, state, boot?}) or croaks.
sub nat_masquerade {
    my ($self, %args) = @_;
    croak "nat_masquerade needs iface=" unless defined $args{iface};
    croak "nat_masquerade needs state="
        unless defined $args{state} && $args{state} =~ /^(?:on|off)$/i;
    my %kv = (iface => $args{iface}, state => lc $args{state});
    $kv{boot} = 1 if $args{boot};
    my $r = $self->send_recv("NAT_MASQUERADE " . format_kv(%kv));
    croak "nat_masquerade: no reply from daemon" unless defined $r;
    my $cmd = parse_line($r);
    croak "nat_masquerade: $cmd->{msg}" if $cmd->{verb} eq 'ERR';
    croak "nat_masquerade: unexpected reply '$r'"
        unless $cmd->{verb} eq 'OK';
    return $cmd->{kv} || {};
}

# SET_GATEWAY action=set via=IP [dev=NAME] [metric=N]
# SET_GATEWAY action=clear        [metric=N]
# Returns the OK kv hashref or croaks on ERR.
sub set_gateway {
    my ($self, %args) = @_;
    my $action = lc($args{action} // (defined $args{via} ? 'set' : 'clear'));
    croak "set_gateway action must be 'set' or 'clear'"
        unless $action eq 'set' || $action eq 'clear';
    my %kv = (action => $action);
    if ($action eq 'set') {
        croak "set_gateway action=set requires via=IP" unless defined $args{via};
        $kv{via}    = $args{via};
        $kv{dev}    = $args{dev}    if defined $args{dev};
    }
    $kv{metric} = $args{metric} if defined $args{metric};
    my $r = $self->send_recv("SET_GATEWAY " . format_kv(%kv));
    croak "set_gateway: no reply from daemon" unless defined $r;
    my $cmd = parse_line($r);
    croak "set_gateway: $cmd->{msg}" if $cmd->{verb} eq 'ERR';
    croak "set_gateway: unexpected reply '$r'" unless $cmd->{verb} eq 'OK';
    return $cmd->{kv} || {};
}

# FORWARD_TO peer=NAME <inner verb...> — proxy a command to NAME's
# daemon via *this* connection's daemon. Returns the list of raw
# reply lines from the destination (in order, including the final
# OK/ERR). Single-hop only on the daemon side.
sub forward_to {
    my ($self, $peer, $inner_line) = @_;
    croak "forward_to needs peer" unless defined $peer && length $peer;
    croak "forward_to needs inner_line" unless defined $inner_line && length $inner_line;
    $self->send_line("FORWARD_TO peer=$peer $inner_line");
    my @lines;
    while (defined(my $line = $self->recv_line)) {
        push @lines, $line;
        last if $line =~ /^\s*(OK|ERR)\b/;
    }
    return \@lines;
}

# CLUSTER_ROLE role=master|follower|auto [member=NAME] [master=NAME]
# Loopback-only on the server side; used by net-mgr-relay to push
# elected role into the daemon so STATUS reports cluster_role
# accurately. Returns the OK kv hashref or croaks on ERR.
sub cluster_role {
    my ($self, %args) = @_;
    croak "cluster_role needs role=" unless defined $args{role};
    my %kv = (role => $args{role});
    $kv{member} = $args{member} if defined $args{member};
    $kv{master} = $args{master} if defined $args{master};
    my $r = $self->send_recv("CLUSTER_ROLE " . format_kv(%kv));
    croak "cluster_role: no reply from daemon" unless defined $r;
    my $cmd = parse_line($r);
    croak "cluster_role: $cmd->{msg}" if $cmd->{verb} eq 'ERR';
    croak "cluster_role: unexpected reply '$r'" unless $cmd->{verb} eq 'OK';
    return $cmd->{kv} || {};
}

# auth(key_id => 'me@host', key_file => '~/.ssh/id_rsa') — drive the
# AUTH / AUTH_RESPONSE handshake. Returns 1 on success or croaks
# with the daemon's error message. After success the connection is
# privileged for FORWARD/NAT_MASQUERADE/SET_GATEWAY regardless of
# source IP.
#
# key_id defaults to "$USER\@$hostname" (matching the comment ssh
# typically embeds in id_*.pub). key_file defaults to the first of
# ~/.ssh/id_ed25519, ~/.ssh/id_rsa that exists. Override either.
sub auth {
    my ($self, %args) = @_;
    my $key_id = $args{key_id} // _default_key_id();
    my $key_file = $args{key_file} // _default_key_file();
    croak "auth: no key_id"   unless defined $key_id   && length $key_id;
    croak "auth: no key_file" unless defined $key_file && -r $key_file;

    # The daemon requires a HELLO (which sets the connection kind/ident)
    # before it will accept AUTH. Send one if the caller hasn't already.
    $self->hello(consumer => $args{as} // $self->{as} // $key_id)
        unless $self->{greeted};

    # Step 1: AUTH key_id=ID  →  READY nonce=...
    $self->send_line("AUTH " . format_kv(key_id => $key_id));
    my $reply = $self->recv_line;
    croak "auth: no reply to AUTH" unless defined $reply;
    my $cmd = parse_line($reply);
    croak "auth: $cmd->{msg}" if $cmd->{verb} eq 'ERR';
    croak "auth: unexpected reply '$reply'" unless $cmd->{verb} eq 'READY';
    my $nonce = ($cmd->{kv} || {})->{nonce};
    croak "auth: READY missing nonce" unless defined $nonce && length $nonce;

    # Step 2: ssh-keygen -Y sign the nonce, send AUTH_RESPONSE.
    require File::Temp;
    require MIME::Base64;
    my $tn = File::Temp->new;
    binmode $tn; print $tn $nonce; $tn->flush;
    my $ts = File::Temp->new(SUFFIX => '.sig');
    binmode $ts;
    # ssh-keygen will block on /dev/tty for a passphrase if the key is
    # encrypted, which hangs the GUI forever (no event loop runs during the
    # system() call). Detach the controlling tty via `setsid sh -c` so /dev/tty
    # isn't usable, and cap the whole thing with `timeout` as a backstop. When
    # either tool is absent we fall back to the bare command (old behaviour) —
    # the dialog still gets a clearer error if it does hang and the user kills
    # it, vs. an unrecoverable hang.
    my $base = "ssh-keygen -q -Y sign -n net-mgr -f " . _shq($key_file)
             . " < " . _shq($tn->filename)
             . " > " . _shq($ts->filename) . " 2>/dev/null";
    my $has_timeout = -x '/usr/bin/timeout' || -x '/bin/timeout';
    my $has_setsid  = -x '/usr/bin/setsid'  || -x '/bin/setsid';
    my $sign_cmd = ($has_timeout || $has_setsid)
        ? join(' ', ($has_timeout ? ('timeout', '8') : ()),
                    ($has_setsid  ? ('setsid')      : ()),
                    'sh', '-c', _shq($base))
        : $base;
    my $rc   = system($sign_cmd);
    my $exit = $rc >> 8;
    if ($rc != 0) {
        if ($exit == 124) {
            croak "auth: ssh-keygen sign timed out (8s). Is the key "
                . "'$key_file' passphrase-protected? "
                . "Either remove the passphrase (ssh-keygen -p -f $key_file) "
                . "or load it into ssh-agent (ssh-add $key_file) before "
                . "starting net-chat.";
        }
        croak "auth: ssh-keygen sign rc=$exit (key '$key_file' — may need "
            . "an unencrypted key or ssh-agent: see ssh-add / ssh-keygen -p)";
    }
    open my $sf, '<', $ts->filename or croak "auth: open sig: $!";
    my $sig;
    { local $/; $sig = <$sf>; }
    close $sf;
    my $sig_b64 = MIME::Base64::encode_base64($sig, '');

    $self->send_line("AUTH_RESPONSE " . format_kv(sig => $sig_b64));
    my $r2 = $self->recv_line;
    croak "auth: no reply to AUTH_RESPONSE" unless defined $r2;
    my $c2 = parse_line($r2);
    croak "auth: $c2->{msg}" if $c2->{verb} eq 'ERR';
    croak "auth: unexpected reply '$r2'" unless $c2->{verb} eq 'OK';
    return 1;
}

sub _default_key_id {
    my $user = $ENV{USER} // (getpwuid($<))[0] // 'unknown';
    chomp(my $host = `hostname`);
    return "$user\@$host";
}

sub _default_key_file {
    for my $f ("ssh/id_ed25519", "ssh/id_rsa", "ssh/id_ecdsa") {
        my $p = "$ENV{HOME}/.$f";
        return $p if -r $p;
    }
    return undef;
}

sub _shq {
    my ($s) = @_;
    return "''" unless defined $s && length $s;
    return $s if $s =~ m{^[A-Za-z0-9_./=,\@:-]+$};
    (my $q = $s) =~ s/'/'\\''/g;
    return "'$q'";
}

# ---- net-chat --------------------------------------------------------
#
# Thin wrappers over the CHAT_* control verbs and OBSERVE kind=chat_msg.
# Both net-chat and the web CGI go through these so there's one code
# path. Each returns the OK kv hashref or croaks with the daemon's
# error. Reading history / listing sessions / the roster all reuse the
# generic snapshot()/SUBSCRIBE machinery against the chat_* tables.

# Internal: send a CHAT_* line, parse the reply, croak on ERR.
sub _chat_cmd {
    my ($self, $verb, %kv) = @_;
    # Carry the loopback identity on control verbs too, so session
    # ownership / membership match what the caller posts as.
    $kv{as} = $self->{as} if defined $self->{as} && !exists $kv{as};
    my $line = $verb;
    $line .= " " . format_kv(%kv) if %kv;
    my $r = $self->send_recv($line);
    croak "$verb: no reply from daemon" unless defined $r;
    my $cmd = parse_line($r);
    croak "$verb: $cmd->{msg}" if $cmd->{verb} eq 'ERR';
    croak "$verb: unexpected reply '$r'" unless $cmd->{verb} eq 'OK';
    return $cmd->{kv} || {};
}

sub chat_open {
    my ($self, %a) = @_;
    croak "chat_open needs name" unless defined $a{name};
    return $self->_chat_cmd('CHAT_OPEN',
        name => $a{name},
        (defined $a{mode}  ? (mode  => $a{mode})  : ()),
        (defined $a{topic} ? (topic => $a{topic}) : ()),
        (defined $a{vlan}  ? (vlan  => $a{vlan})  : ()));
}

sub chat_set {
    my ($self, %a) = @_;
    croak "chat_set needs name" unless defined $a{name};
    return $self->_chat_cmd('CHAT_SET',
        name => $a{name},
        (defined $a{mode}  ? (mode  => $a{mode})  : ()),
        (exists  $a{topic} ? (topic => $a{topic}) : ()),
        # vlan present (even empty) = set/clear the binding.
        (exists  $a{vlan}  ? (vlan  => $a{vlan})  : ()));
}

sub chat_close {
    my ($self, %a) = @_;
    croak "chat_close needs name" unless defined $a{name};
    return $self->_chat_cmd('CHAT_CLOSE', name => $a{name});
}

# File transfer (phase 2). Each returns the OK kv (or croaks on ERR).
sub chat_put { my ($self, %a) = @_; return $self->_chat_cmd('CHAT_PUT', %a) }
sub chat_get { my ($self, %a) = @_; return $self->_chat_cmd('CHAT_GET', %a) }
sub chat_ls  { my ($self, %a) = @_; return $self->_chat_cmd('CHAT_LS',  %a) }
sub chat_rm  { my ($self, %a) = @_; return $self->_chat_cmd('CHAT_RM',  %a) }
sub chat_keys { my ($self, %a) = @_; return $self->_chat_cmd('CHAT_KEYS', %a) }

# Owner-only, destructive: delete a chat and its whole archive.
sub chat_delete {
    my ($self, %a) = @_;
    croak "chat_delete needs name" unless defined $a{name};
    return $self->_chat_cmd('CHAT_DELETE', name => $a{name});
}

sub chat_join {
    my ($self, %a) = @_;
    croak "chat_join needs session" unless defined $a{session};
    # An optional pubkey lets an unverified ('as'-named, unauthed) user supply
    # their SSH public key with the join request. On approval the daemon binds
    # the key to the chat's authorized list and a future AUTH from the matching
    # private key auto-admits (chat-key fallthrough — no second ask). Accepts
    # either an explicit pubkey opt or $self->{as_pubkey} stashed at new() time
    # by the GUI's see-and-request flow.
    my $pk = $a{pubkey} // $self->{as_pubkey};
    my @kv = (session => $a{session});
    push @kv, pubkey => $pk if defined $pk && length $pk;
    return $self->_chat_cmd('CHAT_JOIN', @kv);
}

sub chat_leave {
    my ($self, %a) = @_;
    croak "chat_leave needs session" unless defined $a{session};
    return $self->_chat_cmd('CHAT_LEAVE', session => $a{session});
}

# Membership ops: $op is one of allow|deny|approve|reject.
sub chat_member {
    my ($self, $op, %a) = @_;
    my %verb = (allow   => 'CHAT_ALLOW',   deny    => 'CHAT_DENY',
                approve => 'CHAT_APPROVE', reject  => 'CHAT_REJECT',
                promote => 'CHAT_PROMOTE', demote  => 'CHAT_DEMOTE',
                delete  => 'CHAT_MEMBER_DELETE');
    croak "chat_member: bad op '$op'" unless $verb{$op};
    croak "chat_member needs session + principal"
        unless defined $a{session} && defined $a{principal};
    return $self->_chat_cmd($verb{$op},
        session => $a{session}, principal => $a{principal});
}

# Post a message via OBSERVE kind=chat_msg. `as` is honoured only for
# loopback connections (server stamps verified key_id otherwise).
sub chat_post {
    my ($self, %a) = @_;
    croak "chat_post needs session + body"
        unless defined $a{session} && defined $a{body};
    my %kv = (kind => 'chat_msg', session => $a{session}, body => $a{body});
    my $as = defined $a{as} ? $a{as} : $self->{as};
    $kv{as}          = $as             if defined $as;
    $kv{in_reply_to} = $a{in_reply_to} if defined $a{in_reply_to};
    my $r = $self->send_recv("OBSERVE " . format_kv(%kv));
    croak "chat_post: no reply from daemon" unless defined $r;
    my $cmd = parse_line($r);
    croak "chat_post: $cmd->{msg}" if $cmd->{verb} eq 'ERR';
    croak "chat_post: unexpected reply '$r'" unless $cmd->{verb} eq 'OK';
    return $cmd->{kv} || {};
}

# Send REPAIR, expect OK. Loopback-only on the daemon side (see
# NetMgr::Manager::_handle_repair) — this connection must be to
# 127.0.0.1 / ::1 or the daemon will refuse. Returns the raw OK reply
# line so the caller can log it verbatim; croaks on ERR (unknown action,
# prohibited by config, missing/bad iface, shell-out failure).
#
# Actions:
#   wifi_cycle      iface => IF
#   ethernet_cycle  iface => IF
#   dhcp_cycle      iface => IF
#   conn_up         name  => CONN
#   conn_down       name  => CONN
sub repair {
    my ($self, %kv) = @_;
    croak "repair needs action=<name>"
        unless defined $kv{action} && length $kv{action};
    my $line = "REPAIR " . format_kv(%kv);
    my $r = $self->send_recv($line);
    croak "REPAIR: no reply from daemon" unless defined $r;
    my $cmd = parse_line($r);
    croak "REPAIR: $cmd->{msg}" if $cmd->{verb} eq 'ERR';
    croak "REPAIR: unexpected reply '$r'" unless $cmd->{verb} eq 'OK';
    return $r;
}

# TRACEROUTE — default-allow diagnostic. Daemon runs `traceroute -n` on
# the caller's behalf and returns a per-hop TSV summary as base64 in
# `hops_b64`, alongside high-level counters (count, reached, duration_ms).
# Admission mirrors REPAIR: default open; operators tighten via [diag]
# prohibit_* keys.
#
# Args:   target => HOST_OR_IP   (required)
#         max_hops => N (1..30)  (default 15)
#         timeout_s => S (1..10) (default 2)
#         src_iface => IFACE     (optional)
# Returns a hashref: { target, count, reached, duration_ms,
#                      hops => [ { n, rtt_ms, addr }, ... ] }
# Croaks on ERR.
sub traceroute {
    my ($self, %a) = @_;
    croak "traceroute needs target=<host_or_ip>"
        unless defined $a{target} && length $a{target};
    my %kv = (target => $a{target});
    for my $k (qw(max_hops timeout_s src_iface)) {
        $kv{$k} = $a{$k} if defined $a{$k} && length $a{$k};
    }
    my $r = $self->send_recv("TRACEROUTE " . format_kv(%kv));
    croak "TRACEROUTE: no reply from daemon" unless defined $r;
    my $cmd = parse_line($r);
    croak "TRACEROUTE: $cmd->{msg}" if $cmd->{verb} eq 'ERR';
    croak "TRACEROUTE: unexpected reply '$r'" unless $cmd->{verb} eq 'OK';
    my $okv = $cmd->{kv} || {};
    my @hops;
    if (defined(my $b64 = $okv->{hops_b64})) {
        require MIME::Base64;
        my $tsv = MIME::Base64::decode_base64($b64);
        for my $line (split /\n/, $tsv) {
            next unless length $line;
            my ($n, $rtt, $addr) = split /\t/, $line, 3;
            push @hops, {
                n      => (defined $n    ? $n + 0                       : 0),
                rtt_ms => (defined $rtt && $rtt ne '-' ? ($rtt + 0) : undef),
                addr   => (defined $addr && $addr ne '-' ? $addr    : undef),
            };
        }
    }
    return {
        target      => $okv->{target}      // $a{target},
        count       => ($okv->{count}       // 0) + 0,
        reached     => ($okv->{reached}     // 0) + 0,
        duration_ms => ($okv->{duration_ms} // 0) + 0,
        hops        => \@hops,
    };
}

sub bye {
    my ($self) = @_;
    $self->send_line("BYE");
    eval { close $self->{sock} };
}

sub DESTROY {
    my ($self) = @_;
    eval { close $self->{sock} } if $self->{sock};
}

1;
