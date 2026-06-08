package NetMgr::Manager;
# Main net-mgr daemon. Listens on a TCP socket, accepts producer
# observations + subscriber connections, applies UPSERTs to MySQL,
# detects state transitions, and (in stage-2) streams matching rows
# to subscribers.
#
# Stage 1 (this module): producer side only.
#   - HELLO/OBSERVE/GONE/BYE handling
#   - DB upsert + event-logging based on change-info
#   - ERR/OK replies
#
# Stage 2 will add SUBSCRIBE/UNSUB/TRIGGER and streaming.

use strict;
use warnings;
use Carp qw(croak);
use IO::Socket::INET;
use IO::Select;
use Time::HiRes qw(time);
use FindBin ();
use POSIX ();
use NetMgr::Protocol qw(parse_line format_ok format_err format_row format_eos format_ready);
use NetMgr::Where    qw(parse eval_ast);
use NetMgr::ChatArchive ();
use NetMgr::Auth     ();
use NetMgr::Mesh     ();
use NetMgr::Election ();
use NetMgr::AutoDiscover ();

# Logical tables a SUBSCRIBE may target.
my %SUBSCRIBABLE = map { $_ => 1 } qw(
    machines hostnames interfaces addresses ports aps
    associations dhcp_leases events aliases dhcp_vars
    subnet_routers friendly_names wifi_sockets lost_devices
    peers uplinks isp_links
    forwarding_rules zone_classes interface_zones wifi_zones
    audit_annotations wifi_scan_results wifi_radio_state
    chat_sessions chat_members chat_messages chat_presence
    host_keys
);

# Tables whose contents are sensitive (credentials etc.); SUBSCRIBE
# is allowed only when the calling connection has completed AUTH.
my %SUBSCRIBABLE_AUTH = map { $_ => 1 } qw(
    isp_secrets
);

sub new {
    my ($class, %args) = @_;
    croak "config required" unless $args{config};
    croak "db required"     unless $args{db};
    my $log_fh = $args{log_fh};
    $log_fh = \*STDERR unless defined $log_fh;
    my $self = bless {
        config    => $args{config},
        db        => $args{db},
        log_fh    => $log_fh,
        listeners => {},      # fd → { sock, host, port }
        select    => undef,
        clients   => {},      # fd → { sock, source/consumer, buffer, peer }
        triggers  => {},      # pid → { cli_fd, name, started_at } pending TRIGGER WAITs
        dnsmasq_listeners => {}, # "host:port" → { sock, host, port, buffer }
        started_at => time(),    # for STATUS uptime reporting
        stop      => 0,
        auth_state => NetMgr::Auth::new_state(
            signers_path    => '/etc/net-mgr/allowed_signers',
            authorized_keys => $> == 0 ? '/root/.ssh/authorized_keys'
                                       : ((getpwuid($>))[7] // '') . '/.ssh/authorized_keys',
        ),
        # Chat-only authorization: a dedicated, lower-privilege key list.
        # A key here may use the chat verbs but gets scope='chat' — NO
        # mesh-mutation rights (FORWARD/NAT/SET_GATEWAY) and no access to
        # auth-gated tables. Independent of ~/.ssh/authorized_keys (no
        # fallback) so chat access is decoupled from SSH login, and being on
        # allowed_signers is not required (that grants far more than chat needs).
        chat_auth_state => NetMgr::Auth::new_state(
            signers_path    => '/etc/net-mgr/allowed_chat',
            authorized_keys => undef,
        ),
        version => _read_version(),
        cluster => _load_cluster_state($args{config}),
    }, $class;
    return $self;
}

# The code version reported by STATUS — the git describe string stamped
# into share/net-mgr/version at `make install` (falls back to the source
# tree's .version for from-source runs, else 'unknown').
sub _read_version {
    for my $f ('/usr/local/share/net-mgr/version',
               (__FILE__ =~ m{(.*)/lib/NetMgr/Manager\.pm$} ? "$1/.version" : ())) {
        next unless defined $f && -r $f;
        open my $fh, '<', $f or next;
        chomp(my $v = <$fh> // '');
        close $fh;
        return $v if length $v;
    }
    return 'unknown';
}

# Parse [cluster] config into a normalised state hash. Returns a
# hashref with defaults filled in even when [cluster] is absent —
# absent config means a single-node "cluster" (this host alone),
# which always has quorum and is its own master.
sub _load_cluster_state {
    my ($cfg) = @_;
    my $c = $cfg->{cluster} // {};
    my @members;
    my $auto_spec;
    if (defined $c->{members}) {
        # The directive may be a literal comma-list ("kc-qernel,nas3")
        # or an auto-discovery directive ("auto:DMZ", "auto:Private/lab",
        # bare "auto"). Auto-mode starts with an empty members list;
        # the daemon fills it in periodically via NetMgr::AutoDiscover.
        my $raw = $c->{members};
        $raw =~ s/^\s+|\s+$//g;
        if (my $spec = NetMgr::AutoDiscover::parse_spec($raw)) {
            $auto_spec = $spec;
        } else {
            @members = grep { length }
                       map  { s/^\s+|\s+$//gr }
                       split /,/, $raw;
        }
    }
    my $self_name = _local_member_name();
    my %state = (
        members          => \@members,
        auto_spec        => $auto_spec,        # undef = static members
        role             => $c->{role}        // 'auto',  # auto|master|follower|excluded
        priority         => $c->{priority}    // 100,
        prefer_lan       => exists $c->{prefer_lan} ? ($c->{prefer_lan} ? 1 : 0) : 1,
        internet_facing  => $c->{internet_facing},        # 0|1|undef (=auto)
        election_interval=> $c->{election_interval} // 60,
        self_name        => $self_name,
        is_member        => (!@members || grep { $_ eq $self_name } @members) ? 1 : 0,
        # Self-declared capabilities — this daemon's claim of what
        # it can do. Comma-separated tag list. Treated as advisory
        # by peers (each peer's local %peer_caps is authoritative
        # for what THEY grant — see _load_peer_caps).
        capabilities     => _split_caps($c->{capabilities}),
        # Local authority table: peer name → arrayref of capability
        # tags this daemon grants. Source: /etc/net-mgr/peers (or
        # the path given by [cluster] peers_file). This is THIS
        # daemon's opinion of who's allowed to do what; election
        # filters use it. Other daemons may have different opinions
        # — operator's job to keep them in sync.
        peers_file       => $c->{peers_file} // '/etc/net-mgr/peers',
        peer_caps        => _load_peer_caps($c->{peers_file}
                                            // '/etc/net-mgr/peers'),
    );
    return \%state;
}

sub _split_caps {
    my ($s) = @_;
    return [] unless defined $s && length $s;
    return [ grep { length } map { s/^\s+|\s+$//gr } split /[,\s]+/, $s ];
}

# Load /etc/net-mgr/peers (or whatever path was configured).
# Format is one peer per line, "name: cap1, cap2, ...". Lines
# starting with # are comments; blank lines are ignored. An empty
# capability list ("name:") means the peer is recognised but
# granted nothing — useful for explicitly denying all capabilities.
# Missing file = empty table (no peers granted anything; equivalent
# to a one-node deployment).
sub _load_peer_caps {
    my ($path) = @_;
    my %caps;
    return \%caps unless -r $path;
    open my $fh, '<', $path or return \%caps;
    while (my $line = <$fh>) {
        $line =~ s/[\r\n]+\z//;
        $line =~ s/\s*#.*//;
        $line =~ s/^\s+|\s+$//g;
        next unless length $line;
        if ($line =~ /^([\w.-]+)\s*:\s*(.*)$/) {
            my ($name, $rest) = ($1, $2);
            $caps{$name} = _split_caps($rest);
        }
    }
    close $fh;
    return \%caps;
}

# Identity used in cluster rosters. Hostname's first label (so the
# config can reasonably use bare names like 'kc-qernel' rather than
# fully-qualified). Override via env for testing.
sub _local_member_name {
    return $ENV{NET_MGR_CLUSTER_NAME} if defined $ENV{NET_MGR_CLUSTER_NAME};
    require Sys::Hostname;
    my $h = Sys::Hostname::hostname();
    $h =~ s/\..*//;
    return $h;
}

# ---- logging ----------------------------------------------------------
# Method named _log to avoid any collision with the `log` builtin.

sub _log {
    my ($self, $msg) = @_;
    my $fh = $self->{log_fh};
    return unless defined $fh;
    my $ts = _ts();
    print {$fh} "$ts $msg\n";
}

sub _ts {
    my @t = localtime;
    return sprintf "%04d-%02d-%02d %02d:%02d:%02d",
        $t[5]+1900, $t[4]+1, $t[3], $t[2], $t[1], $t[0];
}

# ---- listener / loop --------------------------------------------------

sub start_listener {
    my ($self) = @_;
    my $spec = $self->{config}{manager}{listen} || 'auto';
    my @binds = _resolve_listen_spec($spec);
    croak "no listen addresses resolved from '$spec'" unless @binds;

    $self->{select} = IO::Select->new;
    for my $b (@binds) {
        my $sock = IO::Socket::INET->new(
            LocalAddr => $b->{host},
            LocalPort => $b->{port},
            Listen    => 16,
            ReuseAddr => 1,
            Proto     => 'tcp',
        );
        if (!$sock) {
            $self->_log("WARN: bind $b->{host}:$b->{port} failed: $!");
            next;
        }
        my $fd = fileno($sock);
        $self->{listeners}{$fd} = { sock => $sock, host => $b->{host}, port => $b->{port} };
        $self->{select}->add($sock);
        $self->_log("listening on $b->{host}:$b->{port}");
    }
    croak "no listeners could be bound from '$spec'" unless %{ $self->{listeners} };
    $self->_start_mesh;
    return [ map { $_->{sock} } values %{ $self->{listeners} } ];
}

# Bring up the cluster mesh — one persistent outbound TCP connection
# to every other [cluster] member, sharing our IO::Select. No-op when
# the roster is empty (single-node deployment) or just contains self.
sub _start_mesh {
    my ($self) = @_;
    my $cs = $self->{cluster} || {};
    my @others = grep { $_ ne $cs->{self_name} } @{ $cs->{members} // [] };
    if (!@others && !$cs->{auto_spec}) {
        $self->_log("mesh: roster has no peers, mesh disabled");
        return;
    }
    $self->{mesh} = NetMgr::Mesh->new(
        select    => $self->{select},
        self_name => $cs->{self_name},
        members   => $cs->{members},
        log       => sub { $self->_log($_[0]) },
        # State broadcast in every outbound HEARTBEAT — kept tight so
        # peers can score us without a STATUS round-trip. Mirror the
        # CLUSTER_ROLE runtime values when set; else fall back to the
        # static [cluster] config.
        state_fn  => sub {
            my $cr = $self->{cluster_runtime} // {};
            return (
                role     => ($cr->{role}     // $cs->{role}),
                priority => $cs->{priority},
                master   => ($cr->{master_member} // ''),
                schema_v => (eval { $self->{db}->current_schema_version } // 0),
            );
        },
    );
    if ($cs->{auto_spec}) {
        $self->_log("mesh: started in auto-discovery mode ("
                  . _auto_spec_desc($cs->{auto_spec}) . ")");
        # Prime immediately so the first mesh tick has peers to dial.
        $self->_auto_discover;
        $self->{next_auto_discover} = time + 300;    # 5 min cadence
    } else {
        $self->_log("mesh: started with " . scalar(@others) . " peer(s): "
                  . join(',', @others));
    }
}

# Pull a fresh members list from NetMgr::AutoDiscover and reconcile
# Mesh's peer table. Best-effort: errors are logged and the
# previously-discovered list stays in effect.
sub _auto_discover {
    my ($self) = @_;
    my $cs = $self->{cluster} or return;
    my $spec = $cs->{auto_spec} or return;
    return unless $self->{mesh};
    my $names = eval {
        NetMgr::AutoDiscover::discover(
            db        => $self->{db},
            spec      => $spec,
            self_name => $cs->{self_name},
            log       => sub { $self->_log($_[0]) },
        );
    };
    if ($@) {
        my $e = $@; chomp $e;
        $self->_log("auto-discover failed: $e");
        return;
    }
    $self->{mesh}->set_members($names || []);
}

sub _auto_spec_desc {
    my ($s) = @_;
    my $c = $s->{zone_class};
    my $n = $s->{zone_name};
    return 'auto (no zone filter)' unless defined $c;
    return "auto:$c" . (defined $n ? "/$n" : '');
}

# Parse a manager.listen spec into a list of { host, port } entries.
# 'auto'        → every 192.168.*.* address on this host + 127.0.0.1
# 'a:p, b:p, …' → one per entry; missing port defaults to 7531
# 'a, b, …'     → ditto, port 7531 implicit
# 'host'        → single entry, port 7531
sub _resolve_listen_spec {
    my ($spec) = @_;
    my $default_port = 7531;
    my @out;
    my %seen;
    for my $tok (grep { length } map { s/^\s+|\s+$//gr } split /,/, $spec) {
        if (lc $tok eq 'auto') {
            for my $ip (_local_192_168_ips()) {
                next if $seen{"$ip:$default_port"}++;
                push @out, { host => $ip, port => $default_port };
            }
            my $lo = "127.0.0.1:$default_port";
            push @out, { host => '127.0.0.1', port => $default_port }
                unless $seen{$lo}++;
            next;
        }
        my ($host, $port) = $tok =~ /^(.+):(\d+)$/
            ? ($1, $2 + 0)
            : ($tok, $default_port);
        next if $seen{"$host:$port"}++;
        push @out, { host => $host, port => $port };
    }
    return @out;
}

# Pick the address forked producers should connect to. They run on this
# same host, so prefer 127.0.0.1 if we're listening on it (the 'auto'
# default puts loopback in the list). Otherwise fall back to the first
# bound address.
sub _child_connect_addr {
    my ($self) = @_;
    for my $l (values %{ $self->{listeners} }) {
        return "127.0.0.1:$l->{port}" if $l->{host} eq '127.0.0.1';
    }
    my ($l) = values %{ $self->{listeners} };
    return $l ? "$l->{host}:$l->{port}" : '127.0.0.1:7531';
}

# Enumerate IPv4 addresses on this host that fall under 192.168.0.0/16.
# Skips loopback. Best-effort via the `ip` command (already a hard
# dependency for the daemon's other paths).
sub _local_192_168_ips {
    my @ips;
    for my $line (`ip -br -4 addr show 2>/dev/null`) {
        chomp $line;
        my ($iface, $state, @addrs) = split ' ', $line;
        next unless defined $iface;
        next if $iface eq 'lo';
        for my $a (@addrs) {
            $a =~ s|/.*||;
            push @ips, $a if $a =~ /^192\.168\./;
        }
    }
    return @ips;
}

sub stop  { $_[0]->{stop} = 1 }

sub run {
    my ($self) = @_;
    $self->start_listener unless %{ $self->{listeners} };

    # Every connection that was joined to a chat session before the
    # last restart is gone; clear stale presence so the roster starts
    # empty (re-populated as clients CHAT_JOIN again).
    eval { $self->{db}->clear_chat_presence } if $self->{db};

    local $SIG{INT}  = sub { $self->stop };
    local $SIG{TERM} = sub { $self->stop };
    local $SIG{PIPE} = 'IGNORE';

    while (!$self->{stop}) {
        my @ready = $self->{select}->can_read(1.0);
        for my $fh (@ready) {
            my $fd = fileno($fh);
            if ($self->{listeners}{$fd}) {
                $self->_accept($self->{listeners}{$fd}{sock});
            } elsif ($self->{mesh} && $self->{mesh}->is_mesh_fd($fd)) {
                $self->{mesh}->handle_readable($fh);
            } else {
                $self->_handle_readable($fh);
            }
        }
        $self->{mesh}->tick                if $self->{mesh};
        $self->_run_election               if $self->{mesh};
        if ($self->{next_auto_discover}
            && time >= $self->{next_auto_discover}) {
            $self->_auto_discover;
            $self->{next_auto_discover} = time + 300;
        }
        $self->_reap_triggers              if %{ $self->{triggers} };
        $self->_check_periodic_triggers;
        $self->_age_out_offline;
        $self->_purge_old_events;
        $self->_check_dnsmasq_listeners;
    }
    $self->_log("shutting down");
    $self->{mesh}->shutdown if $self->{mesh};
    for my $c (values %{ $self->{clients} }) {
        eval { $c->{sock}->close };
    }
    for my $l (values %{ $self->{listeners} }) {
        eval { $l->{sock}->close };
    }
}

sub _accept {
    my ($self, $listener) = @_;
    my $cli = $listener->accept or return;
    $cli->blocking(0);
    my $peer = sprintf "%s:%d", $cli->peerhost // '?', $cli->peerport // 0;
    my $fd   = fileno($cli);
    $self->{clients}{$fd} = {
        sock     => $cli,
        peer     => $peer,
        buffer   => '',
        kind     => undef,    # 'producer' | 'consumer'
        ident    => undef,    # source=... or consumer=...
        subs     => {},       # id → { table, mode, where_ast }
        forwards => {},       # slot port → { method, target, cookie|pid }
        auth     => undef,    # { key_id, nonce_b64 } once AUTH starts;
                              # { key_id, verified=>1 } once verified
    };
    $self->{select}->add($cli);
    $self->_log("connect $peer fd=$fd");
}

sub _handle_readable {
    my ($self, $fh) = @_;
    my $fd  = fileno($fh);
    # dnsmasq event-socket listeners: handled inline (no client struct).
    for my $key (keys %{ $self->{dnsmasq_listeners} }) {
        my $L = $self->{dnsmasq_listeners}{$key};
        return $self->_handle_dnsmasq_data($key)
            if fileno($L->{sock}) == $fd;
    }
    my $cli = $self->{clients}{$fd} or return;
    my $n   = sysread($fh, my $buf, 8192);
    if (!defined $n) {
        return if $!{EAGAIN} || $!{EWOULDBLOCK};
        $self->_drop_client($fd, "read error: $!");
        return;
    }
    if ($n == 0) {
        $self->_drop_client($fd, 'eof');
        return;
    }
    $cli->{buffer} .= $buf;
    while ($cli->{buffer} =~ s/^([^\n]*)\n//) {
        my $line = $1;
        $self->_handle_line($cli, $line);
    }
}

sub _drop_client {
    my ($self, $fd, $why) = @_;
    my $cli = delete $self->{clients}{$fd} or return;
    # Drop this connection's chat presence and tell roster subscribers.
    # conn_id is the fd, so any rows this connection left behind go now.
    if ($self->{db}) {
        my $gone = eval { $self->{db}->delete_presence_for_conn($fd) } || [];
        for my $row (@$gone) {
            $self->_emit_change(table => 'chat_presence', op => 'delete', row => $row);
        }
    }
    # Tear down any port forwards this connection still owns. Same
    # rationale as for subscriptions, but FORWARDs leave kernel side-
    # effects (iptables rules, socat children) so we have to do it
    # explicitly rather than relying on hash deletion.
    if ($cli->{forwards} && %{ $cli->{forwards} }) {
        for my $slot (keys %{ $cli->{forwards} }) {
            my $f = $cli->{forwards}{$slot};
            eval { $self->_remove_forward($f) };
            $self->_log("warn: tearing down slot=$slot on disconnect failed: $@")
                if $@;
        }
    }
    $self->{select}->remove($cli->{sock});
    eval { $cli->{sock}->close };
    $self->_log("disconnect $cli->{peer} fd=$fd ($why)");
}

sub _send {
    my ($self, $cli, $line) = @_;
    return unless $cli && $cli->{sock};
    my $data = "$line\n";
    # Serialize wide chars to UTF-8 bytes before syswrite. A chat body with
    # non-ASCII (e.g. an em-dash) comes back from the DB as a Perl wide
    # string; syswrite on it not only warns "Wide character" but desyncs the
    # byte-vs-char length/offset arithmetic below and aborts the daemon.
    utf8::encode($data) if utf8::is_utf8($data);
    my $left = length $data;
    my $off  = 0;
    while ($left > 0) {
        my $n = syswrite($cli->{sock}, $data, $left, $off);
        if (!defined $n) {
            return if $!{EAGAIN} || $!{EWOULDBLOCK};
            $self->_drop_client(fileno($cli->{sock}), "write error: $!");
            return;
        }
        $left -= $n; $off += $n;
    }
}

sub _handle_line {
    my ($self, $cli, $line) = @_;

    # Intercept FORWARD_TO before parse_line — parse_line croaks on
    # unknown verbs, and this one wraps an inner command we don't want
    # this daemon to parse in its own context. Syntax:
    #   FORWARD_TO peer=NAME <verb> <args ...>
    if ($line =~ /^\s*FORWARD_TO\s+peer=(\S+)\s+(.+)$/i) {
        return $self->_handle_forward_to($cli, $1, $2);
    }

    my $cmd = eval { parse_line($line) };
    if ($@) {
        $self->_send($cli, format_err("parse: $@"));
        $self->_log("err parse from $cli->{peer}: $@");
        return;
    }
    return unless $cmd;

    my $verb = $cmd->{verb};
    if    ($verb eq 'HELLO')     { $self->_handle_hello($cli, $cmd) }
    elsif ($verb eq 'OBSERVE')   { $self->_handle_observe($cli, $cmd) }
    elsif ($verb eq 'GONE')      { $self->_handle_gone($cli, $cmd) }
    elsif ($verb eq 'SUBSCRIBE') { $self->_handle_subscribe($cli, $cmd) }
    elsif ($verb eq 'UNSUB')     { $self->_handle_unsub($cli, $cmd) }
    elsif ($verb eq 'TRIGGER')   { $self->_handle_trigger($cli, $cmd) }
    elsif ($verb eq 'POLL')      { $self->_handle_poll($cli, $cmd) }
    elsif ($verb eq 'BYE')       { $self->_drop_client(fileno($cli->{sock}), 'bye') }
    elsif ($verb eq 'STATUS')    { $self->_handle_status($cli) }
    elsif ($verb eq 'CLUSTER_ROLE') { $self->_handle_cluster_role($cli, $cmd) }
    elsif ($verb eq 'HEARTBEAT') { $self->_handle_heartbeat($cli, $cmd) }
    elsif ($verb eq 'FORWARD')   { $self->_handle_forward($cli, $cmd) }
    elsif ($verb eq 'UNFORWARD') { $self->_handle_unforward($cli, $cmd) }
    elsif ($verb eq 'NAT_MASQUERADE') { $self->_handle_nat_masquerade($cli, $cmd) }
    elsif ($verb eq 'SET_GATEWAY')    { $self->_handle_set_gateway($cli, $cmd) }
    elsif ($verb eq 'AUTH')           { $self->_handle_auth($cli, $cmd) }
    elsif ($verb eq 'AUTH_RESPONSE')  { $self->_handle_auth_response($cli, $cmd) }
    elsif ($verb eq 'CHAT_OPEN')      { $self->_handle_chat_open($cli, $cmd) }
    elsif ($verb eq 'CHAT_SET')       { $self->_handle_chat_set($cli, $cmd) }
    elsif ($verb eq 'CHAT_CLOSE')     { $self->_handle_chat_close($cli, $cmd) }
    elsif ($verb eq 'CHAT_JOIN')      { $self->_handle_chat_join($cli, $cmd) }
    elsif ($verb eq 'CHAT_LEAVE')     { $self->_handle_chat_leave($cli, $cmd) }
    elsif ($verb eq 'CHAT_ALLOW')     { $self->_handle_chat_member_op($cli, $cmd, 'allow') }
    elsif ($verb eq 'CHAT_DENY')      { $self->_handle_chat_member_op($cli, $cmd, 'deny') }
    elsif ($verb eq 'CHAT_APPROVE')   { $self->_handle_chat_member_op($cli, $cmd, 'approve') }
    elsif ($verb eq 'CHAT_REJECT')    { $self->_handle_chat_member_op($cli, $cmd, 'reject') }
    else {
        $self->_send($cli, format_err("verb $verb not handled"));
    }
}

sub _handle_status {
    my ($self, $cli) = @_;
    my @listeners = map { "$_->{host}:$_->{port}" } values %{ $self->{listeners} };
    my ($producers, $consumers, $unknown) = (0, 0, 0);
    for my $c (values %{ $self->{clients} }) {
        my $k = $c->{kind} // '';
        if    ($k eq 'producer') { $producers++ }
        elsif ($k eq 'consumer') { $consumers++ }
        else                     { $unknown++ }
    }
    my $schema_v = eval { $self->{db}->current_schema_version } // 0;
    my $cs = $self->{cluster} // {};
    # Runtime role override pushed by net-mgr-relay's election. When
    # set, it wins over the static [cluster] role in the config — that
    # static value is the *eligibility* declaration (auto/master/
    # follower/excluded), this is what was actually elected.
    my $cr = $self->{cluster_runtime} // {};
    my $live_role = $cr->{role} // $cs->{role};
    my $internet_facing = defined $cs->{internet_facing}
                        ? ($cs->{internet_facing} ? 1 : 0)
                        : _detect_internet_facing();
    # Reachable count: self is always reachable + however many
    # cluster mesh peers have a live connection or recent heartbeat.
    # Falls back to 1 when no mesh (single-node deployment).
    my $roster_n = scalar @{ $cs->{members} // [] };
    my $mesh_reach = $self->{mesh} ? $self->{mesh}->reachable : 0;
    my $reachable = 1 + $mesh_reach;
    my $quorum_ok = ($roster_n <= 1) ? 1
                                     : ($reachable >= int($roster_n / 2) + 1);
    my $mesh_summary = $self->{mesh} ? $self->{mesh}->summary : '';
    $self->_send($cli, format_ok(
        version            => $self->{version} // 'unknown',
        started_at         => $self->{started_at},
        now                => time(),
        listeners          => join(',', sort @listeners),
        clients            => scalar(keys %{ $self->{clients} }),
        producers          => $producers,
        consumers          => $consumers,
        unknown            => $unknown,
        triggers_pending   => scalar(keys %{ $self->{triggers} }),
        schema_version     => $schema_v,
        cluster_member     => $cs->{self_name},
        cluster_role       => $live_role,
        cluster_role_config => $cs->{role},
        cluster_role_reason => $cr->{reason} // '',
        cluster_master     => $cr->{master_member} // '',
        cluster_master_addr=> ($cr->{master_member} && $self->{mesh})
                              ? $self->{mesh}->address_for($cr->{master_member})
                              : '',
        cluster_role_since => $cr->{since}         // 0,
        cluster_priority   => $cs->{priority},
        cluster_prefer_lan => $cs->{prefer_lan},
        cluster_internet_facing => $internet_facing,
        # Static config roster (empty in auto mode); see cluster_mesh
        # for the live mesh roster discovered at runtime.
        cluster_members    => join(',', @{ $cs->{members} // [] }),
        # Auto-discovery directive when [cluster] members is auto:…;
        # empty when the operator passed a static comma list.
        cluster_auto_spec  => $cs->{auto_spec} ? _auto_spec_desc($cs->{auto_spec}) : '',
        # Whether THIS daemon's local peer_caps table is gating
        # eligibility (and how many entries it has) — the most
        # frequent reason role stays 'auto' in a healthy mesh.
        cluster_peer_caps_active =>
            scalar(keys %{ $cs->{peer_caps} // {} }) ? 1 : 0,
        cluster_is_member  => $cs->{is_member},
        # Self-declared (advisory; consumers may verify against
        # their own peer_caps table before trusting it).
        cluster_capabilities => join(',', @{ $cs->{capabilities} // [] }),
        # Count of entries in this daemon's local /etc/net-mgr/peers
        # table — operators can spot-check that peers agree on roster
        # size and authority spread.
        cluster_peer_auth_count => scalar(keys %{ $cs->{peer_caps} // {} }),
        reachable_members  => $reachable,
        quorum_ok          => $quorum_ok,
        cluster_mesh       => $mesh_summary,
    ));
}

# Re-evaluate who should be master. Called every main-loop iteration
# (cheap: a small in-memory sort + a hash compare). Updates
# $self->{cluster_runtime} whenever the decision changes, and logs.
# This makes the daemon's own election authoritative — the older
# 60s-tick election in net-mgr-relay is now redundant (it still runs
# and pushes CLUSTER_ROLE, but its value gets overwritten almost
# immediately by the next election here).
sub _run_election {
    my ($self) = @_;
    my $cs = $self->{cluster} // {};
    # Eligible to elect when we have either a static roster OR an
    # auto-discovery directive in effect. Without that, this is a
    # single-node deploy with no cluster intent — leave role alone.
    return unless @{ $cs->{members} // [] } || $cs->{auto_spec};

    # When deciding, treat *self* as 'auto' (eligible) regardless of
    # what the runtime override currently says — otherwise once we
    # demote ourselves to follower we can never re-promote even if
    # the master goes away.  The static [cluster] role value is what
    # configured eligibility looks like; runtime is just the latest
    # decision.
    my $self_role_for_decide = $cs->{role};
    $self_role_for_decide = 'auto'
        if $self_role_for_decide && $self_role_for_decide eq 'follower'
        && (!$self->{cluster_runtime}
            || ($self->{cluster_runtime}{role} // '') ne 'follower');
    my $decision = NetMgr::Election::decide(
        self_name  => $cs->{self_name},
        self_state => {
            role            => $self_role_for_decide,
            priority        => $cs->{priority},
            prefer_lan      => $cs->{prefer_lan},
            internet_facing => defined $cs->{internet_facing}
                             ? $cs->{internet_facing}
                             : _detect_internet_facing(),
        },
        mesh_snap => $self->{mesh}->snapshot,
        peer_caps => $cs->{peer_caps},
        # In auto-discovery mode there is no known "expected
        # cluster size" — we only know what's reachable right now.
        # Quorum's job is split-brain detection ("I can see N of
        # M, am I isolated?"), which is meaningless without M.
        # Skip the roster_n arg so decide() defaults to reachable
        # count and quorum trivially passes. Static-list mode
        # still uses the configured size, where split-brain is
        # detectable.
        ($cs->{auto_spec}
            ? ()
            : (roster_n => scalar @{ $cs->{members} })),
    );

    my $cur = $self->{cluster_runtime} // {};
    my $cur_key = ($cur->{role}          // '') . '|'
                . ($cur->{master_member} // '');
    my $new_key = $decision->{role} . '|' . $decision->{master_member};
    return if $cur_key eq $new_key;
    $self->{cluster_runtime} = {
        role          => $decision->{role},
        master_member => $decision->{master_member},
        since         => time(),
        reason        => $decision->{reason},
    };
    $self->_log("election: $decision->{reason} → role=$decision->{role} "
              . "master=" . ($decision->{master_member} || '-')
              . " quorum=$decision->{reachable}/$decision->{roster_n}");
}

# FORWARD_TO peer=NAME <inner verb...>
# — proxy the inner command to NAME's daemon, pump replies back
# verbatim. Single-hop only (the inner request goes out tagged with
# hop=1, and the destination's HELLO handler records that so it
# refuses to FORWARD_TO again).
#
# Synchronous: blocks the daemon's run loop until the inner exchange
# completes (or the per-line timeout fires). Acceptable v1 for
# single-reply verbs and snapshot subscriptions on a LAN. Streaming
# subscriptions through forwarding aren't supported — the destination
# would keep sending ROW lines indefinitely and we'd never know to
# stop reading.
sub _handle_forward_to {
    my ($self, $cli, $peer, $inner) = @_;
    if (($cli->{hop} // 0) > 0) {
        return $self->_send($cli,
            format_err("FORWARD_TO: nested forwarding rejected (hop=$cli->{hop})"));
    }
    # Pick the destination address. Prefer a live mesh socket's
    # peerhost — that's a peer we've already proved we can reach.
    # Fall back to "name:7531" and let the kernel resolve.
    my $addr = '';
    $addr = $self->{mesh}->address_for($peer) if $self->{mesh};
    $addr = "$peer:7531" unless length $addr;
    my ($host, $port) = split /:/, $addr, 2;
    $port = ($port && $port =~ /^\d+$/) ? $port + 0 : 7531;

    my $sock = IO::Socket::INET->new(
        PeerAddr => $host,
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    );
    if (!$sock) {
        return $self->_send($cli,
            format_err("FORWARD_TO: connect $addr failed: $!"));
    }

    my $orig_ident = $cli->{ident} // 'anon';
    eval {
        syswrite($sock, "HELLO consumer=fwd:$orig_ident hop=1\n");
        my $hello_reply = _read_one_line($sock, 5);
        die "HELLO failed: " . ($hello_reply // 'no reply') . "\n"
            unless $hello_reply && $hello_reply =~ /^OK\b/;

        syswrite($sock, "$inner\n");

        # Pump reply lines. End on OK or ERR at line start — single-
        # reply verbs (STATUS, OBSERVE, POLL, TRIGGER) reply with one
        # such line; snapshot subscriptions emit ROW…ROW…EOS then
        # an OK ack we use as the stop signal.
        while (defined(my $line = _read_one_line($sock, 60))) {
            $self->_send($cli, $line);
            last if $line =~ /^\s*(OK|ERR)\b/;
        }
    };
    if ($@) {
        my $err = $@; chomp $err;
        $self->_send($cli, format_err("FORWARD_TO: $err"));
    }
    eval { close $sock };
    return;
}

# Small synchronous line reader for FORWARD_TO. Returns the next \n-
# terminated line (without the newline) or undef on timeout/eof.
# Uses a per-socket buffer attached to the file handle via Perl's
# fileno-keyed hash so a multi-line reply isn't chopped between
# reads.
my %_fwd_bufs;
sub _read_one_line {
    my ($sock, $timeout) = @_;
    my $fd = fileno($sock);
    $_fwd_bufs{$fd} //= '';
    while (1) {
        if ($_fwd_bufs{$fd} =~ s/^([^\n]*)\n//) {
            my $line = $1;
            return $line;
        }
        my $vec = ''; vec($vec, $fd, 1) = 1;
        my $rv = select(my $r = $vec, undef, undef, $timeout);
        if ($rv <= 0) {
            delete $_fwd_bufs{$fd};
            return undef;
        }
        my $n = sysread($sock, my $chunk, 4096);
        if (!defined $n || $n == 0) {
            delete $_fwd_bufs{$fd};
            return undef;
        }
        $_fwd_bufs{$fd} .= $chunk;
    }
}

# Inbound HEARTBEAT from a peer over its outbound mesh socket — the
# *receiving* daemon's side. We trust the `member=` field as the
# sender's self-identification (cluster member names are how the
# roster is keyed; spoofing requires presence on the bound iface,
# which is a separate threat model). Updates the local mesh state
# table so STATUS can surface "what does X think they are".
#
# No OK reply — heartbeats are fire-and-forget so neither side
# blocks on the other's processing latency. The mesh's own retry
# logic handles drops.
sub _handle_heartbeat {
    my ($self, $cli, $cmd) = @_;
    return unless $self->{mesh};
    my $kv = $cmd->{kv} || {};
    my $member = $kv->{member};
    return unless defined $member && length $member;
    $self->{mesh}->record($member, $kv);
}

# Loopback-only control verb. net-mgr-relay calls this after its
# election picks a winner so STATUS starts reporting cluster_role
# accurately to the rest of the cluster.
#
#   CLUSTER_ROLE role=master|follower|auto member=NAME [master=NAME]
#
# 'member' is the role-bearer's own member name (sanity-checked
# against cluster.self_name). 'master' is the elected master's name
# — required on role=follower, ignored on role=master (the role
# bearer is the master), cleared on role=auto.
#
# Restricted to loopback peers; the relay always runs on the same
# host as the daemon. Any other peer trying to assert cluster role
# is ignored.
sub _handle_cluster_role {
    my ($self, $cli, $cmd) = @_;
    unless (_peer_is_loopback($cli)) {
        return $self->_send($cli,
            format_err("CLUSTER_ROLE restricted to loopback peers"));
    }
    my $kv = $cmd->{kv} || {};
    my $role = lc($kv->{role} // '');
    unless ($role =~ /^(master|follower|auto)$/) {
        return $self->_send($cli,
            format_err("CLUSTER_ROLE: role must be master|follower|auto"));
    }
    my $cs = $self->{cluster} // {};
    if (defined $kv->{member} && length $kv->{member}
        && defined $cs->{self_name} && $kv->{member} ne $cs->{self_name}) {
        return $self->_send($cli, format_err(
            "CLUSTER_ROLE: member='$kv->{member}' != self_name='$cs->{self_name}'"));
    }
    my $master = $kv->{master};
    if ($role eq 'master') {
        $master = $cs->{self_name};
    } elsif ($role eq 'auto') {
        $master = '';
    } else {
        return $self->_send($cli,
            format_err("CLUSTER_ROLE role=follower needs master=NAME"))
            unless defined $master && length $master;
    }
    $self->{cluster_runtime} = {
        role          => $role,
        master_member => $master,
        since         => time(),
    };
    $self->_log("cluster_role=$role"
              . ($master ? " master=$master" : '')
              . " (set by $cli->{peer})");
    return $self->_send($cli, format_ok(
        role   => $role,
        master => ($master // ''),
        since  => $self->{cluster_runtime}{since},
    ));
}

# Heuristic: this host has an "internet-facing" default route if any
# default route's egress iface name looks like a USB/PCIe NIC the
# operator typically wires to a modem (enxXXXX, enpXsY, eth-USB-ish).
# Returns 1 if internet-facing detected, 0 if not. Operator can
# override via [cluster] internet_facing = 0|1.
sub _detect_internet_facing {
    open my $fh, '-|', 'ip', '-o', '-4', 'route', 'show', 'default'
        or return 0;
    my $internet = 0;
    while (my $line = <$fh>) {
        # default via X.X.X.X dev IFACE ...
        if ($line =~ /\bdev\s+(\S+)/) {
            my $iface = $1;
            # Common patterns for USB-ethernet / NIC-on-PCIe / generic
            # ethernet that operators use to connect to a modem.
            $internet = 1 if $iface =~ /^(enx|enp\d+s|eth\d|wlp)/;
        }
    }
    close $fh;
    return $internet;
}

sub _handle_hello {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    if ($kv->{source}) {
        $cli->{kind} = 'producer'; $cli->{ident} = $kv->{source};
    } elsif ($kv->{consumer}) {
        $cli->{kind} = 'consumer'; $cli->{ident} = $kv->{consumer};
    } else {
        return $self->_send($cli, format_err("HELLO needs source= or consumer="));
    }
    # hop=N marks a forwarded request — block transitive FORWARD_TO.
    # Mesh is single-hop by design.
    $cli->{hop} = ($kv->{hop} // 0) + 0;
    $self->_log("hello $cli->{peer} $cli->{kind}=$cli->{ident}"
              . ($cli->{hop} ? " hop=$cli->{hop}" : ''));
    $self->_send($cli, format_ok());
}

# ---- SUBSCRIBE / UNSUB ------------------------------------------------

sub _handle_subscribe {
    my ($self, $cli, $cmd) = @_;
    my $sub   = $cmd->{sub};
    my $mode  = $cmd->{mode};
    my $table = $cmd->{table};
    my $where = $cmd->{where};
    return $self->_send($cli, format_err("unknown table '$table'"))
        unless $SUBSCRIBABLE{$table} || $SUBSCRIBABLE_AUTH{$table};
    if ($SUBSCRIBABLE_AUTH{$table} && !$self->_auth_is_full($cli)) {
        return $self->_send($cli,
            format_err("table '$table' requires full-scope AUTH (or loopback peer)"));
    }

    my $where_ast = eval { NetMgr::Where::parse($where) };
    if ($@) {
        my $err = $@; chomp $err;
        return $self->_send($cli, format_err("WHERE: $err"));
    }

    $cli->{subs}{$sub} = {
        table     => $table,
        mode      => $mode,
        where_ast => $where_ast,
    };
    $self->_log("subscribe $cli->{ident} sub=$sub mode=$mode FROM $table"
              . (defined $where ? " WHERE $where" : ''));

    # Snapshot phase. For tables with a `ts` column (events) we look
    # for a `ts > ago(N)` lower bound in the WHERE clause and push it
    # to SQL, so a windowed snapshot doesn't have to load the entire
    # ping history into Perl just to filter it out.
    if ($mode eq 'snapshot' || $mode eq 'snapshot+stream') {
        my %qopts;
        if (my $bound = _extract_ts_lower_bound($where_ast)) {
            $qopts{since_epoch} = $bound;
        }
        # Guard the DB call so a bug in query_table (missed allowlist
        # entry, etc.) doesn't unwind out of the main loop and kill
        # the daemon. Report as an ERR and drop the subscription;
        # next connection isn't affected.
        my $rows = eval { $self->{db}->query_table($table, %qopts) };
        if ($@) {
            my $e = $@; chomp $e;
            $self->_log("err snapshot $table from $cli->{ident}: $e");
            delete $cli->{subs}{$sub};
            return $self->_send($cli, format_err("snapshot $table: $e"));
        }
        for my $row (@$rows) {
            next if $where_ast && !eval_ast($where_ast, _row_for_match($row));
            $self->_send($cli, format_row($sub, $table, 'snapshot', %$row));
        }
        $self->_send($cli, format_eos($sub));
    }

    # If snapshot-only, drop the subscription so we don't stream.
    if ($mode eq 'snapshot') {
        delete $cli->{subs}{$sub};
    }

    $self->_send($cli, format_ok(sub => $sub));
}

sub _handle_unsub {
    my ($self, $cli, $cmd) = @_;
    my $sub = $cmd->{sub};
    if (delete $cli->{subs}{$sub}) {
        $self->_log("unsub $cli->{ident} sub=$sub");
        $self->_send($cli, format_ok(sub => $sub));
    } else {
        $self->_send($cli, format_err("no such subscription sub=$sub"));
    }
}

# ---- FORWARD / UNFORWARD --------------------------------------------
#
# Wires a local-loopback port (the laptop end of an ssh -L tunnel)
# to a LAN target by installing an iptables OUTPUT-chain DNAT rule
# (or a socat process if iptables is unavailable). Forwards live for
# the duration of the connection that requested them; on disconnect,
# every still-installed forward is torn down.
#
# Authorisation: by default, only loopback peers (127.0.0.1) may
# FORWARD. The laptop usually reaches the daemon by tunnelling an
# extra -L through ssh terminating at the daemon host, so its source
# from sshd's POV is 127.0.0.1.
#
# When the daemon host is NOT the ssh entry-point — e.g., the laptop
# logs into zmc1 but the daemon is on nas3, with the laptop's tunnel
# `-L 7531:nas3.grfx.com:7531` — connections from the daemon's POV
# come from zmc1's LAN IP, not loopback. Set
#   [forward]
#   allow_peers = 192.168.15.0/24, 192.168.223.0/24
# in the daemon config to permit those peers. Loopback is always
# allowed regardless of config.

sub _handle_forward {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};

    return $self->_send($cli, format_err("FORWARD requires HELLO first"))
        unless defined $cli->{kind};
    return $self->_send($cli,
        format_err("FORWARD peer not permitted (need AUTH or loopback; "
                 . "see [forward] allow_peers for IP-based legacy access)"))
        unless $self->_peer_may_mutate($cli);

    my $slot = $kv->{slot};
    my $tgt  = $kv->{target};
    return $self->_send($cli, format_err("FORWARD requires slot=PORT"))
        unless defined $slot && $slot =~ /^\d+$/ && $slot >= 1 && $slot <= 65535;
    return $self->_send($cli, format_err("FORWARD requires target=IP:PORT"))
        unless defined $tgt && $tgt =~ /^(\d+\.\d+\.\d+\.\d+):(\d+)$/;
    my ($tip, $tport) = ($1, $2);
    return $self->_send($cli, format_err("bad target port $tport"))
        unless $tport >= 1 && $tport <= 65535;

    # Replace any existing forward on the same slot for this connection.
    if (my $old = delete $cli->{forwards}{$slot}) {
        eval { $self->_remove_forward($old) };
        $self->_log("warn: replacing slot=$slot remove-old failed: $@") if $@;
    }

    my $f = eval {
        $self->_install_forward(
            slot   => $slot + 0,
            target => "$tip:$tport",
            owner  => $cli->{ident} // 'anon',
            fd     => fileno($cli->{sock}),
        );
    };
    if ($@ || !$f) {
        my $msg = $@ // 'install failed';
        $msg =~ s/\s+at\s+\S+\s+line\s+\d+\.?$//;
        return $self->_send($cli, format_err("FORWARD failed: $msg"));
    }

    $cli->{forwards}{$slot} = $f;
    $self->_log("forward $cli->{ident} slot=$slot → $tip:$tport via $f->{method}");
    $self->_send($cli, format_ok(slot => $slot, method => $f->{method}));
}

sub _handle_unforward {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my $slot = $kv->{slot};
    return $self->_send($cli, format_err("UNFORWARD requires slot=PORT"))
        unless defined $slot && $slot =~ /^\d+$/;
    my $f = delete $cli->{forwards}{$slot}
        or return $self->_send($cli, format_err("no such forward slot=$slot"));
    eval { $self->_remove_forward($f) };
    if ($@) {
        my $msg = $@; $msg =~ s/\s+at\s+\S+\s+line\s+\d+\.?$//;
        return $self->_send($cli, format_err("UNFORWARD: $msg"));
    }
    $self->_log("unforward $cli->{ident} slot=$slot");
    $self->_send($cli, format_ok(slot => $slot));
}

# ---- NAT_MASQUERADE -------------------------------------------------
#
# Install or remove an iptables MASQUERADE rule on the daemon host's
# nat POSTROUTING chain, scoped to the named egress interface. Used
# by net-set to make a candidate gateway routing-ready before we flip
# clients onto it.
#
#   NAT_MASQUERADE iface=enp4s0 state=on  [boot=1]
#   NAT_MASQUERADE iface=enp4s0 state=off
#
# Idempotent: state=on with the rule already present is a no-op
# (returns OK). state=off with no marked rule for that iface is also
# a no-op. boot=1 also writes through to /etc/iptables/rules.v4 (or
# netfilter-persistent save) so the rule survives reboot; OK reply
# notes which mechanism was used.
#
# Authorisation: same as FORWARD (loopback always allowed; off-host
# peers gated by [forward] allow_peers). MASQUERADE on an outbound
# interface doesn't expose anything inbound, so persistence is the
# default (no per-connection cleanup).

sub _handle_nat_masquerade {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};

    return $self->_send($cli, format_err("NAT_MASQUERADE requires HELLO first"))
        unless defined $cli->{kind};
    return $self->_send($cli,
        format_err("NAT_MASQUERADE peer not permitted (need AUTH or loopback; "
                 . "see [forward] allow_peers for IP-based legacy access)"))
        unless $self->_peer_may_mutate($cli);

    my $iface = $kv->{iface};
    my $state = lc($kv->{state} // '');
    my $boot  = $kv->{boot} ? 1 : 0;
    return $self->_send($cli, format_err("NAT_MASQUERADE requires iface=NAME"))
        unless defined $iface && $iface =~ /^[A-Za-z0-9._-]+$/;
    return $self->_send($cli, format_err("NAT_MASQUERADE state must be 'on' or 'off'"))
        unless $state eq 'on' || $state eq 'off';

    return $self->_send($cli, format_err("iptables not available on this host"))
        unless _have_cmd('iptables');

    my $cookie = "net-mgr:masq:$iface";
    my $present = _masq_rule_present($iface, $cookie);

    my $boot_msg;
    if ($state eq 'on') {
        unless ($present) {
            my @cmd = ('iptables', '-t', 'nat', '-A', 'POSTROUTING',
                       '-o', $iface,
                       '-m', 'comment', '--comment', $cookie,
                       '-j', 'MASQUERADE');
            my $rc = system(@cmd);
            if ($rc != 0) {
                return $self->_send($cli,
                    format_err("iptables install rc=" . ($rc >> 8)));
            }
            $self->_log("nat_masquerade $cli->{ident} iface=$iface ON");
        }
        $boot_msg = $self->_persist_iptables if $boot;
    } else {
        # state=off — remove every rule with our marker for this iface.
        my $removed = 0;
        while (_masq_rule_present($iface, $cookie)) {
            my @cmd = ('iptables', '-t', 'nat', '-D', 'POSTROUTING',
                       '-o', $iface,
                       '-m', 'comment', '--comment', $cookie,
                       '-j', 'MASQUERADE');
            my $rc = system(@cmd);
            last if $rc != 0;
            $removed++;
        }
        $self->_log("nat_masquerade $cli->{ident} iface=$iface OFF removed=$removed")
            if $removed;
        $boot_msg = $self->_persist_iptables if $boot;
    }

    my %ok = (iface => $iface, state => $state);
    $ok{boot} = $boot_msg if defined $boot_msg;
    $self->_send($cli, format_ok(%ok));
}

# Returns 1 if a POSTROUTING rule with our marker for $iface exists.
sub _masq_rule_present {
    my ($iface, $cookie) = @_;
    open my $fh, '-|', 'iptables', '-t', 'nat', '-S', 'POSTROUTING'
        or return 0;
    my $hit = 0;
    while (my $line = <$fh>) {
        if ($line =~ /-o \Q$iface\E\b/
         && $line =~ /\Q$cookie\E/
         && $line =~ /-j MASQUERADE/) {
            $hit = 1; last;
        }
    }
    close $fh;
    return $hit;
}

# Try the common Debian/Ubuntu persistence mechanisms in order.
# Returns a short string describing what was used, suitable for the
# OK reply's boot=... field.
sub _persist_iptables {
    my ($self) = @_;
    if (_have_cmd('netfilter-persistent')) {
        my $rc = system('netfilter-persistent', 'save');
        return $rc == 0 ? 'netfilter-persistent'
                        : 'netfilter-persistent-failed';
    }
    if (-d '/etc/iptables' && _have_cmd('iptables-save')) {
        my $tmp = '/etc/iptables/rules.v4.tmp';
        my $rc  = system("iptables-save > $tmp && mv $tmp /etc/iptables/rules.v4");
        return $rc == 0 ? 'iptables-save->/etc/iptables/rules.v4'
                        : 'iptables-save-failed';
    }
    return 'no-mechanism';
}

# ---- SET_GATEWAY ----------------------------------------------------
#
# Install (or remove) a low-metric default route on the daemon host.
# The strategy is to leave whatever default route DHCP gave us in
# place and add a competing one at metric=1; the kernel always picks
# the lowest-metric default, so traffic switches to ours immediately.
# To revert, remove the metric=1 entry — DHCP's default takes back
# over with no need to touch dhclient/networkd state.
#
#   SET_GATEWAY action=set via=IP [dev=NAME] [metric=1]
#   SET_GATEWAY action=clear         [metric=1]
#
# Idempotent. action=set replaces any prior route at the same metric
# (we own that metric for this purpose). Authorisation is the same
# as FORWARD: loopback always allowed; off-host gated by
# [forward] allow_peers.

sub _handle_set_gateway {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};

    return $self->_send($cli, format_err("SET_GATEWAY requires HELLO first"))
        unless defined $cli->{kind};
    return $self->_send($cli,
        format_err("SET_GATEWAY peer not permitted (need AUTH or loopback; "
                 . "see [forward] allow_peers for IP-based legacy access)"))
        unless $self->_peer_may_mutate($cli);

    return $self->_send($cli, format_err("ip(8) not available on this host"))
        unless _have_cmd('ip');

    my $action = lc($kv->{action} // 'set');
    my $metric = $kv->{metric} // 1;
    return $self->_send($cli, format_err("metric must be 0..4294967295"))
        unless $metric =~ /^\d+$/ && $metric <= 4294967295;

    if ($action eq 'clear') {
        # Remove every default route at this metric (typically just one).
        # Loop because successive `ip route del` may match siblings.
        my $removed = 0;
        for (1..8) {
            my $rc = system('ip', 'route', 'del', 'default',
                            'metric', $metric);
            last if $rc != 0;       # nothing left to delete
            $removed++;
        }
        $self->_log("set_gateway $cli->{ident} CLEAR metric=$metric removed=$removed");
        return $self->_send($cli, format_ok(action => 'clear',
                                            metric => $metric,
                                            removed => $removed));
    }

    if ($action ne 'set') {
        return $self->_send($cli,
            format_err("SET_GATEWAY action must be 'set' or 'clear'"));
    }

    my $via = $kv->{via};
    return $self->_send($cli, format_err("SET_GATEWAY action=set requires via=IP"))
        unless defined $via && $via =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
    my $dev = $kv->{dev};
    return $self->_send($cli, format_err("dev must be A-Za-z0-9._-"))
        if defined $dev && $dev !~ /^[A-Za-z0-9._-]+$/;

    # Replace any existing route we own at this metric (idempotent).
    system('ip', 'route', 'del', 'default', 'metric', $metric);   # may fail; OK

    my @cmd = ('ip', 'route', 'add', 'default', 'via', $via,
               'metric', $metric);
    push @cmd, 'dev', $dev if defined $dev;
    my $rc = system(@cmd);
    if ($rc != 0) {
        return $self->_send($cli,
            format_err("ip route add rc=" . ($rc >> 8)));
    }
    $self->_log("set_gateway $cli->{ident} SET via=$via dev="
              . ($dev // 'auto') . " metric=$metric");
    $self->_send($cli, format_ok(
        action => 'set', via => $via,
        dev    => ($dev // 'auto'),
        metric => $metric,
    ));
}

# ---- AUTH / AUTH_RESPONSE -------------------------------------------
#
# SSH-key client authentication via OpenSSH's SSHSIG scheme. See
# NetMgr::Auth for the verification mechanics. Workflow:
#
#   client → AUTH key-id=ID
#   server → READY nonce=base64
#   client → AUTH_RESPONSE sig=base64(armored sshsig)
#   server → OK key-id=ID  (or ERR ...)
#
# After OK, $cli->{auth} = { key_id => ID, verified => 1 } and
# privileged verbs (FORWARD, NAT_MASQUERADE, SET_GATEWAY) accept the
# connection regardless of source IP. Without auth, the legacy
# loopback-or-allow_peers IP check still applies.
#
# The nonce is per-connection and one-shot — once consumed by an
# AUTH_RESPONSE (success or failure), it's cleared. The client must
# AUTH again to retry.

sub _handle_auth {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my $key_id = $kv->{key_id};
    return $self->_send($cli, format_err("AUTH requires key_id="))
        unless defined $key_id && length $key_id;
    return $self->_send($cli, format_err("AUTH requires HELLO first"))
        unless defined $cli->{kind};
    my $nonce = NetMgr::Auth::fresh_nonce();
    $cli->{auth} = { key_id => $key_id, nonce => $nonce, verified => 0 };
    $self->_send($cli, format_ready(nonce => $nonce, key_id => $key_id));
}

sub _handle_auth_response {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my $sig = $kv->{sig};
    my $auth = $cli->{auth};
    unless (defined $auth && defined $auth->{nonce} && !$auth->{verified}) {
        return $self->_send($cli,
            format_err("AUTH_RESPONSE without prior AUTH"));
    }
    return $self->_send($cli, format_err("AUTH_RESPONSE requires sig="))
        unless defined $sig && length $sig;

    # Tier 1: the full allowlist (allowed_signers + authorized_keys) grants
    # scope='full' — mesh mutation + chat + auth-gated reads. Tier 2: the
    # chat-only allowlist (allowed_chat) grants scope='chat'. verify() is
    # stateless w.r.t. the nonce, so trying both with the same nonce is safe.
    my ($ok, $err) = NetMgr::Auth::verify(
        $self->{auth_state}, $auth->{key_id}, $auth->{nonce}, $sig);
    my $scope = 'full';
    if (!$ok) {
        my ($cok, $cerr) = NetMgr::Auth::verify(
            $self->{chat_auth_state}, $auth->{key_id}, $auth->{nonce}, $sig);
        if ($cok) { $ok = 1; $scope = 'chat'; }
        else      { $err = $cerr // $err; }
    }
    # Always invalidate the nonce — one-shot regardless of outcome.
    delete $auth->{nonce};
    if (!$ok) {
        $cli->{auth} = undef;
        $self->_log("auth FAIL $cli->{peer} key-id=$auth->{key_id}: $err");
        return $self->_send($cli, format_err("AUTH failed: $err"));
    }
    $cli->{auth} = { key_id => $auth->{key_id}, verified => 1, scope => $scope };
    $self->_log("auth OK $cli->{peer} key_id=$auth->{key_id} scope=$scope");
    $self->_send($cli, format_ok(key_id => $auth->{key_id}, scope => $scope));
}

# True if this connection is allowed to mutate (FORWARD,
# NAT_MASQUERADE, SET_GATEWAY). Loopback peers always allowed;
# verified-auth connections always allowed regardless of source IP;
# otherwise fall through to the legacy allow_peers IP check.
# True iff the connection holds FULL-scope authority — a loopback peer, or
# an auth'd connection whose key is on allowed_signers/authorized_keys
# (scope='full'). Required for mesh mutation, ISP secrets, and peer-authority
# changes. A chat-only connection (scope='chat', from allowed_chat) is
# verified but NOT full, so it is excluded from every privileged op below.
sub _auth_is_full {
    my ($self, $cli) = @_;
    return 1 if _peer_is_loopback($cli);
    return 1 if $cli->{auth} && $cli->{auth}{verified}
             && ($cli->{auth}{scope} // 'full') eq 'full';
    return 0;
}

sub _peer_may_mutate {
    my ($self, $cli) = @_;
    return 1 if $self->_auth_is_full($cli);
    return $self->_peer_may_forward($cli);
}

sub _peer_is_loopback {
    my ($cli) = @_;
    my $sock = $cli->{sock} or return 0;
    my $h = eval { $sock->peerhost } // '';
    return $h eq '127.0.0.1' || $h eq '::1';
}

# Loopback always allowed; otherwise the peer's IPv4 must fall in one
# of the CIDRs listed in [forward] allow_peers (comma- or whitespace-
# separated). Parsed once and cached.
sub _peer_may_forward {
    my ($self, $cli) = @_;
    return 1 if _peer_is_loopback($cli);
    my $sock = $cli->{sock} or return 0;
    my $h = eval { $sock->peerhost } // '';
    return 0 unless $h =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
    my $peer = ($1 << 24) | ($2 << 16) | ($3 << 8) | $4;
    my $cidrs = $self->{_fwd_allow_cidrs} //= _parse_cidrs(
        eval { $self->{cfg}{forward}{allow_peers} } // ''
    );
    for my $c (@$cidrs) {
        return 1 if ($peer & $c->[1]) == $c->[0];
    }
    return 0;
}

sub _parse_cidrs {
    my ($s) = @_;
    my @out;
    for my $tok (split /[\s,]+/, $s) {
        next unless length $tok;
        if ($tok =~ m{^(\d+)\.(\d+)\.(\d+)\.(\d+)(?:/(\d+))?$}) {
            my ($a,$b,$c,$d,$pl) = ($1,$2,$3,$4,$5);
            $pl //= 32;
            next unless $pl >= 0 && $pl <= 32;
            my $ipi  = ($a << 24) | ($b << 16) | ($c << 8) | $d;
            my $mask = $pl == 0 ? 0 : ((0xffffffff << (32 - $pl)) & 0xffffffff);
            push @out, [ $ipi & $mask, $mask ];
        }
    }
    return \@out;
}

# Walks every consumer's subscriptions; for each that matches table+WHERE,
# pushes a ROW line. Called after every UPSERT/insert/event.
sub _emit_change {
    my ($self, %args) = @_;
    my $table = $args{table};
    my $op    = $args{op};
    my $row   = $args{row} or return;
    my $match_row = _row_for_match($row);

    for my $cli (values %{ $self->{clients} }) {
        my $subs = $cli->{subs} or next;
        for my $sub_id (keys %$subs) {
            my $sub = $subs->{$sub_id};
            next unless $sub->{table} eq $table;
            next unless $sub->{mode} eq 'stream' || $sub->{mode} eq 'snapshot+stream';
            if ($sub->{where_ast}) {
                next unless eval_ast($sub->{where_ast}, $match_row);
            }
            $self->_send($cli, format_row($sub_id, $table, $op, %$row));
        }
    }
}

# Convert a DB row (DATETIME strings) to a hash with epoch seconds for
# date-shaped values, so WHERE-eval's now()/interval comparisons work.
sub _row_for_match {
    my ($row) = @_;
    my %out;
    for my $k (keys %$row) {
        my $v = $row->{$k};
        if (defined $v && $v =~ /^(\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)/) {
            require Time::Local;
            $out{$k} = eval { Time::Local::timelocal($6, $5, $4, $3, $2-1, $1) }
                       // $v;
        } else {
            $out{$k} = $v;
        }
    }
    return \%out;
}

# ---- TRIGGER ---------------------------------------------------------

sub _handle_trigger {
    my ($self, $cli, $cmd) = @_;
    my $name = $cmd->{name};
    my $wait = $cmd->{wait};

    if ($name eq 'scan-ap') {
        my @ips = $self->_known_ap_ips;
        return $self->_send($cli, format_err("no APs known"))
            unless @ips;
        my $bin = $self->_producer_path('net-poll-ap');
        return $self->_send($cli, format_err("net-poll-ap not found at $bin"))
            unless -x $bin;

        my $pid = fork();
        return $self->_send($cli, format_err("fork: $!"))
            unless defined $pid;
        if ($pid == 0) {
            # Child: close inherited sockets, exec the producer.
            for my $c (values %{ $self->{clients} }) {
                close $c->{sock} if $c->{sock};
            }
            for my $l (values %{ $self->{listeners} }) {
                close $l->{sock} if $l->{sock};
            }
            $ENV{NET_MGR_LISTEN} = $self->_child_connect_addr;
            exec $bin, @ips;
            exit 127;
        }
        $self->_log("trigger scan-ap pid=$pid ips=" . scalar(@ips)
                  . ($wait ? ' (WAIT)' : ''));

        # Don't block in waitpid — the child needs to connect back here
        # to push observations, which we can't accept while blocked.
        # Record the pending trigger; the main loop reaps it.
        $self->{triggers}{$pid} = {
            cli_fd     => ($wait ? fileno($cli->{sock}) : undef),
            name       => $name,
            started_at => time(),
        };
        $self->_send($cli, format_ok(name => $name, pid => $pid))
            unless $wait;
        return;
    }

    if ($name eq 'wifi-survey') {
        # net-wifi-survey ssh's to every AP and runs the channel scan.
        # The web CGI runs as www-data and has no ssh keys, so it
        # delegates here — the daemon runs as root with keys available.
        my $bin = $self->_producer_path('net-wifi-survey');
        return $self->_send($cli, format_err("net-wifi-survey not found at $bin"))
            unless -x $bin;
        my $pid = fork();
        return $self->_send($cli, format_err("fork: $!"))
            unless defined $pid;
        if ($pid == 0) {
            for my $c (values %{ $self->{clients} }) {
                close $c->{sock} if $c->{sock};
            }
            for my $l (values %{ $self->{listeners} }) {
                close $l->{sock} if $l->{sock};
            }
            $ENV{NET_MGR_LISTEN} = $self->_child_connect_addr;
            exec $bin;
            exit 127;
        }
        $self->_log("trigger wifi-survey pid=$pid"
                  . ($wait ? ' (WAIT)' : ''));
        $self->{triggers}{$pid} = {
            cli_fd     => ($wait ? fileno($cli->{sock}) : undef),
            name       => $name,
            started_at => time(),
        };
        $self->_send($cli, format_ok(name => $name, pid => $pid))
            unless $wait;
        return;
    }

    if ($name eq 'discover') {
        my $bin = $self->_producer_path('net-discover');
        return $self->_send($cli, format_err("net-discover not found at $bin"))
            unless -x $bin;
        my @args = ('--discover');
        if ($cmd->{kv}{network}) {
            push @args, '--network', $cmd->{kv}{network};
        }
        my $pid = fork();
        return $self->_send($cli, format_err("fork: $!"))
            unless defined $pid;
        if ($pid == 0) {
            for my $c (values %{ $self->{clients} }) {
                close $c->{sock} if $c->{sock};
            }
            for my $l (values %{ $self->{listeners} }) {
                close $l->{sock} if $l->{sock};
            }
            $ENV{NET_MGR_LISTEN} = $self->_child_connect_addr;
            exec $bin, @args;
            exit 127;
        }
        $self->_log("trigger discover pid=$pid args=@args"
                  . ($wait ? ' (WAIT)' : ''));
        $self->{triggers}{$pid} = {
            cli_fd     => ($wait ? fileno($cli->{sock}) : undef),
            name       => $name,
            started_at => time(),
        };
        $self->_send($cli, format_ok(name => $name, pid => $pid))
            unless $wait;
        return;
    }

    if ($name eq 'presence') {
        my $bin = $self->_producer_path('net-discover');
        return $self->_send($cli, format_err("net-discover not found at $bin"))
            unless -x $bin;
        my $pid = fork();
        return $self->_send($cli, format_err("fork: $!")) unless defined $pid;
        if ($pid == 0) {
            for my $c (values %{ $self->{clients} }) { close $c->{sock} if $c->{sock} }
            for my $l (values %{ $self->{listeners} }) {
                close $l->{sock} if $l->{sock};
            }
            $ENV{NET_MGR_LISTEN} = $self->_child_connect_addr;
            exec $bin, '--presence';
            exit 127;
        }
        $self->_log("trigger presence pid=$pid" . ($wait ? ' (WAIT)' : ''));
        $self->{triggers}{$pid} = {
            cli_fd     => ($wait ? fileno($cli->{sock}) : undef),
            name       => $name,
            started_at => time(),
        };
        $self->_send($cli, format_ok(name => $name, pid => $pid))
            unless $wait;
        return;
    }

    if ($name eq 'probe-host') {
        return $self->_send($cli, format_err("trigger '$name' not yet implemented"));
    }

    if ($name eq 'reset-rtt') {
        # In-process: no fork, just clear the RTT fields. addr= picks
        # one IP; addr= absent + all=1 clears every row.
        my $kv   = $cmd->{kv} || {};
        my $addr = $kv->{addr};
        my $all  = $kv->{all};
        my $n;
        if ($addr) {
            $n = $self->{db}->reset_rtt(addr => $addr);
        } elsif ($all) {
            $n = $self->{db}->reset_rtt;
        } else {
            return $self->_send($cli,
                format_err("reset-rtt needs addr=<ip> or all=1"));
        }
        $self->_log("trigger reset-rtt rows=$n addr=" . ($addr // '*'));
        return $self->_send($cli, format_ok(name => $name, rows => $n));
    }

    $self->_send($cli, format_err("unknown trigger '$name'"));
}

# Flip currently-online interfaces back to offline if their last_seen
# is older than the grace period. Cheap query; runs at most every 30s.
# Walk a parsed WHERE AST looking for a `ts > ago(N)` (or AND-chain
# containing one), return the absolute epoch threshold. Used to push a
# windowed snapshot down into SQL when the events table is queried.
# Conservative — only matches a few common shapes; falls through (=
# no SQL filter) for anything fancier and the in-Perl WHERE eval still
# applies.
sub _extract_ts_lower_bound {
    my ($ast) = @_;
    return undef unless ref $ast eq 'ARRAY' && @$ast;
    my $op = $ast->[0];
    if ($op eq 'and') {
        for my $branch (@{$ast}[1 .. $#$ast]) {
            my $b = _extract_ts_lower_bound($branch);
            return $b if $b;
        }
        return undef;
    }
    if ($op eq '>' || $op eq '>=') {
        my ($lhs, $rhs) = @{$ast}[1, 2];
        return undef unless ref $lhs eq 'ARRAY' && $lhs->[0] eq 'col'
                         && $lhs->[1] eq 'ts';
        return undef unless ref $rhs eq 'ARRAY' && $rhs->[0] eq 'fn_ago';
        my $secs = $rhs->[1];
        return undef unless ref $secs eq 'ARRAY' && $secs->[0] eq 'num';
        return time() - $secs->[1];
    }
    return undef;
}

# Run periodically: drop events older than retention. Bounded by an
# hourly cap so the daemon doesn't keep slamming DELETE on a tiny table.
sub _purge_old_events {
    my ($self) = @_;
    my $now = time();
    return if ($now - ($self->{_last_purge} // 0)) < 3600;
    $self->{_last_purge} = $now;
    my $days = $self->{config}{manager}{event_retention_days} // 7;
    return unless $days > 0;
    my $n = $self->{db}->purge_events(days => $days);
    $self->_log("purged $n event row(s) older than ${days}d") if $n && $n > 0;
}

sub _age_out_offline {
    my ($self) = @_;
    my $grace = $self->{config}{manager}{offline_after} // 300;
    return unless $grace && $grace > 0;
    my $now = time();
    return if ($now - ($self->{_last_age_check} // 0)) < 30;
    $self->{_last_age_check} = $now;

    my $rows = $self->{db}->dbh->selectall_arrayref(
        "SELECT mac FROM interfaces
          WHERE online = 1
            AND last_seen < DATE_SUB(NOW(), INTERVAL ? SECOND)",
        { Slice => {} }, $grace
    );
    return unless @$rows;
    for my $r (@$rows) {
        my $upd = $self->_upsert('interfaces', 'upsert_interface',
            mac => $r->{mac}, online => 0);
        if ($upd->{op} eq 'update'
            && grep { $_ eq 'online' } @{ $upd->{changed_fields} })
        {
            $self->_log_event(type => 'interface_offline', mac => $r->{mac});
        }
    }
}

# Periodic, daemon-initiated TRIGGERs. Reads intervals from
# $cfg->{scheduling} and fires the matching producer when due.
# Skips if a previous run of the same name is still pending.
sub _check_periodic_triggers {
    my ($self) = @_;
    my $sched = $self->{config}{scheduling} || {};
    my $now   = time();
    $self->{periodic_last} //= {};

    for my $name (qw(scan-ap presence discover find-peers)) {
        my $interval = $sched->{$name} // 0;
        next unless $interval && $interval > 0;
        my $last = $self->{periodic_last}{$name} // 0;
        next if ($now - $last) < $interval;

        # Don't pile up if the previous run is still going
        if (grep { $_->{name} eq $name } values %{ $self->{triggers} }) {
            next;
        }
        $self->{periodic_last}{$name} = $now;
        $self->_fire_periodic($name);
    }
}

sub _fire_periodic {
    my ($self, $name) = @_;
    my ($bin, @args);
    if ($name eq 'scan-ap') {
        my @ips = $self->_known_ap_ips;
        return unless @ips;
        $bin  = $self->_producer_path('net-poll-ap');
        @args = @ips;
    } elsif ($name eq 'presence') {
        $bin  = $self->_producer_path('net-discover');
        @args = ('--presence');
    } elsif ($name eq 'discover') {
        $bin  = $self->_producer_path('net-discover');
        @args = ('--discover');
    } elsif ($name eq 'find-peers') {
        # Auto-discover other net-mgr daemons on the LAN. The tool
        # writes its findings to the local `peers` table; the new
        # 'unconfigured peer found' event-emit path lives in
        # net-find-peers itself (sees a peer whose primary_name
        # isn't in [cluster] members, emits an event). Keeping the
        # logic there avoids duplicating it in this dispatcher.
        $bin  = $self->_producer_path('net-find-peers');
        @args = ('--quiet');
    } else {
        return;
    }
    return unless $bin && -x $bin;

    my $pid = fork();
    return unless defined $pid;
    if ($pid == 0) {
        for my $c (values %{ $self->{clients} }) { close $c->{sock} if $c->{sock} }
        close $self->{listen} if $self->{listen};
        $ENV{NET_MGR_LISTEN} = $self->{config}{manager}{listen}
                            // '127.0.0.1:7531';
        exec $bin, @args;
        exit 127;
    }
    $self->_log("periodic $name pid=$pid (next in $self->{config}{scheduling}{$name}s)");
    $self->{triggers}{$pid} = {
        cli_fd     => undef,
        name       => $name,
        started_at => time(),
    };
}

# Non-blocking reap of any TRIGGER children that have exited.
# For WAIT triggers, sends READY to the waiting client (if still connected).
sub _reap_triggers {
    my ($self) = @_;
    while ((my $pid = waitpid(-1, POSIX::WNOHANG())) > 0) {
        my $exit = $? >> 8;
        my $t = delete $self->{triggers}{$pid};
        next unless $t;
        $self->_log("trigger $t->{name} pid=$pid done exit=$exit"
                  . " elapsed=" . (time() - $t->{started_at}) . "s");
        next unless defined $t->{cli_fd};
        my $cli = $self->{clients}{ $t->{cli_fd} };
        next unless $cli;
        $self->_send($cli, format_ready(name => $t->{name}, pid => $pid,
                                        exit => $exit));
    }
}

# ---- POLL ----------------------------------------------------------------
#
# Synchronous RPC: peer asks the daemon to run a whitelisted local probe
# and ship the captured stdout back in the OK reply.  Output is base64-
# encoded so newlines/quotes survive the kv wire format.  No client-
# supplied shell — the name argument indexes into %POLL_SCRIPTS only.
#
# Runs as the daemon user (typically root, which is what iptables-save
# needs).  Same trust boundary as the rest of the protocol: anyone who
# can reach :7531 can already drive producers via TRIGGER, so POLL
# isn't widening the attack surface — just exposing read-only probes
# of host state that the daemon can already see.
# Each value is either a shell-script string (run via /bin/sh -c) or
# a code-ref that returns a string. The dispatcher in _handle_poll
# picks the right path.
my %POLL_SCRIPTS = (
    fw_state => <<'SH',
echo ===KIND===
if [ -f /tmp/.rc_started ] || [ -e /jffs ]; then echo dd-wrt
elif [ -f /etc/openwrt_release ]; then echo openwrt
elif [ -e /usr/bin/cygpath ]; then echo cygwin
else echo linux; fi
echo ===HOSTNAME===
hostname 2>/dev/null
echo ===ROUTES===
ip -4 route show 2>/dev/null || route -n 2>/dev/null
echo ===NAT===
iptables-save -t nat 2>/dev/null
echo ===FILTER===
iptables-save -t filter 2>/dev/null
echo ===END===
SH
    ssh_forwards => 'pgrep -lfa ssh 2>/dev/null',
    'host-debug' => sub {
        require NetMgr::HostDebug;
        return NetMgr::HostDebug::format_report();
    },
);

# Coderef POLLs that need access to the daemon object (for in-memory
# state, e.g. the cluster's peer_caps table). Keyed identically to
# %POLL_SCRIPTS; checked first.
my %POLL_METHODS = (
    'peer-caps' => sub {
        my ($self) = @_;
        my $caps = $self->{cluster}{peer_caps} || {};
        my @lines;
        for my $name (sort keys %$caps) {
            my $list = join(',', @{ $caps->{$name} || [] });
            push @lines, "$name\t$list";
        }
        return join("\n", @lines) . "\n";
    },
);

sub _handle_poll {
    my ($self, $cli, $cmd) = @_;
    my $name = $cmd->{name} // '';
    my $method = $POLL_METHODS{$name};
    my $handler = $POLL_SCRIPTS{$name};
    if (!defined $method && !defined $handler) {
        my @ok = sort(keys %POLL_SCRIPTS, keys %POLL_METHODS);
        return $self->_send($cli,
            format_err("unknown POLL '$name' (allowed: @ok)"));
    }
    my $output = '';
    eval {
        if ($method) {
            $output = $method->($self) // '';
        } elsif (ref($handler) eq 'CODE') {
            $output = $handler->() // '';
        } else {
            open(my $fh, '-|', '/bin/sh', '-c', $handler)
                or die "fork /bin/sh: $!\n";
            local $/;
            $output = <$fh> // '';
            close $fh;
        }
    };
    if ($@) {
        my $e = $@; chomp $e;
        return $self->_send($cli, format_err("POLL $name: $e"));
    }
    require MIME::Base64;
    my $b64 = MIME::Base64::encode_base64($output, '');   # no newlines
    $self->_send($cli, format_ok(name => $name, output => $b64));
    $self->_log("poll $name from $cli->{ident} ("
              . length($output) . " bytes)");
}

# Returns sorted unique v4 addresses for known APs.
sub _known_ap_ips {
    my ($self) = @_;
    my $rows = $self->{db}->dbh->selectall_arrayref(
        "SELECT DISTINCT ad.addr
           FROM aps a JOIN addresses ad ON ad.mac = a.mac
          WHERE ad.family = 'v4'
          ORDER BY ad.addr",
        { Slice => {} }
    );
    return map { $_->{addr} } @$rows;
}

# Locate a sibling producer binary. Looks at config[paths] first, then
# alongside the daemon under sbin/../bin/.
sub _producer_path {
    my ($self, $name) = @_;
    my $cfg_path = $self->{config}{paths}{$name};
    return $cfg_path if $cfg_path;
    # Source-tree layout: lib/NetMgr/Manager.pm → ../../bin/<name>
    require File::Basename;
    my $here = File::Basename::dirname(__FILE__);
    for my $cand ("$here/../../bin/$name",
                  "$FindBin::Bin/../bin/$name",
                  "/usr/local/bin/$name") {
        return $cand if -x $cand;
    }
    return "$here/../../bin/$name";   # report this in the error
}

# ---- upsert + emit wrappers ------------------------------------------
# Keeps the OBSERVE handlers tidy and ensures every change reaches
# subscribers. $table is the logical table name; $method is the DB
# method (e.g. 'upsert_interface').

sub _upsert {
    my ($self, $table, $method, %args) = @_;
    my $r = $self->{db}->$method(%args);
    if ($r->{op} && $r->{op} ne 'noop' && $r->{now}) {
        $self->_emit_change(table => $table, op => $r->{op}, row => $r->{now});
    }
    return $r;
}

sub _log_event {
    my ($self, %ev) = @_;
    my $id = $self->{db}->log_event(%ev);
    $self->_log("event $ev{type} mac=" . ($ev{mac} // '-')
                                . " addr=" . ($ev{addr} // '-'));
    # Re-fetch the row so subscribers see exactly what's persisted.
    my $row = $self->{db}->dbh->selectrow_hashref(
        "SELECT * FROM events WHERE id = ?", undef, $id);
    $self->_emit_change(table => 'events', op => 'insert', row => $row) if $row;
    return $id;
}


# ---- net-chat --------------------------------------------------------
#
# Named chat sessions hosted by the daemon. Control verbs (CHAT_OPEN /
# SET / CLOSE / JOIN / LEAVE / ALLOW / DENY / APPROVE / REJECT) flow
# through the handlers below; message posting rides OBSERVE
# kind=chat_msg (_obs_chat_msg). Reading history / listing sessions /
# streaming a roster all use the generic SUBSCRIBE machinery against
# the chat_* tables (registered in %SUBSCRIBABLE).

# Resolve the caller's chat identity. A verified-AUTH connection is its
# key_id (an 'agent'); a loopback connection is trusted to self-declare
# `as=NAME` (a 'human', used by the web GUI passing REMOTE_USER) and
# falls back to 'local'. Anyone else is unauthenticated → (undef,undef).
sub _chat_identity {
    my ($self, $cli, $kv) = @_;
    if ($cli->{auth} && $cli->{auth}{verified}) {
        return ($cli->{auth}{key_id}, 'agent');
    }
    if (_peer_is_loopback($cli)) {
        my $as = (defined $kv && length($kv->{as} // '')) ? $kv->{as} : 'local';
        return ($as, 'human');
    }
    return (undef, undef);
}

# Session names: a short safe token usable bare in WHERE clauses and URLs.
sub _chat_valid_name {
    my ($n) = @_;
    return defined $n && $n =~ /\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z/;
}

# May $principal administer $session_row (edit/close/manage membership)?
# Loopback is trusted as an admin (matches net-mgr's loopback model);
# otherwise only the creator or an 'owner'-role member qualifies.
sub _chat_may_admin {
    my ($self, $cli, $session_row, $principal) = @_;
    return 1 if _peer_is_loopback($cli);
    return 0 unless defined $principal;
    return 1 if $session_row->{created_by} eq $principal;
    my $m = $self->{db}->get_chat_member($session_row->{name}, $principal);
    return $m && $m->{role} eq 'owner';
}

# Add this connection to a session's live roster + emit to subscribers.
sub _chat_presence_add {
    my ($self, $cli, $session, $principal) = @_;
    my $conn_id = fileno($cli->{sock});
    return unless defined $conn_id;
    my $r = $self->{db}->upsert_chat_presence(
        session => $session, conn_id => $conn_id, principal => $principal);
    $self->_emit_change(table => 'chat_presence', op => $r->{op}, row => $r->{now})
        if $r->{op} ne 'noop' && $r->{now};
}

sub _handle_chat_open {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my ($who) = $self->_chat_identity($cli, $kv);
    return $self->_send($cli, format_err("CHAT_OPEN: not authorized"))
        unless defined $who;
    my $name = $kv->{name};
    return $self->_send($cli, format_err("CHAT_OPEN: bad/missing name="))
        unless _chat_valid_name($name);
    my $mode = $kv->{mode} // 'open';
    return $self->_send($cli, format_err("CHAT_OPEN: bad mode '$mode'"))
        unless $mode =~ /\A(open|list|request)\z/;

    # A previously-closed session is reopened (not rejected as 'exists') by an
    # owner/admin — otherwise CHAT_CLOSE is irreversible and follow/post stay
    # blocked forever. mode/topic are updated only if explicitly supplied.
    if (my $existing = $self->{db}->get_chat_session($name)) {
        if ($existing->{status} eq 'closed') {
            return $self->_send($cli,
                format_err("CHAT_OPEN: not authorized to reopen '$name'"))
                unless $self->_chat_may_admin($cli, $existing, $who);
            # Resurrect archived messages back into the DB before reopening.
            eval { $self->_chat_restore($name) };
            $self->_log("chat resurrect $name failed: $@") if $@;
            my $rr = $self->{db}->reopen_chat_session($name,
                (defined $kv->{mode}  ? (access_mode => $mode)        : ()),
                (defined $kv->{topic} ? (topic       => $kv->{topic}) : ()));
            $self->_emit_change(table => 'chat_sessions', op => 'update',
                                row => $rr->{now}) if $rr->{now};
            $self->_log("chat reopen $name by $who");
            return $self->_send($cli, format_ok(name => $name,
                mode => ($rr->{now}{access_mode} // $mode),
                status => 'open', reopened => 1));
        }
        return $self->_send($cli, format_err("CHAT_OPEN: session '$name' exists"));
    }

    my $r = eval {
        $self->{db}->open_chat_session(
            name => $name, created_by => $who,
            access_mode => $mode, topic => $kv->{topic});
    };
    return $self->_send($cli, format_err("CHAT_OPEN: $@")) if $@;
    return $self->_send($cli, format_err("CHAT_OPEN: session '$name' exists"))
        if $r->{op} eq 'exists';

    # Creator becomes owner-member, then stream both new rows.
    my $m = $self->{db}->set_chat_member(
        session => $name, principal => $who, role => 'owner',
        state => 'member', added_by => $who);
    $self->_emit_change(table => 'chat_sessions', op => 'insert', row => $r->{now});
    $self->_emit_change(table => 'chat_members',  op => 'insert', row => $m->{now})
        if $m->{now};
    $self->_log("chat open $name by $who mode=$mode");
    $self->_send($cli, format_ok(name => $name, mode => $mode));
}

sub _handle_chat_set {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my ($who) = $self->_chat_identity($cli, $kv);
    my $name = $kv->{name};
    my $s = $self->{db}->get_chat_session($name)
        or return $self->_send($cli, format_err("CHAT_SET: no such session '".($name//'')."'"));
    return $self->_send($cli, format_err("CHAT_SET: not authorized"))
        unless $self->_chat_may_admin($cli, $s, $who);
    if (defined $kv->{mode} && $kv->{mode} !~ /\A(open|list|request)\z/) {
        return $self->_send($cli, format_err("CHAT_SET: bad mode '$kv->{mode}'"));
    }
    my $r = eval {
        $self->{db}->set_chat_session(
            name => $name,
            (defined $kv->{mode}  ? (access_mode => $kv->{mode})  : ()),
            (exists  $kv->{topic} ? (topic       => $kv->{topic}) : ()));
    };
    return $self->_send($cli, format_err("CHAT_SET: $@")) if $@;
    $self->_emit_change(table => 'chat_sessions', op => 'update', row => $r->{now})
        if $r->{now};
    $self->_send($cli, format_ok(name => $name));
}

sub _handle_chat_close {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my ($who) = $self->_chat_identity($cli, $kv);
    my $name = $kv->{name};
    my $s = $self->{db}->get_chat_session($name)
        or return $self->_send($cli, format_err("CHAT_CLOSE: no such session '".($name//'')."'"));
    return $self->_send($cli, format_err("CHAT_CLOSE: not authorized"))
        unless $self->_chat_may_admin($cli, $s, $who);

    # Move the messages out of the DB into the on-disk archive (kept until
    # explicitly deleted). The chat_sessions row stays so owners can find and
    # resurrect it. If archiving fails, abort the close — don't lose messages.
    my $dir = eval { $self->_chat_archive($name, $s) };
    if ($@) {
        my $e = $@; $e =~ s/\s+\z//;
        $self->_log("chat close $name: archive FAILED: $e");
        return $self->_send($cli, format_err("CHAT_CLOSE: archive failed: $e"));
    }

    my $r = $self->{db}->close_chat_session($name);
    $self->_emit_change(table => 'chat_sessions', op => 'update', row => $r->{now})
        if $r->{now};
    $self->_log("chat close $name by ".($who//'?')." -> $dir");
    $self->_send($cli, format_ok(name => $name, status => 'closed', archive => $dir));
}

sub _chat_archive_base {
    my ($self) = @_;
    return $self->{config}{chat}{archive_dir} // '/var/lib/net-mgr/chat';
}

# Serialize a session's messages (+ metadata + members) to its archive
# directory, then delete the message rows from the DB. Returns the directory.
sub _chat_archive {
    my ($self, $name, $s) = @_;
    my $base     = $self->_chat_archive_base;
    my $members  = $self->{db}->dbh->selectall_arrayref(
        "SELECT * FROM chat_members WHERE session = ?", { Slice => {} }, $name);
    my $messages = $self->{db}->get_chat_messages($name);
    my $dir = NetMgr::ChatArchive::write_archive($base, $s, $members, $messages);
    $self->{db}->delete_chat_messages($name);
    return $dir;
}

# Resurrect: pull archived messages back into the DB (only when the session has
# none live, so a reopen can't duplicate them). Ids/ts are preserved.
sub _chat_restore {
    my ($self, $name) = @_;
    my $base = $self->_chat_archive_base;
    return unless NetMgr::ChatArchive::has_archive($base, $name);
    my ($have) = $self->{db}->dbh->selectrow_array(
        "SELECT COUNT(*) FROM chat_messages WHERE session = ?", undef, $name);
    return if $have;
    my $msgs = NetMgr::ChatArchive::read_messages($base, $name);
    $self->{db}->restore_chat_message(%$_) for @$msgs;
    $self->_log("chat resurrect $name: restored " . scalar(@$msgs) . " message(s)");
}

sub _handle_chat_join {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my ($who) = $self->_chat_identity($cli, $kv);
    return $self->_send($cli, format_err("CHAT_JOIN: not authorized"))
        unless defined $who;
    my $name = $kv->{session} // $kv->{name};
    my $s = $self->{db}->get_chat_session($name)
        or return $self->_send($cli, format_err("CHAT_JOIN: no such session '".($name//'')."'"));
    return $self->_send($cli, format_err("CHAT_JOIN: session '$name' is closed"))
        if $s->{status} eq 'closed';

    my $mode = $s->{access_mode};
    my $existing = $self->{db}->get_chat_member($name, $who);
    my $is_member = $existing && $existing->{state} eq 'member';

    if ($mode eq 'request' && !$is_member && !$self->_chat_may_admin($cli, $s, $who)) {
        # Not yet allowed — record/refresh the join request and notify
        # owners (anyone subscribed WHERE state="requested" sees it).
        my $m = $self->{db}->set_chat_member(
            session => $name, principal => $who, state => 'requested', added_by => $who);
        $self->_emit_change(table => 'chat_members', op => 'update', row => $m->{now})
            if $m->{now};
        $self->_log("chat join-request $name by $who");
        return $self->_send($cli, format_ok(session => $name, state => 'requested'));
    }
    if ($mode eq 'list' && !$is_member
        && !($existing && $existing->{state} eq 'invited')
        && !$self->_chat_may_admin($cli, $s, $who)) {
        return $self->_send($cli,
            format_err("CHAT_JOIN: '$name' is allow-list only; ask an owner to CHAT_ALLOW you"));
    }

    # Allowed: ensure a member row (idempotent) and add live presence.
    if (!$is_member) {
        my $m = $self->{db}->set_chat_member(
            session => $name, principal => $who, state => 'member', added_by => $who);
        $self->_emit_change(table => 'chat_members', op => 'update', row => $m->{now})
            if $m->{now};
    }
    $self->_chat_presence_add($cli, $name, $who);
    $self->_log("chat join $name by $who");
    $self->_send($cli, format_ok(session => $name, state => 'member'));
}

sub _handle_chat_leave {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my $name = $kv->{session} // $kv->{name};
    return $self->_send($cli, format_err("CHAT_LEAVE: missing session="))
        unless defined $name;
    my $conn_id = fileno($cli->{sock});
    my $row = defined $conn_id
        ? $self->{db}->delete_chat_presence($name, $conn_id) : undef;
    $self->_emit_change(table => 'chat_presence', op => 'delete', row => $row) if $row;
    $self->_send($cli, format_ok(session => $name));
}

# CHAT_ALLOW / DENY / APPROVE / REJECT — owner edits to the membership
# list. allow/approve → state 'member'; deny/reject → state 'denied'.
sub _handle_chat_member_op {
    my ($self, $cli, $cmd, $op) = @_;
    my $kv = $cmd->{kv} || {};
    my ($who) = $self->_chat_identity($cli, $kv);
    my $name = $kv->{session} // $kv->{name};
    my $principal = $kv->{principal};
    my $verb = "CHAT_" . uc $op;
    my $s = $self->{db}->get_chat_session($name)
        or return $self->_send($cli, format_err("$verb: no such session '".($name//'')."'"));
    return $self->_send($cli, format_err("$verb: not authorized"))
        unless $self->_chat_may_admin($cli, $s, $who);
    return $self->_send($cli, format_err("$verb: missing principal="))
        unless defined $principal && length $principal;
    my $state = ($op eq 'allow' || $op eq 'approve') ? 'member' : 'denied';
    my $m = $self->{db}->set_chat_member(
        session => $name, principal => $principal, state => $state, added_by => $who);
    $self->_emit_change(table => 'chat_members', op => 'update', row => $m->{now})
        if $m->{now};
    $self->_log("chat $op $name principal=$principal by ".($who//'?'));
    $self->_send($cli, format_ok(session => $name, principal => $principal, state => $state));
}

# OBSERVE kind=chat_msg session=N body="..." [in_reply_to=ID] [as=NAME]
# Posts one message. Identity is server-stamped from the verified key
# (or loopback `as`); a closed session or a non-member (on list/request
# sessions) is rejected. Returns no events — it does its own emit.
sub _obs_chat_msg {
    my ($self, $cli, $kv) = @_;
    my ($who, $kind) = $self->_chat_identity($cli, $kv);
    die "not authorized to post\n" unless defined $who;
    my $name = $kv->{session} // $kv->{name};
    my $body = $kv->{body};
    die "chat_msg: missing session=\n" unless defined $name && length $name;
    die "chat_msg: missing body=\n"    unless defined $body && length $body;
    my $s = $self->{db}->get_chat_session($name)
        or die "chat_msg: no such session '$name'\n";
    die "chat_msg: session '$name' is closed\n" if $s->{status} eq 'closed';

    if ($s->{access_mode} ne 'open' && !_peer_is_loopback($cli)) {
        my $m = $self->{db}->get_chat_member($name, $who);
        die "chat_msg: not a member of '$name'\n"
            unless $m && $m->{state} eq 'member';
    }

    my $row = $self->{db}->insert_chat_message(
        session => $name, sender => $who, sender_kind => $kind,
        body => $body, in_reply_to => $kv->{in_reply_to});
    $self->{db}->touch_chat_activity($name);
    $self->_emit_change(table => 'chat_messages', op => 'insert', row => $row);
    # Stream the bumped last_activity so session lists re-sort live.
    my $fresh = $self->{db}->get_chat_session($name);
    $self->_emit_change(table => 'chat_sessions', op => 'update', row => $fresh)
        if $fresh;
    return ();   # not a network event; no events-table row
}

# ---- OBSERVE dispatch ------------------------------------------------

sub _handle_observe {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my $kind = $kv->{kind} // '';
    my @events;
    eval {
        if    ($kind eq 'ap_self')     { @events = $self->_obs_ap_self($cli, $kv) }
        elsif ($kind eq 'association') { @events = $self->_obs_association($cli, $kv) }
        elsif ($kind eq 'arp')         { @events = $self->_obs_arp($cli, $kv) }
        elsif ($kind eq 'lease')       { @events = $self->_obs_lease($cli, $kv) }
        elsif ($kind eq 'host')        { @events = $self->_obs_host($cli, $kv) }
        elsif ($kind eq 'ssh_host_key'){ @events = $self->_obs_ssh_host_key($cli, $kv) }
        elsif ($kind eq 'port')        { @events = $self->_obs_port($cli, $kv) }
        elsif ($kind eq 'ping')        { @events = $self->_obs_ping($cli, $kv) }
        elsif ($kind eq 'link')        { @events = $self->_obs_link($cli, $kv) }
        elsif ($kind eq 'isp_link')    { @events = $self->_obs_isp_link($cli, $kv) }
        elsif ($kind eq 'isp_secret')  { @events = $self->_obs_isp_secret($cli, $kv) }
        elsif ($kind eq 'isp_link_delete')
                                       { @events = $self->_obs_isp_link_delete($cli, $kv) }
        elsif ($kind eq 'lost_device_delete')
                                       { @events = $self->_obs_lost_device_delete($cli, $kv) }
        elsif ($kind eq 'peer_cap_set')
                                       { @events = $self->_obs_peer_cap_set($cli, $kv) }
        elsif ($kind eq 'peer_cap_clear')
                                       { @events = $self->_obs_peer_cap_clear($cli, $kv) }
        elsif ($kind eq 'event')       { @events = $self->_obs_event($cli, $kv) }
        elsif ($kind eq 'forward')     { @events = $self->_obs_forward($cli, $kv) }
        elsif ($kind eq 'chat_msg')    { @events = $self->_obs_chat_msg($cli, $kv) }
        else {
            die "unknown observation kind '$kind'\n";
        }
    };
    if ($@) {
        my $err = $@; chomp $err;
        $self->_send($cli, format_err($err));
        $self->_log("err observe from $cli->{ident}: $err");
        return;
    }
    for my $e (@events) {
        $self->_log_event(%$e);
    }
    $self->_send($cli, format_ok());
}

sub _handle_gone {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my $mac = $kv->{mac};
    return $self->_send($cli, format_err("GONE needs mac=")) unless $mac;
    my $r = $self->_upsert('interfaces', 'upsert_interface',
                           mac => $mac, online => 0);
    if ($r->{op} eq 'update' && grep { $_ eq 'online' } @{ $r->{changed_fields} }) {
        $self->_log_event(type => 'interface_offline', mac => $mac);
    }
    $self->_send($cli, format_ok());
}

# Look up or create a machine identified by name and link an interface
# to it. Adds the (machine_id, name, source) tuple to hostnames. Used
# whenever a producer reports a hostname for a MAC (DHCP lease,
# AP self-name, future SSH-fingerprint).
#
# Auto-correlation rule 1 from the design memo: two interfaces that
# report the same name → same machine.
sub _associate_machine {
    my ($self, $mac, $name, $source) = @_;
    return unless defined $mac && defined $name && length $name && $name ne '*';
    $mac = lc $mac;
    my $iface = $self->{db}->get_interface_by_mac($mac);
    return unless $iface;

    my $mid = $iface->{machine_id};
    if (!$mid) {
        my ($existing) = $self->{db}->dbh->selectrow_array(
            "SELECT id FROM machines WHERE primary_name = ? LIMIT 1",
            undef, $name);
        if ($existing) {
            $mid = $existing;
        } else {
            my $r = $self->_upsert('machines', 'upsert_machine',
                primary_name => $name, online => 1);
            $mid = $r->{now}{id};
        }
        $self->_upsert('interfaces', 'upsert_interface',
            mac => $mac, machine_id => $mid);
    }
    $self->_upsert('hostnames', 'upsert_hostname',
        machine_id => $mid, name => $name, source => $source);
    return $mid;
}

# ---- per-kind observation handlers -----------------------------------

# Returns: list of event hashrefs to log.
sub _events_from_iface_change {
    my ($r, $extra_addr) = @_;
    my @ev;
    if ($r->{op} eq 'insert') {
        push @ev, { type => 'interface_new', mac => $r->{now}{mac},
                    addr => $extra_addr };
        if ($r->{now}{online}) {
            push @ev, { type => 'interface_online', mac => $r->{now}{mac},
                        addr => $extra_addr };
        }
    } elsif ($r->{op} eq 'update'
             && grep { $_ eq 'online' } @{ $r->{changed_fields} }) {
        push @ev, {
            type => $r->{now}{online} ? 'interface_online' : 'interface_offline',
            mac  => $r->{now}{mac},
            addr => $extra_addr,
        };
    }
    return @ev;
}

sub _events_for_addr_op {
    my ($a, $mac, $ip) = @_;
    return () unless ref $a;
    my @ev;
    push @ev, { type => 'address_added', mac => $mac, addr => $ip }
        if ($a->{op} // '') eq 'insert';
    push @ev, { type => 'address_removed', mac => $_, addr => $ip,
                reason => 'superseded' }
        for @{ $a->{superseded} // [] };
    return @ev;
}

sub _obs_ap_self {
    my ($self, $cli, $kv) = @_;
    my $mac = $kv->{mac} or die "ap_self: mac required (br0 not parsed?)\n";
    my @ev;
    my $iface = $self->_upsert('interfaces', 'upsert_interface',
        mac => $mac, kind => 'wifi', online => 1, live => 1);
    push @ev, _events_from_iface_change($iface, $kv->{ip});

    if ($kv->{ip}) {
        my $a = $self->_upsert('addresses', 'upsert_address',
            mac => $mac, family => 'v4', addr => $kv->{ip}, live => 1,
            defined $kv->{source} ? (source => $kv->{source}) : ());
        push @ev, _events_for_addr_op($a, $mac, $kv->{ip});
    }
    $self->_upsert('aps', 'upsert_ap',
        mac => $mac, ssid => $kv->{ssid},
        model => $kv->{model}, board => $kv->{board});
    # Promote the AP's router_name to a machine identity.
    $self->_associate_machine($mac, $kv->{name}, 'ap') if $kv->{name};
    return @ev;
}

sub _obs_association {
    my ($self, $cli, $kv) = @_;
    my $client_mac = $kv->{client_mac} or die "association: client_mac required\n";
    my $ap_ip      = $kv->{ap_ip};
    my @ev;

    my $iface = $self->_upsert('interfaces', 'upsert_interface',
        mac => $client_mac, kind => 'wifi', online => 1, live => 1);
    push @ev, _events_from_iface_change($iface);

    # Resolve ap_ip → ap_mac via aps/addresses join.
    my $ap_mac;
    if ($ap_ip) {
        my $row = $self->{db}->dbh->selectrow_array(
            "SELECT a.mac FROM aps a
               JOIN addresses ad ON ad.mac = a.mac
              WHERE ad.addr = ? LIMIT 1", undef, $ap_ip);
        $ap_mac = $row;
    }
    if ($ap_mac) {
        my $r = $self->_upsert('associations', 'upsert_association',
            ap_mac     => $ap_mac,
            client_mac => $client_mac,
            iface      => $kv->{iface},
            signal     => $kv->{signal},
            ssid       => $kv->{ssid},
        );
        if ($r->{op} eq 'insert') {
            push @ev, { type => 'ap_associated', mac => $client_mac,
                        details => qq({"ap_mac":"$ap_mac"}) };
        }
    }
    return @ev;
}

sub _obs_arp {
    my ($self, $cli, $kv) = @_;
    my $mac = $kv->{mac} or die "arp: mac required\n";
    my $ip  = $kv->{ip}  or die "arp: ip required\n";
    my @ev;
    my $iface = $self->_upsert('interfaces', 'upsert_interface',
        mac => $mac, kind => 'ethernet', online => 1, live => 1);
    push @ev, _events_from_iface_change($iface, $ip);
    my $a = $self->_upsert('addresses', 'upsert_address',
        mac => $mac, family => 'v4', addr => $ip, live => 1,
        defined $kv->{source} ? (source => $kv->{source}) : ());
    push @ev, _events_for_addr_op($a, $mac, $ip);
    return @ev;
}

sub _obs_lease {
    my ($self, $cli, $kv) = @_;
    my $mac = $kv->{mac} or die "lease: mac required\n";
    my $ip  = $kv->{ip}  or die "lease: ip required\n";
    my @ev;
    my $iface = $self->_upsert('interfaces', 'upsert_interface',
        mac => $mac, online => 1, live => 1);
    push @ev, _events_from_iface_change($iface, $ip);
    my $a = $self->_upsert('addresses', 'upsert_address',
        mac => $mac, family => 'v4', addr => $ip, live => 1,
        defined $kv->{source} ? (source => $kv->{source}) : ());
    push @ev, _events_for_addr_op($a, $mac, $ip);
    $self->_upsert('dhcp_leases', 'upsert_lease',
        mac      => $mac,
        ip       => $ip,
        hostname => $kv->{hostname},
        expires  => $kv->{expires},
    );
    # DHCP-supplied hostname → machine identity.
    $self->_associate_machine($mac, $kv->{hostname}, 'dhcp')
        if $kv->{hostname};
    return @ev;
}

sub _obs_host {
    my ($self, $cli, $kv) = @_;
    # generic host observation (e.g. from net-discover or net-import-dhcp)
    my $mac = $kv->{mac};
    my $ip  = $kv->{ip};
    my @ev;
    if ($mac) {
        # Only mark online for *live* observations. Imports from
        # dhcp.master / dhcp.extra are paper records — they don't
        # prove the device is currently reachable.
        my $src = $kv->{source} // '';
        my $is_live = $src !~ /:dhcp\.(master|extra)$/;
        my %iface_args = (
            mac    => $mac,
            kind   => $kv->{iface_kind} // 'ethernet',
            vendor => $kv->{vendor},
        );
        if ($is_live) { $iface_args{online} = 1; $iface_args{live} = 1 }
        my $iface = $self->_upsert('interfaces', 'upsert_interface', %iface_args);
        push @ev, _events_from_iface_change($iface, $ip);
        if ($ip) {
            my $a = $self->_upsert('addresses', 'upsert_address',
                mac => $mac, family => $kv->{family} // 'v4', addr => $ip,
                ($is_live ? (live => 1) : ()),
                defined $kv->{source} ? (source => $kv->{source}) : ());
            push @ev, _events_for_addr_op($a, $mac, $ip);
        }
        # Producer supplied a hostname (e.g. dhcp.master importer) →
        # promote to a machine identity. name_source classifies the
        # hostnames row ('dhcp.master', 'dhcp.extra', 'config', ...).
        if ($kv->{name}) {
            $self->_associate_machine(
                $mac, $kv->{name}, $kv->{name_source} // 'config');
        }
    }
    return @ev;
}

# Find or create a machine by primary_name; returns its id. Used when we know
# the name but not (yet) a MAC to link — e.g. net-ssh recording a host key
# against the alias it just connected to.
sub _machine_id_for_name {
    my ($self, $name) = @_;
    return undef unless defined $name && length $name;
    my ($id) = $self->{db}->dbh->selectrow_array(
        "SELECT id FROM machines WHERE primary_name = ? LIMIT 1", undef, $name);
    return $id if $id;
    my $r = $self->_upsert('machines', 'upsert_machine',
        primary_name => $name, online => 1);
    return $r->{now}{id};
}

# kind=ssh_host_key key_id=SHA256:... [key_type=ed25519] [ip=IP] [mac=MAC]
#                   [name=NAME] [name_source=...] [source=...]
# Record an SSH host key against a machine. A host key is stable per machine,
# so a fingerprint we've seen before identifies the host even on a new IP/MAC.
# Machine resolution, strongest first: an explicit name (net-ssh knows the
# alias) wins; else a previously-recorded machine for this fingerprint (the
# floating-IP case); else the MAC's current machine. When mac+ip are present we
# also refresh their liveness, like a host observation.
sub _obs_ssh_host_key {
    my ($self, $cli, $kv) = @_;
    my $key_id = $kv->{key_id} or die "ssh_host_key: key_id required\n";
    my $mac    = $kv->{mac} ? lc $kv->{mac} : undef;
    my $ip     = $kv->{ip};
    my @ev;

    if ($mac && $ip) {
        my $iface = $self->_upsert('interfaces', 'upsert_interface',
            mac => $mac, kind => $kv->{iface_kind} // 'ethernet',
            online => 1, live => 1);
        push @ev, _events_from_iface_change($iface, $ip);
        my $a = $self->_upsert('addresses', 'upsert_address',
            mac => $mac, family => $kv->{family} // 'v4', addr => $ip, live => 1,
            defined $kv->{source} ? (source => $kv->{source}) : ());
        push @ev, _events_for_addr_op($a, $mac, $ip);
    }

    my $known = $self->{db}->host_key_machine($key_id);
    my $mid;
    if ($kv->{name}) {
        $mid = $self->_machine_id_for_name($kv->{name});
        $self->_associate_machine($mac, $kv->{name},
            $kv->{name_source} // 'ssh-hostkey') if $mac;
    } elsif ($known) {
        # Seen this key before → same machine, wherever it is now.
        $mid = $known;
        if ($mac) {
            my ($pname) = $self->{db}->dbh->selectrow_array(
                "SELECT primary_name FROM machines WHERE id = ?", undef, $known);
            $self->_associate_machine($mac, $pname, 'ssh-hostkey')
                if defined $pname && length $pname;
        }
    } elsif ($mac) {
        my $iface = $self->{db}->get_interface_by_mac($mac);
        $mid = $iface->{machine_id} if $iface && $iface->{machine_id};
    }

    $self->{db}->upsert_host_key(
        key_id => $key_id, key_type => $kv->{key_type}, machine_id => $mid);
    return @ev;
}

sub _obs_forward {
    my ($self, $cli, $kv) = @_;
    my $direction = uc($kv->{direction} // '');
    die "forward: direction must be L/R/D\n" unless $direction =~ /^[LRD]$/;
    die "forward: source_host required\n"    unless $kv->{source_host};
    die "forward: bind_port required\n"      unless defined $kv->{bind_port};

    my $bind_addr = $kv->{bind_addr};
    $bind_addr = '*' if !defined $bind_addr || $bind_addr eq '';

    # Check for existence to pick the right op for downstream subscribers.
    # upsert_forwarding_rule uses INSERT ... ON DUPLICATE KEY UPDATE and
    # returns the post-write row; we just need was-or-wasn't here.
    my $existed = $self->{db}->dbh->selectrow_array(
        "SELECT 1 FROM forwarding_rules
          WHERE source_host = ? AND direction = ?
            AND bind_addr   = ? AND bind_port = ?",
        undef, $kv->{source_host}, $direction, $bind_addr, $kv->{bind_port}
    );

    my $row = $self->{db}->upsert_forwarding_rule(
        source      => $kv->{source}      // 'ssh',
        source_host => $kv->{source_host},
        source_pid  => $kv->{source_pid},
        direction   => $direction,
        bind_addr   => $bind_addr,
        bind_port   => $kv->{bind_port},
        target_host => $kv->{target_host},
        target_port => $kv->{target_port},
        ssh_user    => $kv->{ssh_user},
        ssh_host    => $kv->{ssh_host},
        ssh_port    => $kv->{ssh_port},
        notes       => $kv->{notes},
    );
    $self->_emit_change(
        table => 'forwarding_rules',
        op    => $existed ? 'update' : 'insert',
        row   => $row,
    ) if $row;
    return;
}

sub _obs_port {
    my ($self, $cli, $kv) = @_;
    my $mac  = $kv->{mac}  or die "port: mac required\n";
    my $port = $kv->{port}; defined $port or die "port: port required\n";
    my @ev;
    my $r = $self->_upsert('ports', 'upsert_port',
        mac => $mac, port => $port,
        proto => $kv->{proto} // 'tcp',
        service => $kv->{service},
    );
    if ($r->{op} eq 'insert') {
        push @ev, { type => 'port_opened', mac => $mac,
                    details => qq({"port":$port}) };
    }
    return @ev;
}

# Threshold for emitting ping_slow: rtt must be at least 5× the
# known minimum AND at least 50ms above it. Both gates: avoids
# false positives on tiny baselines (1ms × 5 = 5ms isn't really
# "slow") and on large stable baselines (100ms × 1.5 isn't a spike).
use constant PING_SLOW_RATIO => 5.0;
use constant PING_SLOW_MIN_DELTA_MS => 50.0;

sub _obs_ping {
    my ($self, $cli, $kv) = @_;
    my $mac    = $kv->{mac}    or die "ping: mac required\n";
    my $addr   = $kv->{addr}   or die "ping: addr required\n";
    my $rtt    = $kv->{rtt_ms};
    die "ping: rtt_ms required\n" unless defined $rtt;
    die "ping: rtt_ms not numeric\n" unless $rtt =~ /^\d+(?:\.\d+)?$/;
    my $loss = $kv->{loss_pct};
    if (defined $loss) {
        die "ping: loss_pct not numeric\n" unless $loss =~ /^\d+(?:\.\d+)?$/;
    }

    my %args = (mac => $mac, addr => $addr, family => 'v4', rtt_ms => $rtt);
    $args{loss_pct} = $loss if defined $loss;
    my $r = $self->{db}->update_rtt(%args);
    return unless $r->{found};   # row missing — silent no-op (producer bug)

    # update_rtt writes directly (not via _upsert) so it doesn't auto-
    # broadcast to subscribers. Emit explicitly so net-watch and other
    # streaming consumers see the new last_rtt_ms / min_rtt_ms.
    my $row = $self->{db}->dbh->selectrow_hashref(
        "SELECT * FROM addresses WHERE mac = ? AND family = 'v4' AND addr = ?",
        undef, lc $mac, $addr
    );
    $self->_emit_change(table => 'addresses', op => 'update', row => $row)
        if $row;

    my @ev;

    # Successful ping = the interface is reachable. Flip online=1 if it
    # wasn't already; the interface_online event fires on the offline→
    # online transition (paired with the interface_offline that GONE
    # emits when all of a mac's addresses go silent). Without this,
    # a host that recovered would never log a "came back" event.
    my $iface = $self->_upsert('interfaces', 'upsert_interface',
        mac => $mac, online => 1, live => 1);
    push @ev, _events_from_iface_change($iface, $addr);

    # Emit ping_slow only on the OK→slow transition so a sustained
    # slowness doesn't generate one event per probe. The transition
    # check uses prev_last (the rtt from the previous ping cycle) —
    # if it was already slow, we already emitted then.
    my $min  = $r->{prev_min};
    my $prev = $r->{prev_last};
    if (defined $min && $min > 0
        && $rtt > PING_SLOW_RATIO * $min
        && ($rtt - $min) > PING_SLOW_MIN_DELTA_MS
        && !(defined $prev
             && $prev > PING_SLOW_RATIO * $min
             && ($prev - $min) > PING_SLOW_MIN_DELTA_MS))
    {
        push @ev, {
            type => 'ping_slow',
            mac  => $mac,
            addr => $addr,
            details => sprintf('{"min_rtt_ms":%.3f,"rtt_ms":%.3f}', $min, $rtt),
        };
    }

    return @ev;
}

# kind=link mac=NAME link_speed_mbps=N — push interface link rate.
# Source is sysfs (/sys/class/net/$IF/speed) for wired, iw for wifi;
# producer is bin/net-link-stats. Silent no-op if the interface row
# doesn't exist yet (the producer should know its own MACs).
sub _obs_link {
    my ($self, $cli, $kv) = @_;
    my $mac = $kv->{mac} or die "link: mac required\n";
    my $sp  = $kv->{link_speed_mbps};
    die "link: link_speed_mbps required\n" unless defined $sp;
    die "link: link_speed_mbps not an integer\n" unless $sp =~ /^-?\d+$/;
    my $rows = $self->{db}->update_link_speed(
        mac => $mac, link_speed_mbps => $sp + 0
    );
    if ($rows) {
        # Re-fetch + emit so streaming consumers see the new value.
        my $row = $self->{db}->dbh->selectrow_hashref(
            "SELECT * FROM interfaces WHERE mac = ?", undef, lc $mac
        );
        $self->_emit_change(table => 'interfaces', op => 'update', row => $row)
            if $row;
    }
    return ();
}

# kind=isp_link gateway=NAME isp=NAME [iface=...] [mac=...] [auth_type=...]
#   [auth_user=...] [status=active|standby|broken|unknown] [notes=...]
# Records that a gateway machine connects (or could connect) to a
# given ISP via the named iface, with the listed credentials. Public-
# readable. Resolves the gateway name → machine_id by primary_name.
sub _obs_isp_link {
    my ($self, $cli, $kv) = @_;
    my $gw  = $kv->{gateway} or die "isp_link: gateway required\n";
    my $isp = $kv->{isp}     or die "isp_link: isp required\n";
    my $mid = $self->_machine_id_by_name($gw)
        or die "isp_link: no machine named '$gw'\n";
    my $r = $self->_upsert('isp_links', 'upsert_isp_link',
        gateway_machine_id => $mid,
        isp_name           => $isp,
        iface              => $kv->{iface},
        mac                => $kv->{mac},
        auth_type          => $kv->{auth_type},
        auth_user          => $kv->{auth_user},
        status             => $kv->{status},
        notes              => $kv->{notes},
    );
    return ();
}

# kind=isp_link_delete gateway=NAME isp=NAME — removes the link
# (and via FK CASCADE, any matching secret).
sub _obs_isp_link_delete {
    my ($self, $cli, $kv) = @_;
    my $gw  = $kv->{gateway} or die "isp_link_delete: gateway required\n";
    my $isp = $kv->{isp}     or die "isp_link_delete: isp required\n";
    my $mid = $self->_machine_id_by_name($gw)
        or die "isp_link_delete: no machine named '$gw'\n";
    # Snapshot the row first so we can emit a delete event.
    my $row = $self->{db}->dbh->selectrow_hashref(
        "SELECT * FROM isp_links
          WHERE gateway_machine_id = ? AND isp_name = ?",
        undef, $mid, $isp
    );
    $self->{db}->delete_isp_link(gateway_machine_id => $mid, isp_name => $isp);
    $self->_emit_change(table => 'isp_links', op => 'delete', row => $row)
        if $row;
    return ();
}

# kind=isp_secret gateway=NAME isp=NAME secret=PASS — stores or
# updates the credential. Restricted: requires either a loopback
# peer or an authenticated connection (matching the SUBSCRIBE gate
# on isp_secrets).
sub _obs_isp_secret {
    my ($self, $cli, $kv) = @_;
    unless ($self->_auth_is_full($cli)) {
        die "isp_secret: requires full-scope AUTH (or loopback peer)\n";
    }
    my $gw     = $kv->{gateway} or die "isp_secret: gateway required\n";
    my $isp    = $kv->{isp}     or die "isp_secret: isp required\n";
    my $secret = $kv->{secret};
    die "isp_secret: secret required\n" unless defined $secret;
    my $mid = $self->_machine_id_by_name($gw)
        or die "isp_secret: no machine named '$gw'\n";
    # The corresponding isp_links row must exist (FK).
    my ($exists) = $self->{db}->dbh->selectrow_array(
        "SELECT 1 FROM isp_links
          WHERE gateway_machine_id = ? AND isp_name = ?",
        undef, $mid, $isp
    );
    die "isp_secret: no isp_link for $gw/$isp (create with isp_link first)\n"
        unless $exists;
    $self->{db}->upsert_isp_secret(
        gateway_machine_id => $mid,
        isp_name           => $isp,
        auth_secret        => $secret,
    );
    return ();
}

# kind=lost_device_delete subnet=CIDR mac=MAC — clears the
# lost_devices row that net-find-lost created. Used by the recovery
# scripts after they've put a wandering device back at its proper
# IP, so the device doesn't keep showing on the "Lost devices"
# page.
sub _obs_lost_device_delete {
    my ($self, $cli, $kv) = @_;
    my $subnet = $kv->{subnet} or die "lost_device_delete: subnet required\n";
    my $mac    = $kv->{mac}    or die "lost_device_delete: mac required\n";
    # Snapshot the row first so we can broadcast a delete event.
    my $row = $self->{db}->dbh->selectrow_hashref(
        "SELECT * FROM lost_devices WHERE subnet = ? AND mac = ?",
        undef, $subnet, lc $mac
    );
    $self->{db}->delete_lost_device(subnet => $subnet, mac => $mac);
    $self->_emit_change(table => 'lost_devices', op => 'delete', row => $row)
        if $row;
    return ();
}

# kind=peer_cap_set peer=NAME caps=cap1,cap2[,...] — grant the
# listed capabilities to a peer in THIS daemon's local authority
# table. Persisted to /etc/net-mgr/peers. Requires AUTH (or
# loopback) because changing who can be master is a privileged op.
sub _obs_peer_cap_set {
    my ($self, $cli, $kv) = @_;
    unless ($self->_auth_is_full($cli)) {
        die "peer_cap_set: requires full-scope AUTH (or loopback peer)\n";
    }
    my $peer = $kv->{peer} or die "peer_cap_set: peer required\n";
    die "peer_cap_set: bad peer name '$peer'\n"
        unless $peer =~ /^[\w.-]+$/;
    my $caps = _split_caps($kv->{caps});
    $self->{cluster}{peer_caps}{$peer} = $caps;
    my $err = _write_peers_file($self->{cluster}{peers_file},
                                $self->{cluster}{peer_caps});
    die "peer_cap_set: write failed: $err\n" if $err;
    $self->_log("peer_cap_set $peer = " . join(',', @$caps));
    return ();
}

# kind=peer_cap_clear peer=NAME — remove the peer from this
# daemon's local authority table entirely. Same auth gate.
sub _obs_peer_cap_clear {
    my ($self, $cli, $kv) = @_;
    unless ($self->_auth_is_full($cli)) {
        die "peer_cap_clear: requires full-scope AUTH (or loopback peer)\n";
    }
    my $peer = $kv->{peer} or die "peer_cap_clear: peer required\n";
    delete $self->{cluster}{peer_caps}{$peer};
    my $err = _write_peers_file($self->{cluster}{peers_file},
                                $self->{cluster}{peer_caps});
    die "peer_cap_clear: write failed: $err\n" if $err;
    $self->_log("peer_cap_clear $peer");
    return ();
}

# Atomic rewrite of the peers file. Writes to a sibling tempfile
# and renames over the target, so a partial write can never leave
# a corrupt table. Existing comments / formatting in the file are
# NOT preserved — the daemon owns this file when it's writing it.
# Operator hand-edits should happen with the daemon down (and would
# need to be re-checked against any in-memory state on restart).
# Returns undef on success, an error string otherwise.
sub _write_peers_file {
    my ($path, $caps) = @_;
    my $tmp = "$path.tmp.$$";
    open my $fh, '>', $tmp or return "open $tmp: $!";
    print $fh "# /etc/net-mgr/peers — local authority table\n";
    print $fh "# managed by net-mgr (OBSERVE kind=peer_cap_set/clear)\n";
    print $fh "# format: name: cap1, cap2, ...\n\n";
    for my $name (sort keys %$caps) {
        my $list = join(', ', @{ $caps->{$name} || [] });
        printf $fh "%-20s: %s\n", $name, $list;
    }
    close $fh or return "close $tmp: $!";
    chmod 0644, $tmp;
    rename $tmp, $path or return "rename $tmp $path: $!";
    return undef;
}

sub _machine_id_by_name {
    my ($self, $name) = @_;
    my ($id) = $self->{db}->dbh->selectrow_array(
        "SELECT id FROM machines WHERE primary_name = ? LIMIT 1",
        undef, $name
    );
    return $id;
}

# Lets clients persist arbitrary events without DB credentials. Used by
# net-roam to record wifi_deauth (so the next run can honor a cooldown).
# The dispatch loop in _handle_observe runs returned events through
# _log_event, which writes the row and broadcasts to subscribers.
sub _obs_event {
    my ($self, $cli, $kv) = @_;
    my $type = $kv->{type} or die "event: type required\n";
    return ({
        type    => $type,
        mac     => $kv->{mac},
        addr    => $kv->{addr},
        details => $kv->{details},
    });
}

# ---- dnsmasq event-socket listeners ----------------------------------
#
# Each --event-listen=HOST:PORT-equipped dnsmasq we can reach gets a
# persistent TCP connection from inside this daemon. Sockets are added
# to the same IO::Select that handles client traffic, so events flow
# through the existing main-loop dispatch with no extra threads.

use IO::Socket::INET ();

# Periodic: scan the DB for hosts likely to be running dnsmasq (port
# 53 or 67 known open) and try to connect to their event-listen port,
# default 7532. Re-attempt every minute by default; once attached the
# socket stays in select() forever.
sub _check_dnsmasq_listeners {
    my ($self) = @_;
    my $cfg = $self->{config}{scanner} // {};
    my $port  = $cfg->{dnsmasq_event_port}           // 7532;
    my $every = $cfg->{dnsmasq_event_check_interval} // 60;
    my $now = time();
    $self->{periodic_last} //= {};
    return if ($now - ($self->{periodic_last}{dnsmasq_listeners} // 0)) < $every;
    $self->{periodic_last}{dnsmasq_listeners} = $now;

    my $rows = $self->{db}->dbh->selectall_arrayref(<<'SQL', { Slice => {} });
        SELECT DISTINCT a.addr
          FROM addresses a
          JOIN ports     p ON p.mac = a.mac
         WHERE a.family = 'v4'
           AND p.port IN (53, 67)
SQL
    for my $r (@$rows) {
        my $key = "$r->{addr}:$port";
        next if $self->{dnsmasq_listeners}{$key};
        $self->_try_connect_dnsmasq($r->{addr}, $port);
    }
}

sub _try_connect_dnsmasq {
    my ($self, $host, $port) = @_;
    my $sock = IO::Socket::INET->new(
        PeerAddr => $host, PeerPort => $port,
        Proto    => 'tcp', Timeout => 1,
    );
    return unless $sock;
    $sock->blocking(0);
    my $key = "$host:$port";
    $self->{dnsmasq_listeners}{$key} = {
        sock => $sock, host => $host, port => $port, buffer => '',
    };
    $self->{select}->add($sock);
    $self->_log("dnsmasq listener attached to $key");
}

sub _drop_dnsmasq_listener {
    my ($self, $key) = @_;
    my $L = delete $self->{dnsmasq_listeners}{$key} // return;
    $self->{select}->remove($L->{sock});
    eval { $L->{sock}->close };
    $self->_log("dnsmasq listener dropped from $key");
}

sub _handle_dnsmasq_data {
    my ($self, $key) = @_;
    my $L = $self->{dnsmasq_listeners}{$key} or return;
    my $buf;
    my $n = sysread $L->{sock}, $buf, 4096;
    if (!defined $n || $n == 0) {
        $self->_drop_dnsmasq_listener($key);
        return;
    }
    $L->{buffer} .= $buf;
    while ($L->{buffer} =~ s/^([^\n]*)\n//) {
        $self->_process_dnsmasq_event($1, $key);
    }
}

# Wire format from src/event-socket.c in our patched dnsmasq:
#   EVENT action=<add|del|old|have> ts=<unix> mac=<hex:..> ip=<v4|v6>
#         hostname=<name>
sub _process_dnsmasq_event {
    my ($self, $line, $key) = @_;
    return unless $line =~ /^EVENT\s/;
    my %kv;
    while ($line =~ /\b([\w-]+)=(\S+)/g) { $kv{$1} = $2 }
    my $action = $kv{action} // '';
    my $mac    = $kv{mac};
    my $ip     = $kv{ip};
    return unless $mac && $ip;

    my @ev;
    if ($action =~ /^(?:add|old|have)$/) {
        my $iface = $self->_upsert('interfaces', 'upsert_interface',
            mac => $mac, online => 1, live => 1);
        push @ev, _events_from_iface_change($iface, $ip);
        my $a = $self->_upsert('addresses', 'upsert_address',
            mac => $mac, family => ($ip =~ /:/ ? 'v6' : 'v4'),
            addr => $ip, live => 1, source => "$key:dnsmasq");
        push @ev, _events_for_addr_op($a, $mac, $ip);
        $self->_upsert('dhcp_leases', 'upsert_lease',
            mac      => $mac,
            ip       => $ip,
            hostname => $kv{hostname},
        );
        $self->_associate_machine($mac, $kv{hostname}, 'dhcp')
            if $kv{hostname};
    }
    elsif ($action eq 'del') {
        my $r = $self->_upsert('interfaces', 'upsert_interface',
            mac => $mac, online => 0);
        if ($r->{op} eq 'update'
            && grep { $_ eq 'online' } @{ $r->{changed_fields} })
        {
            push @ev, { type => 'interface_offline', mac => $mac };
        }
    }
    $self->_log_event(%$_) for @ev;
}

# ---- forward backend (iptables / socat) -----------------------------
#
# Two implementations behind one interface so the FORWARD verb doesn't
# care which is in use. Iptables is preferred when available because
# it's stateless from the daemon's POV (one rule, no child process to
# supervise). Socat is the no-root fallback.
#
# Forward record shape:
#   { method => 'iptables',
#     slot   => 5901,
#     target => '192.168.15.104:5900',
#     cookie => 'net-mgr:fwd:42:5901',   # iptables comment marker
#   }
#   { method => 'socat',
#     slot   => 5901,
#     target => '192.168.15.104:5900',
#     pid    => 12345,
#   }

sub _forward_method {
    my ($self) = @_;
    return $self->{_fwd_method_cache}
        if exists $self->{_fwd_method_cache};

    # Allow explicit pin via [forward] method = iptables|socat in the
    # daemon config. Otherwise probe.
    my $cfg_method = eval { $self->{cfg}{forward}{method} } // 'auto';
    if ($cfg_method eq 'iptables' || $cfg_method eq 'socat') {
        $self->_log("forward backend pinned to '$cfg_method' by config");
        return $self->{_fwd_method_cache} = $cfg_method;
    }

    # Auto: prefer iptables if we can run it AND we're root.
    if ($> == 0 && _have_cmd('iptables')) {
        # Enable route_localnet on lo; harmless if already on. Required
        # for OUTPUT-chain DNAT from 127.0.0.1/* to a non-loopback dest.
        system('sysctl', '-q', '-w',
               'net.ipv4.conf.lo.route_localnet=1') == 0
            or $self->_log("warn: sysctl route_localnet=1 failed (rc=$?)");
        $self->_log("forward backend = iptables (root + iptables found)");
        return $self->{_fwd_method_cache} = 'iptables';
    }
    if (_have_cmd('socat')) {
        $self->_log("forward backend = socat (no iptables / not root)");
        return $self->{_fwd_method_cache} = 'socat';
    }
    $self->_log("warn: no forward backend available (need iptables+root or socat)");
    return $self->{_fwd_method_cache} = '';
}

sub _have_cmd {
    my ($cmd) = @_;
    for my $d (split /:/, $ENV{PATH} // '/usr/sbin:/sbin:/usr/bin:/bin') {
        return 1 if -x "$d/$cmd";
    }
    return 0;
}

sub _install_forward {
    my ($self, %args) = @_;
    my $slot   = $args{slot}   or croak "slot required";
    my $target = $args{target} or croak "target required";
    my $owner  = $args{owner}  // 'anon';
    my $fd     = $args{fd}     // 0;

    my $method = $self->_forward_method
        or croak "no forward backend available";

    if ($method eq 'iptables') {
        return $self->_iptables_install($slot, $target, $fd);
    } else {
        return $self->_socat_install($slot, $target);
    }
}

sub _remove_forward {
    my ($self, $f) = @_;
    return unless ref $f;
    if ($f->{method} eq 'iptables') {
        return $self->_iptables_remove($f);
    } elsif ($f->{method} eq 'socat') {
        return $self->_socat_remove($f);
    }
    croak "unknown forward method '$f->{method}'";
}

# OUTPUT-chain DNAT in the nat table. -d 127.0.0.1 matches the
# loopback destination that ssh's local end of `ssh -L slot:127.0.0.1:slot`
# will connect to. Comment marker carries fd so cleanup-on-disconnect
# can identify our own rules even if state is lost mid-restart.
sub _iptables_install {
    my ($self, $slot, $target, $fd) = @_;
    my ($ip, $port) = split /:/, $target, 2;
    my $cookie = "net-mgr:fwd:$$:$fd:$slot";
    my @cmd = ('iptables', '-t', 'nat', '-I', 'OUTPUT',
               '-p', 'tcp', '-d', '127.0.0.1', '--dport', $slot,
               '-m', 'comment', '--comment', $cookie,
               '-j', 'DNAT', '--to-destination', "$ip:$port");
    my $rc = system(@cmd);
    if ($rc != 0) {
        croak "iptables install rc=" . ($rc >> 8);
    }
    return {
        method => 'iptables',
        slot   => $slot,
        target => $target,
        cookie => $cookie,
    };
}

sub _iptables_remove {
    my ($self, $f) = @_;
    my ($ip, $port) = split /:/, $f->{target}, 2;
    my @cmd = ('iptables', '-t', 'nat', '-D', 'OUTPUT',
               '-p', 'tcp', '-d', '127.0.0.1', '--dport', $f->{slot},
               '-m', 'comment', '--comment', $f->{cookie},
               '-j', 'DNAT', '--to-destination', "$ip:$port");
    my $rc = system(@cmd);
    croak "iptables remove rc=" . ($rc >> 8) if $rc != 0;
    return 1;
}

# Socat fallback — listens on 127.0.0.1:slot, forks per connection,
# proxies to the target. Detached so a daemon restart doesn't kill
# them, but tracked by pid for explicit teardown.
sub _socat_install {
    my ($self, $slot, $target) = @_;
    my ($ip, $port) = split /:/, $target, 2;
    my $pid = fork;
    croak "fork: $!" unless defined $pid;
    if ($pid == 0) {
        # child: run socat, replacing this process
        POSIX::setsid();
        open STDIN,  '<', '/dev/null';
        open STDOUT, '>>', '/dev/null';
        open STDERR, '>>', '/dev/null';
        exec 'socat',
            "TCP-LISTEN:$slot,bind=127.0.0.1,fork,reuseaddr",
            "TCP:$ip:$port";
        exit 127;
    }
    # parent: tiny grace period, then check it didn't exit immediately
    select(undef, undef, undef, 0.1);
    if (waitpid($pid, POSIX::WNOHANG()) == $pid) {
        croak "socat exited immediately (rc=" . ($? >> 8) . ")";
    }
    return {
        method => 'socat',
        slot   => $slot,
        target => $target,
        pid    => $pid,
    };
}

sub _socat_remove {
    my ($self, $f) = @_;
    my $pid = $f->{pid} or return 1;
    kill 'TERM', $pid;
    # Brief wait for it to die; SIGKILL if it doesn't.
    for (1..10) {
        return 1 if waitpid($pid, POSIX::WNOHANG()) == $pid;
        select(undef, undef, undef, 0.05);
    }
    kill 'KILL', $pid;
    waitpid($pid, 0);
    return 1;
}

1;
