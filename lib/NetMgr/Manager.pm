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

# Logical tables a SUBSCRIBE may target.
my %SUBSCRIBABLE = map { $_ => 1 } qw(
    machines hostnames interfaces addresses ports aps
    associations dhcp_leases events aliases dhcp_vars
    subnet_routers friendly_names wifi_sockets
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
        listen    => undef,
        select    => undef,
        clients   => {},      # fd → { sock, source/consumer, buffer, peer }
        triggers  => {},      # pid → { cli_fd, name, started_at } pending TRIGGER WAITs
        dnsmasq_listeners => {}, # "host:port" → { sock, host, port, buffer }
        stop      => 0,
    }, $class;
    return $self;
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
    my $listen = $self->{config}{manager}{listen} || '127.0.0.1:7531';
    my ($host, $port) = split /:/, $listen, 2;
    my $sock = IO::Socket::INET->new(
        LocalAddr => $host,
        LocalPort => $port,
        Listen    => 16,
        ReuseAddr => 1,
        Proto     => 'tcp',
    ) or croak "bind $listen: $!";
    $self->{listen} = $sock;
    $self->{select} = IO::Select->new($sock);
    $self->_log("listening on $listen");
    return $sock;
}

sub stop  { $_[0]->{stop} = 1 }

sub run {
    my ($self) = @_;
    $self->start_listener unless $self->{listen};

    local $SIG{INT}  = sub { $self->stop };
    local $SIG{TERM} = sub { $self->stop };
    local $SIG{PIPE} = 'IGNORE';

    while (!$self->{stop}) {
        my @ready = $self->{select}->can_read(1.0);
        for my $fh (@ready) {
            if ($fh == $self->{listen}) {
                $self->_accept;
            } else {
                $self->_handle_readable($fh);
            }
        }
        $self->_reap_triggers          if %{ $self->{triggers} };
        $self->_check_periodic_triggers;
        $self->_age_out_offline;
        $self->_purge_old_events;
        $self->_check_dnsmasq_listeners;
    }
    $self->_log("shutting down");
    for my $c (values %{ $self->{clients} }) {
        eval { $c->{sock}->close };
    }
    eval { $self->{listen}->close };
}

sub _accept {
    my ($self) = @_;
    my $cli = $self->{listen}->accept or return;
    $cli->blocking(0);
    my $peer = sprintf "%s:%d", $cli->peerhost // '?', $cli->peerport // 0;
    my $fd   = fileno($cli);
    $self->{clients}{$fd} = {
        sock   => $cli,
        peer   => $peer,
        buffer => '',
        kind   => undef,    # 'producer' | 'consumer'
        ident  => undef,    # source=... or consumer=...
        subs   => {},       # id → { table, mode, where_ast }
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
    $self->{select}->remove($cli->{sock});
    eval { $cli->{sock}->close };
    $self->_log("disconnect $cli->{peer} fd=$fd ($why)");
}

sub _send {
    my ($self, $cli, $line) = @_;
    return unless $cli && $cli->{sock};
    my $data = "$line\n";
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
    elsif ($verb eq 'BYE')       { $self->_drop_client(fileno($cli->{sock}), 'bye') }
    else {
        $self->_send($cli, format_err("verb $verb not handled"));
    }
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
    $self->_log("hello $cli->{peer} $cli->{kind}=$cli->{ident}");
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
        unless $SUBSCRIBABLE{$table};

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
        my $rows = $self->{db}->query_table($table, %qopts);
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
            close $self->{listen} if $self->{listen};
            $ENV{NET_MGR_LISTEN} = $self->{config}{manager}{listen}
                                // '127.0.0.1:7531';
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
            close $self->{listen} if $self->{listen};
            $ENV{NET_MGR_LISTEN} = $self->{config}{manager}{listen}
                                // '127.0.0.1:7531';
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
            close $self->{listen} if $self->{listen};
            $ENV{NET_MGR_LISTEN} = $self->{config}{manager}{listen}
                                // '127.0.0.1:7531';
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

    for my $name (qw(scan-ap presence discover)) {
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
        elsif ($kind eq 'port')        { @events = $self->_obs_port($cli, $kv) }
        elsif ($kind eq 'ping')        { @events = $self->_obs_ping($cli, $kv) }
        elsif ($kind eq 'event')       { @events = $self->_obs_event($cli, $kv) }
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

    my $r = $self->{db}->update_rtt(
        mac => $mac, addr => $addr, family => 'v4', rtt_ms => $rtt
    );
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

1;
