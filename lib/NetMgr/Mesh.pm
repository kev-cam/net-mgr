package NetMgr::Mesh;
# Persistent peer-to-peer mesh on top of the daemon's existing
# IO::Select. Each daemon opens one outbound TCP connection to every
# other [cluster] member, keeps it alive with periodic HEARTBEAT
# lines, and reconnects with exponential backoff when it drops. The
# inbound HEARTBEATs from peers are handled by Manager and routed
# back into `record()` — so this module owns the per-member state
# table no matter which direction the data came in on.
#
# Used by:
#   - Slice C  (this commit) — just the mesh + heartbeats, exposed in
#                              STATUS so operators can see who's up.
#   - Slice D  — election fires on heartbeat / drop events instead of
#                a 60s timer; replaces net-mgr-relay's polling loop.
#   - Slice E  — query forwarding rides the same mesh socket
#                (FORWARD_TO peer=…).
#
# Construction:
#   my $mesh = NetMgr::Mesh->new(
#       select    => $self->{select},   # the daemon's IO::Select
#       self_name => 'kc-qernel',
#       members   => ['kc-qernel','nas3','gateway3'],
#       state_fn  => sub { (role => ..., priority => ..., master => ...) },
#       log       => sub { $self->_log(@_) },
#   );
#
# Owner is expected to call:
#   $mesh->tick($now)                  every main-loop iteration
#   $mesh->handle_readable($fh)        when a ready fd belongs to us
#   $mesh->is_mesh_fd($fd)             to route _handle_readable
#   $mesh->record($member, $kv)        when an inbound HEARTBEAT verb
#                                       was parsed off some client
#   $mesh->snapshot                    for STATUS exposure
#
# State held per member:
#   conn_state : down | up
#   sock       : open socket if connected
#   backoff    : seconds until next reconnect attempt
#   next_try   : earliest time _connect may be retried
#   last_hb_tx : when we last sent a HEARTBEAT on the outbound socket
#   last_hb_rx : last time we received a HEARTBEAT from this member
#                (via either the outbound or an inbound connection)
#   remote     : hashref of the kv from their last heartbeat (role,
#                priority, master, schema_v, …)

use strict;
use warnings;
use IO::Socket::INET;
use Time::HiRes ();

sub new {
    my ($class, %args) = @_;
    my $self = bless {
        select       => $args{select},
        self_name    => $args{self_name},
        members      => $args{members}   || [],
        state_fn     => $args{state_fn},
        log          => $args{log}       || sub {},
        hb_interval  => $args{hb_interval} // 5,    # send HB every 5s
        hb_dead      => $args{hb_dead}     // 30,   # drop if no HB for 30s
        backoff_min  => 1,
        backoff_max  => 60,
        connect_timeout => $args{connect_timeout} // 1,
        port         => $args{port} // 7531,
        peers        => {},
    }, $class;

    for my $m (@{ $self->{members} }) {
        next if $m eq $self->{self_name};
        $self->{peers}{$m} = {
            conn_state => 'down',
            sock       => undef,
            buffer     => '',
            backoff    => $self->{backoff_min},
            next_try   => 0,
            last_hb_tx => 0,
            last_hb_rx => 0,
            remote     => {},
        };
    }
    return $self;
}

# Called once per main-loop iteration. Cheap when nothing's due.
sub tick {
    my ($self, $now) = @_;
    $now //= time;
    for my $name (sort keys %{ $self->{peers} }) {
        my $p = $self->{peers}{$name};
        if ($p->{conn_state} eq 'down') {
            $self->_try_connect($name, $p, $now) if $now >= $p->{next_try};
            next;
        }
        # conn_state eq 'up'
        if ($now - $p->{last_hb_tx} >= $self->{hb_interval}) {
            $self->_send_hb($name, $p, $now);
        }
        # Heartbeat liveness: only kill the socket if we've received at
        # least one HB and then went silent. A brand-new connection
        # that hasn't received its first HB yet shouldn't be reaped on
        # last_hb_rx==0.
        if ($p->{last_hb_rx} > 0
            && ($now - $p->{last_hb_rx}) >= $self->{hb_dead}) {
            $self->_drop($name, $p, 'heartbeat timeout');
        }
    }
}

sub is_mesh_fd {
    my ($self, $fd) = @_;
    for my $p (values %{ $self->{peers} }) {
        return 1 if $p->{sock} && fileno($p->{sock}) == $fd;
    }
    return 0;
}

# Called by Manager when an fd in IO::Select belongs to one of our
# outbound mesh sockets. Reads available bytes, parses heartbeats
# (or any other lines the peer sends back), and updates state.
sub handle_readable {
    my ($self, $fh) = @_;
    my $fd = fileno($fh);
    my $hit_name;
    my $hit_p;
    for my $name (sort keys %{ $self->{peers} }) {
        my $p = $self->{peers}{$name};
        next unless $p->{sock} && fileno($p->{sock}) == $fd;
        $hit_name = $name; $hit_p = $p; last;
    }
    return 0 unless $hit_p;

    my $n = sysread($fh, my $buf, 8192);
    if (!defined $n) {
        return 1 if $!{EAGAIN} || $!{EWOULDBLOCK};
        $self->_drop($hit_name, $hit_p, "read error: $!");
        return 1;
    }
    if ($n == 0) {
        $self->_drop($hit_name, $hit_p, 'eof');
        return 1;
    }
    $hit_p->{buffer} .= $buf;
    while ($hit_p->{buffer} =~ s/^([^\n]*)\n//) {
        $self->_handle_line($hit_name, $hit_p, $1);
    }
    return 1;
}

# Inbound HEARTBEAT verb handler — Manager calls this with the member
# name and parsed kv when a regular client connection sends HEARTBEAT.
# We still update last_hb_rx + remote even if we have no outbound
# socket to that member (the peer's outbound to us is enough).
sub record {
    my ($self, $member, $kv) = @_;
    return unless defined $member && length $member;
    my $p = $self->{peers}{$member};
    if (!$p) {
        # member not in our roster; remember anyway so STATUS can show
        # unconfigured peers reaching out (useful diagnostic)
        $p = $self->{peers}{$member} = {
            conn_state => 'down',     # outbound never tried
            sock       => undef,
            buffer     => '',
            backoff    => $self->{backoff_max},
            next_try   => time + $self->{backoff_max},
            last_hb_tx => 0,
            last_hb_rx => 0,
            remote     => {},
            unconfigured => 1,
        };
    }
    $p->{last_hb_rx} = time;
    $p->{remote}     = { %$kv, rx_at => time };
}

# Snapshot for STATUS / debugging. Returns a hashref:
#   { member => { conn_state, last_hb_tx, last_hb_rx, backoff,
#                 unconfigured?, remote => {...} } }
sub snapshot {
    my ($self) = @_;
    my %out;
    for my $name (sort keys %{ $self->{peers} }) {
        my $p = $self->{peers}{$name};
        $out{$name} = {
            conn_state   => $p->{conn_state},
            last_hb_tx   => $p->{last_hb_tx},
            last_hb_rx   => $p->{last_hb_rx},
            backoff      => $p->{backoff},
            unconfigured => $p->{unconfigured} ? 1 : 0,
            remote       => { %{ $p->{remote} || {} } },
        };
    }
    return \%out;
}

# Compact one-line status used by Manager._handle_status. Example:
#   "kc-qernel:up nas3:up gateway3:down(backoff=8)"
sub summary {
    my ($self) = @_;
    my @parts;
    for my $name (sort keys %{ $self->{peers} }) {
        my $p = $self->{peers}{$name};
        next if $p->{unconfigured};
        my $s = "$name:$p->{conn_state}";
        $s .= "(backoff=$p->{backoff})" if $p->{conn_state} eq 'down';
        push @parts, $s;
    }
    return join(' ', @parts);
}

# Count of peers we believe to be reachable right now (conn_state up
# OR last_hb_rx recent). Used by Slice D to gate quorum.
sub reachable {
    my ($self, $now) = @_;
    $now //= time;
    my $n = 0;
    for my $p (values %{ $self->{peers} }) {
        next if $p->{unconfigured};
        if ($p->{conn_state} eq 'up') { $n++; next }
        if ($p->{last_hb_rx} > 0
            && ($now - $p->{last_hb_rx}) < $self->{hb_dead}) { $n++ }
    }
    return $n;
}

sub shutdown {
    my ($self) = @_;
    for my $name (sort keys %{ $self->{peers} }) {
        my $p = $self->{peers}{$name};
        next unless $p->{sock};
        eval { $self->{select}->remove($p->{sock}) } if $self->{select};
        eval { $p->{sock}->close };
        $p->{sock}       = undef;
        $p->{conn_state} = 'down';
    }
}

# --- internals ------------------------------------------------------

sub _try_connect {
    my ($self, $name, $p, $now) = @_;
    # Bypass for self-loops or member names we can't resolve.
    my $sock = IO::Socket::INET->new(
        PeerAddr => $name,
        PeerPort => $self->{port},
        Proto    => 'tcp',
        Timeout  => $self->{connect_timeout},
    );
    if (!$sock) {
        $self->_bump_backoff($p);
        $p->{next_try} = $now + $p->{backoff};
        return;
    }
    $sock->blocking(0);
    $p->{sock}       = $sock;
    $p->{conn_state} = 'up';
    $p->{backoff}    = $self->{backoff_min};
    $p->{next_try}   = 0;
    $p->{buffer}     = '';
    $p->{last_hb_tx} = 0;
    $p->{last_hb_rx} = 0;
    $self->{select}->add($sock) if $self->{select};
    # Announce ourselves so the receiver's HELLO handler is satisfied.
    # The from_member kv is informational — the receiving daemon's
    # _handle_heartbeat reads `member=` off subsequent HEARTBEAT lines.
    eval {
        syswrite($sock, "HELLO consumer=mesh:$self->{self_name}\n");
    };
    # First HB right away so the peer sees us promptly.
    $self->_send_hb($name, $p, $now);
    $self->{log}->("mesh: connected to $name fd=" . fileno($sock));
}

sub _send_hb {
    my ($self, $name, $p, $now) = @_;
    return unless $p->{sock};
    my %kv = ('member' => $self->{self_name});
    if ($self->{state_fn}) {
        my %s = $self->{state_fn}->();
        @kv{ keys %s } = values %s;
    }
    my $line = 'HEARTBEAT '
             . join(' ', map { my $v = $kv{$_} // ''; "$_=$v" } sort keys %kv);
    my $ok = eval { syswrite($p->{sock}, "$line\n") };
    if (!defined $ok) {
        $self->_drop($name, $p, "write error: $!");
        return;
    }
    $p->{last_hb_tx} = $now;
}

sub _handle_line {
    my ($self, $name, $p, $line) = @_;
    return if $line eq '';
    # We expect HEARTBEAT lines back from the peer (peers HB in both
    # directions). Anything else we tolerate but ignore — keeps us
    # forward-compatible if the peer sends OK acks or new verbs.
    if ($line =~ /^HEARTBEAT\b\s*(.*)$/) {
        my $kv = _parse_kv($1);
        my $member = $kv->{member} // $name;
        # Update the peer's state (could be a different member than
        # `$name` if e.g. DNS aliasing — trust the line's member=).
        my $target = $self->{peers}{$member} // $p;
        $target->{last_hb_rx} = time;
        $target->{remote}     = { %$kv, rx_at => time };
    }
    # OK / ERR / anything else: drop silently.
}

sub _parse_kv {
    my ($rest) = @_;
    my %kv;
    while ($rest =~ /\b([a-z_][\w-]*)=("[^"]*"|\S+)/gi) {
        my ($k, $v) = ($1, $2);
        $v =~ s/^"(.*)"$/$1/;
        $kv{$k} = $v;
    }
    return \%kv;
}

sub _bump_backoff {
    my ($self, $p) = @_;
    $p->{backoff} = $p->{backoff} * 2 || $self->{backoff_min};
    $p->{backoff} = $self->{backoff_max}
        if $p->{backoff} > $self->{backoff_max};
}

sub _drop {
    my ($self, $name, $p, $why) = @_;
    $self->{log}->("mesh: drop $name ($why)");
    if ($p->{sock}) {
        eval { $self->{select}->remove($p->{sock}) } if $self->{select};
        eval { $p->{sock}->close };
    }
    $p->{sock}       = undef;
    $p->{buffer}     = '';
    $p->{conn_state} = 'down';
    $self->_bump_backoff($p);
    $p->{next_try}   = time + $p->{backoff};
}

1;
