package NetMgr::Client;
# Synchronous client for the net-mgr socket protocol.
# Used by net-poll-ap, net-report, and the compat shims.

use strict;
use warnings;
use Carp qw(croak);
use IO::Socket::INET;
use NetMgr::Protocol qw(parse_line format_kv);

sub new {
    my ($class, %args) = @_;
    my $listen = $args{listen} // $ENV{NET_MGR_LISTEN} // '127.0.0.1:7531';
    # Default port to 7531 so '--listen zmc1' / '--listen zmc1.grfx.com'
    # both work without spelling out the port every time.
    my ($host, $port) = split /:/, $listen, 2;
    $port //= 7531;
    $port  =  7531 if $port eq '';
    my $timeout = $args{timeout} // 10;
    my $sock = IO::Socket::INET->new(
        PeerAddr => $host,
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => $timeout,
    ) or croak "connect $host:$port: $!";
    return bless { sock => $sock, buf => '', listen => "$host:$port" }, $class;
}

sub send_line {
    my ($self, $line) = @_;
    print { $self->{sock} } "$line\n";
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

# Send a line and return the next reply line.
sub send_recv {
    my ($self, $line) = @_;
    $self->send_line($line);
    return $self->recv_line;
}

# Convenience: send HELLO, expect OK.
sub hello {
    my ($self, %args) = @_;
    my $r = $self->send_recv("HELLO " . format_kv(%args));
    croak "HELLO failed: $r" unless defined $r && $r =~ /^OK\b/;
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
