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
