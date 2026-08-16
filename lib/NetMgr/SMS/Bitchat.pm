package NetMgr::SMS::Bitchat;
# Last-resort relay: DM a paired phone over BLE and ask IT to send the SMS.
#
# This is the only path that needs neither internet nor any wiring at all — it
# rides the BitChat mesh, which is radio between devices in range. When both
# uplinks are dark and no modem is fitted, this is what is left.
#
#   [provider:bitchat]
#   type     = bitchat
#   peer     = 92dce4b2d4b5f9cf     16-hex peer_id, or a nickname
#   listen   = 127.0.0.1:7531       local net-mgr daemon
#   prefix   = SMS:                 how the phone recognises a relay request
#   max_age  = 900                  seconds; refuse if the peer went quiet
#
# HONEST LIMITATION, stated here because it decides whether this is worth
# configuring at all: the phone must be running something that understands the
# request and is permitted to send an SMS. The net-chat-android client has NO
# SMS capability today — no SEND_SMS permission, no SmsManager anywhere in the
# tree — so until that is added this provider delivers a message to a phone and
# a human acts on it. That is still useful (it escapes a total outage, which
# nothing else here does), but it is a page, not an automated SMS, and
# available() will not pretend otherwise.
#
# The recipient number is included in the DM text rather than being implied, so
# a human reading it on the phone knows who to forward to.

use strict;
use warnings;

sub new {
    my ($class, %a) = @_;
    my $cfg = $a{cfg} || {};
    die "peer is required\n" unless defined $cfg->{peer} && length $cfg->{peer};
    return bless { name => $a{name}, cfg => $cfg }, $class;
}

sub type      { 'bitchat' }
sub needs_net { 0 }          # BLE radio, not IP

# Available only if the local daemon is reachable AND the target peer has been
# heard from recently. A peer_id that was last seen yesterday is not a delivery
# path, and reporting it as available would make the chain stop here instead of
# falling through to something that works.
sub available {
    my ($self) = @_;
    my $c = $self->{cfg};
    my $cli = eval { _client($c->{listen} // '127.0.0.1:7531') }
        or return (0, 'local net-mgr daemon not reachable');
    my $peers = eval { $cli->snapshot(1, 'bitchat_peers') } || [];
    eval { $cli->bye };
    my $want = lc $c->{peer};
    my $max  = $c->{max_age} // 900;
    for my $p (@$peers) {
        next unless lc($p->{peer_id} // '') eq $want
                 || lc($p->{nickname} // '') eq $want;
        my $age = _age_seconds($p->{last_seen});
        return (0, "peer $c->{peer} last seen ${age}s ago (>${max}s)")
            if defined $age && $age > $max;
        return (1, '');
    }
    return (0, "peer $c->{peer} not in bitchat_peers");
}

sub send {
    my ($self, $to, $text) = @_;
    my $c   = $self->{cfg};
    my $cli = eval { _client($c->{listen} // '127.0.0.1:7531') }
        or return (0, 'local net-mgr daemon not reachable');
    my $body = ($c->{prefix} // 'SMS:') . " $to $text";
    my $r = eval { $cli->observe(kind => 'bitchat_dm',
                                 peer_id => $c->{peer}, text => $body) };
    my $err = $@;
    eval { $cli->bye };
    return (0, "dm failed: $err") if $err;
    return (0, "dm rejected: $r") if !defined $r || $r =~ /^ERR/;
    return (1, "relayed to $c->{peer}");
}

sub _client {
    my ($listen) = @_;
    require NetMgr::Client;
    my $cli = NetMgr::Client->new(listen => $listen, timeout => 8) or return undef;
    $cli->hello(consumer => "net-sms.$$");
    return $cli;
}

# 'YYYY-MM-DD HH:MM:SS' -> seconds ago, or undef if unparseable.
sub _age_seconds {
    my ($ts) = @_;
    return undef unless defined $ts && $ts =~ /^(\d{4})-(\d\d)-(\d\d)[ T](\d\d):(\d\d):(\d\d)/;
    require Time::Local;
    my $t = eval { Time::Local::timelocal($6, $5, $4, $3, $2 - 1, $1) };
    return undef unless defined $t;
    return time - $t;
}

1;
