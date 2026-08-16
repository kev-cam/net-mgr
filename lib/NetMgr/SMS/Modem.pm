package NetMgr::SMS::Modem;
# SMS via a local cellular modem, using gammu.
#
# The only provider here that needs no network of any kind: a USB LTE stick with
# its own SIM will send while every uplink is down, which is precisely when the
# message matters. gammu and ModemManager are already installed on gateway2;
# what is missing is hardware (mmcli -L reports no modems, and there is no
# /dev/ttyUSB*), so this provider will report itself unavailable until a stick
# is plugged in — which is the correct behaviour, not an error.
#
#   [provider:modem]
#   type    = modem
#   device  = /dev/ttyUSB0        optional; gammu uses its own config otherwise
#   config  = /etc/gammurc        optional gammu config file
#   timeout = 30
#
# gammu is preferred over raw AT commands: it handles PDU encoding, multipart
# messages and the modem's own quirks. Sending raw AT+CMGS by hand gets the
# encoding wrong for anything non-ASCII and silently truncates at 160 chars.

use strict;
use warnings;

sub new {
    my ($class, %a) = @_;
    return bless { name => $a{name}, cfg => $a{cfg} || {} }, $class;
}

sub type     { 'modem' }
sub needs_net { 0 }          # the entire point of this one

sub available {
    my ($self) = @_;
    my $g = _which('gammu') or return (0, 'gammu not installed');
    my $dev = $self->{cfg}{device};
    if (defined $dev && length $dev) {
        return (0, "device $dev not present") unless -e $dev;
    }
    else {
        # No explicit device: make sure SOMETHING modem-shaped exists, rather
        # than letting gammu spend its timeout discovering there is nothing.
        my @cand = (glob('/dev/ttyUSB*'), glob('/dev/ttyACM*'), glob('/dev/gsmmodem*'));
        return (0, 'no /dev/ttyUSB*, ttyACM* or gsmmodem* present') unless @cand;
    }
    return (1, '');
}

sub send {
    my ($self, $to, $text) = @_;
    my $g = _which('gammu') or return (0, 'gammu not installed');
    my @cmd = ($g);
    push @cmd, '-c', $self->{cfg}{config} if $self->{cfg}{config};
    push @cmd, 'sendsms', 'TEXT', $to, '-text', $text;

    my $pid = open(my $fh, '-|');
    return (0, 'fork failed') unless defined $pid;
    if (!$pid) { open STDERR, '>&', \*STDOUT; exec @cmd; exit 127 }
    local $/;
    my $out = <$fh> // '';
    close $fh;
    my $rc = $? >> 8;
    $out =~ s/\s+/ /g;
    return $rc == 0 ? (1, 'gammu ok')
                    : (0, "gammu rc=$rc " . substr($out, 0, 120));
}

sub _which {
    my ($p) = @_;
    for my $d (split /:/, ($ENV{PATH} // '')) { return "$d/$p" if -x "$d/$p" }
    return undef;
}

1;
