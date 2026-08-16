package NetMgr::SMS;
# Modular SMS sending: try each configured mechanism in turn until one works.
#
# The point of the fallback chain is that the messages you most want to send are
# the ones sent while something is broken. A single provider is therefore not
# enough — a web service cannot tell you the internet is down. Providers declare
# whether they need internet, and the chain skips the ones that cannot possibly
# work right now rather than spending their timeout discovering it. That matters:
# five web providers at a 15s timeout each is 75s of silence before the modem
# that would have worked is even tried.
#
#   my $sms = NetMgr::SMS->load;                 # /etc/net-mgr/sms.conf
#   my ($ok, $via, $log) = $sms->send('+15551234567', 'gateway3 down');
#
# Config (INI). `order` decides preference; anything not listed is not used:
#
#   [sms]
#   order   = lterouter, numberbarn, gvoice, modem, bitchat
#   from    = net-mgr
#   dry_run = 0
#
#   [provider:lterouter]
#   type = http
#   ...   (see NetMgr::SMS::HttpForm for the http keys)
#
# Providers live in NetMgr::SMS::<Type> and implement three methods:
#   new(name => $n, cfg => \%cfg)
#   available()          -> ($ok, $why)     cheap, no message sent
#   send($to, $text)     -> ($ok, $detail)
# plus needs_net() returning 1 if the provider requires working internet.

use strict;
use warnings;

our $CONF = '/etc/net-mgr/sms.conf';

# config `type =` -> implementing module under NetMgr::SMS::
our %TYPE = (
    http    => 'NetMgr::SMS::HttpForm',   # any web API or LAN device web UI
    modem   => 'NetMgr::SMS::Modem',      # local cellular modem via gammu
    bitchat => 'NetMgr::SMS::Bitchat',    # ask a paired phone over BLE to relay
);

sub load {
    my ($class, %a) = @_;
    my $path = $a{config} // $CONF;
    my $cfg  = _read_ini($path);
    my $self = bless {
        path    => $path,
        general => $cfg->{sms} || {},
        raw     => $cfg,
        dry_run => $a{dry_run} // ($cfg->{sms}{dry_run} ? 1 : 0),
    }, $class;
    $self->{providers} = $self->_build($cfg);
    return $self;
}

sub _build {
    my ($self, $cfg) = @_;
    my @order = grep { length } map { s/^\s+|\s+$//gr }
                split /\s*,\s*/, ($cfg->{sms}{order} // '');
    my @out;
    for my $name (@order) {
        my $pc = $cfg->{"provider:$name"};
        unless ($pc) {
            push @out, { name => $name, err => "no [provider:$name] section" };
            next;
        }
        my $type = lc($pc->{type} // '');
        # Explicit map rather than ucfirst($type): the config word and the
        # module name should be free to differ (type=http is friendlier than
        # type=httpform), and an unknown type must fail by name, not by
        # attempting to require whatever the user typed.
        my $mod = $TYPE{$type};
        unless ($mod) {
            push @out, { name => $name,
                         err => "unknown type '" . ($pc->{type} // '') . "'"
                              . " (known: " . join(', ', sort keys %TYPE) . ")" };
            next;
        }
        my $obj = eval {
            (my $f = $mod) =~ s{::}{/}g;
            require "$f.pm";
            $mod->new(name => $name, cfg => $pc);
        };
        if ($@ || !$obj) {
            my $e = $@ || 'constructor returned nothing';
            $e =~ s/\s+at\s+\S+\s+line\s+\d+\.?\s*$//;
            push @out, { name => $name, err => "$mod: $e" };
            next;
        }
        push @out, { name => $name, obj => $obj };
    }
    return \@out;
}

# Cheap "can anything reach the internet" test, done ONCE per send rather than
# per provider. Deliberately not a DNS lookup: DNS is itself one of the things
# that breaks, and a resolver timeout would be misread as no internet.
sub have_net {
    my ($self) = @_;
    return $self->{_net} if defined $self->{_net};
    my $ok = 0;
    for my $t (qw(1.1.1.1 9.9.9.9)) {
        my $rc = system("ping -c1 -W2 -q $t >/dev/null 2>&1");
        if ($rc == 0) { $ok = 1; last }
    }
    return $self->{_net} = $ok;
}

# Returns ($ok, $provider_name_or_undef, \@log). @log has one line per attempt
# so the caller can report exactly what was tried and why each one was passed
# over — a notifier that says only "failed" is not debuggable at 3am.
sub send {
    my ($self, $to, $text, %o) = @_;
    my @log;
    return (0, undef, ["no recipient"])     unless defined $to   && length $to;
    return (0, undef, ["empty message"])    unless defined $text && length $text;
    unless (@{ $self->{providers} }) {
        return (0, undef, ["no providers configured in $self->{path}"]);
    }
    my $dry = $o{dry_run} // $self->{dry_run};

    for my $p (@{ $self->{providers} }) {
        if ($p->{err}) { push @log, "$p->{name}: skipped ($p->{err})"; next }
        my $obj = $p->{obj};
        if ($obj->needs_net && !$self->have_net) {
            push @log, "$p->{name}: skipped (needs internet, none available)";
            next;
        }
        my ($avail, $why) = $obj->available;
        unless ($avail) {
            push @log, "$p->{name}: unavailable ($why)";
            next;
        }
        if ($dry) {
            push @log, "$p->{name}: DRY-RUN would send";
            return (1, $p->{name}, \@log);
        }
        my ($ok, $detail) = eval { $obj->send($to, $text) };
        if ($@) { my $e = $@; $e =~ s/\s+$//; push @log, "$p->{name}: died ($e)"; next }
        if ($ok) { push @log, "$p->{name}: SENT" . ($detail ? " ($detail)" : ''); return (1, $p->{name}, \@log) }
        push @log, "$p->{name}: failed" . ($detail ? " ($detail)" : '');
    }
    return (0, undef, \@log);
}

# For `net-sms providers`: what would be tried, in order, and why not.
sub status {
    my ($self) = @_;
    my @rows;
    for my $p (@{ $self->{providers} }) {
        if ($p->{err}) {
            push @rows, { name => $p->{name}, type => '-', ok => 0, why => $p->{err} };
            next;
        }
        my $obj = $p->{obj};
        my ($ok, $why);
        if ($obj->needs_net && !$self->have_net) { ($ok, $why) = (0, 'needs internet, none available') }
        else                                     { ($ok, $why) = $obj->available }
        push @rows, { name => $p->{name}, type => $obj->type,
                      ok => ($ok ? 1 : 0), why => ($why // ''),
                      needs_net => $obj->needs_net };
    }
    return \@rows;
}

# ---- tiny INI reader ------------------------------------------------
# Sections become top-level keys; `[provider:foo]` is just a section name.
sub _read_ini {
    my ($path) = @_;
    my %c;
    open my $fh, '<', $path or return \%c;
    my $sec = 'sms';
    while (my $l = <$fh>) {
        $l =~ s/\r?\n$//;
        next if $l =~ /^\s*[#;]/ || $l =~ /^\s*$/;
        if ($l =~ /^\s*\[([^\]]+)\]\s*$/) { $sec = lc $1; next }
        next unless $l =~ /^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$/;
        $c{$sec}{lc $1} = $2;
    }
    close $fh;
    return \%c;
}

1;
