package NetMgr::Config;
# Loads /etc/net-mgr/config (INI-style) into a nested hashref.
#
# Sections:
#   [manager]   listen, log
#   [mysql]     db, defaults, section
#   [scanner]   networks, presence_interval, discover_interval, reprobe_ports
#   [ap_poll]   interval, ssh_timeout
#   [timeouts]  ap, fping, nmap, dhcp     (dhcp may be 'lease')
#   [paths]     dnsmasq_conf_glob, oui_csv
#   [bindings]  machine "<name>" = mac1, mac2, ...
#
# Durations: '90s', '5m', '24h', '7d', '2w' → seconds. 'lease' kept as-is.
# Defaults are merged so callers can rely on every documented key existing.

use strict;
use warnings;
use Carp qw(croak);

my %DEFAULTS = (
    manager => {
        # 'auto' = bind to every 192.168.*.* address on this host, plus
        # 127.0.0.1, all on the default port. Override with a comma-
        # separated list of host[:port] entries (e.g. on a firewall:
        # listen = 192.168.15.1:7531). 0.0.0.0:PORT also still works
        # for the legacy "bind everywhere" behaviour.
        listen        => 'auto',
        log           => '/var/log/net-mgr.log',
        # Flip interfaces.online back to 0 when last_seen is older than
        # this many seconds. Combined with the periodic scan-ap /
        # presence triggers (in [scheduling]), keeps online accurate.
        offline_after => 300,
    },
    mysql => {
        db       => 'netmgr',
        defaults => '/root/.my.cnf',
        section  => 'net-mgr',
    },
    scanner => {
        networks          => 'auto',
        presence_interval => 90,
        discover_interval => 86400,
        reprobe_ports     => 604800,
    },
    ap_poll => {
        interval    => 60,
        ssh_timeout => 10,
    },
    timeouts => {
        ap    => 120,
        fping => 180,
        nmap  => 86400,
        dhcp  => 'lease',
    },
    paths => {
        dnsmasq_conf_glob => '/usr/local/sgy/conf.d/dnsmasq-*',
        oui_csv           => '/var/lib/ieee-data/oui.csv',
    },
    bindings => {
        machines => {},
    },
    dns => {
        listen   => '0.0.0.0:53',   # primary bind
        fallback => 5333,           # tried if primary fails (perms or busy);
                                    # 5353 collides with mDNS/avahi
        upstream => 'auto',         # 'auto' = parse /etc/resolv.conf
        ttl      => 60,             # seconds for replies we generate
        domain   => '',             # e.g. 'grfx.com' for FQDN handling
    },
    # Opt-in periodic TRIGGERs the daemon fires on its own.
    # 0 = disabled. Set seconds in /etc/net-mgr/config [scheduling].
    scheduling => {
        'scan-ap' => 0,
        presence  => 0,
        discover  => 0,
    },
    # Output directory for net-gen-dnsmasq. Placeholder values
    # themselves live in the dhcp_vars DB table — manage with net-var(1).
    dhcp => {
        out_dir => '/etc/net-mgr/dnsmasq.d',
    },
);

# Per-section, which keys should be coerced to integer seconds.
my %DURATION_KEYS = (
    manager    => { offline_after => 1 },
    scanner    => { presence_interval => 1, discover_interval => 1, reprobe_ports => 1 },
    ap_poll    => { interval => 1, ssh_timeout => 1 },
    timeouts   => { ap => 1, fping => 1, nmap => 1, dhcp => 1 },
    dns        => { ttl => 1 },
    scheduling => { 'scan-ap' => 1, presence => 1, discover => 1 },
);

sub load {
    my ($class, $path) = @_;
    $path //= $ENV{NET_MGR_CONF} // '/etc/net-mgr/config';
    my $cfg = _deep_copy(\%DEFAULTS);

    if (-e $path) {
        open my $fh, '<', $path or croak "open $path: $!";
        my $section;
        my $lineno = 0;
        while (my $line = <$fh>) {
            $lineno++;
            $line =~ s/[\r\n]+\z//;
            $line =~ s/^\s+//;
            $line =~ s/\s+$//;
            next if $line eq '' || $line =~ /^[#;]/;
            if ($line =~ /^\[([^\]]+)\]\s*$/) {
                $section = lc $1;
                $cfg->{$section} //= {};
                next;
            }
            croak "$path:$lineno: line outside any section: $line" unless defined $section;

            if ($section eq 'bindings') {
                if ($line =~ /^machine\s+"([^"]+)"\s*=\s*(.*)$/) {
                    my ($name, $rhs) = ($1, $2);
                    my @macs = grep { length } map { s/^\s+|\s+$//gr } split /,/, $rhs;
                    $cfg->{bindings}{machines}{$name} = [ map { lc } @macs ];
                    next;
                }
                croak "$path:$lineno: bad [bindings] line: $line";
            }

            if ($line =~ /^([A-Za-z_][\w-]*)\s*=\s*(.*)$/) {
                my ($k, $v) = ($1, $2);
                $v =~ s/^"(.*)"$/$1/;
                if ($DURATION_KEYS{$section} && $DURATION_KEYS{$section}{$k}) {
                    $v = parse_duration($v);
                }
                $cfg->{$section}{$k} = $v;
                next;
            }
            croak "$path:$lineno: unparseable line: $line";
        }
        close $fh;
    }

    return $cfg;
}

# 90s, 5m, 24h, 7d, 2w → seconds. Bare integer → seconds. 'lease' kept.
# Returns the original string for any non-numeric token (e.g. 'lease').
sub parse_duration {
    my ($v) = @_;
    return $v unless defined $v;
    $v =~ s/^\s+|\s+$//g;
    return 0 if $v eq '';
    if ($v =~ /^(\d+)\s*(s|sec|second|seconds)?$/i) { return $1 + 0 }
    if ($v =~ /^(\d+)\s*(m|min|minute|minutes)$/i)  { return $1 * 60 }
    if ($v =~ /^(\d+)\s*(h|hr|hour|hours)$/i)       { return $1 * 3600 }
    if ($v =~ /^(\d+)\s*(d|day|days)$/i)            { return $1 * 86400 }
    if ($v =~ /^(\d+)\s*(w|wk|week|weeks)$/i)       { return $1 * 604800 }
    return $v;   # non-numeric tokens like 'lease' pass through
}

sub _deep_copy {
    my ($x) = @_;
    if (ref $x eq 'HASH')  { return { map { $_ => _deep_copy($x->{$_}) } keys %$x } }
    if (ref $x eq 'ARRAY') { return [ map { _deep_copy($_) } @$x ] }
    return $x;
}

# Sections/keys actually consumed by code at runtime. Anything in a
# user's config not on this list is reported by `dead_keys()` as
# probably-vestigial — used by `make install` to warn about leftover
# keys that the daemon silently ignores.
#
# Keep in sync with the grep:
#   grep -rE '\$cfg->\{|config\}\{' lib bin sbin
my %ACTIVE = (
    manager    => [qw(listen log offline_after event_retention_days)],
    mysql      => [qw(db defaults section)],
    scanner    => [qw(presence_interval
                       dnsmasq_event_port dnsmasq_event_check_interval)],
    scheduling => [qw(scan-ap presence discover)],
    paths      => '*',
    dns        => '*',
    bindings   => '*',                        # parsed for future use
    dhcp       => '*',                        # placeholders used by net-gen-dnsmasq
);

# Returns a list of "[section] key" strings for entries in $path that
# the runtime code doesn't read. Empty list = config is clean.
sub dead_keys {
    my ($path) = @_;
    $path //= $ENV{NET_MGR_CONF} // '/etc/net-mgr/config';
    return () unless -e $path;
    open my $fh, '<', $path or return ();
    my $section;
    my @dead;
    while (my $line = <$fh>) {
        $line =~ s/[\r\n]+\z//;
        $line =~ s/^\s+//;
        $line =~ s/\s+$//;
        next if $line eq '' || $line =~ /^[#;]/;
        if ($line =~ /^\[([^\]]+)\]\s*$/) { $section = lc $1; next; }
        next unless defined $section;
        next unless $line =~ /^([\w-]+)\s*=/;
        my $key = $1;
        my $allowed = $ACTIVE{$section};
        if (!$allowed) {
            push @dead, "[$section] (whole section unused)";
        } elsif ($allowed ne '*' && !grep { $_ eq $key } @$allowed) {
            push @dead, "[$section] $key";
        }
    }
    close $fh;
    my %seen;
    return grep { !$seen{$_}++ } @dead;
}

1;
