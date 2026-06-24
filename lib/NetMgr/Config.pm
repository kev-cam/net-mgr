package NetMgr::Config;
# Loads /etc/net-mgr/config (INI-style) into a nested hashref. A per-user file
# (~/.config/net-mgr/config) overlays it for the parts client tools read —
# notably [servers]; see user_path() and servers().
#
# Sections:
#   [manager]   listen, log
#   [mysql]     db, defaults, section
#   [scanner]   networks, presence_interval, discover_interval, reprobe_ports
#   [ap_poll]   interval, ssh_timeout
#   [timeouts]  ap, fping, nmap, dhcp     (dhcp may be 'lease')
#   [paths]     dnsmasq_conf_glob, oui_csv
#   [bindings]  machine "<name>" = mac1, mac2, ...
#   [servers]   <name> = host[:port], plus default = <name>  (client tools)
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
        # Canonical location (alongside the rest of /etc/net-mgr). The generic
        # /root/.my.cnf is deprecated; mysql_defaults_file() still falls back
        # to it with a one-time warning so existing installs keep working.
        defaults => '/etc/net-mgr/root.conf',
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
    # How a node keeps its dnsmasq in sync with the federated DB (net-gen-dnsmasq
    # --from-db / net-push-ap). mode: off (default, ignore) | auto (regenerate
    # THIS node's dnsmasq from the DB replica + reload whenever dhcp_reservations
    # change — the gateway path) | command (regen only when told via
    # OBSERVE kind=regen_dnsmasq / `net-cluster regen`). out_dir is where the
    # per-zone files are written (a gateway's include dir). push_aps (master
    # only) also pushes DD-WRT AP static_leases on reservation changes.
    dnsmasq => {
        mode     => 'off',
        out_dir  => '/usr/local/sgy/conf.d',
        push_aps => 0,
        gateways => '',    # space/comma list of DHCP gateways for net-import-dnsmasq --auto
    },
    # Named net-mgr daemons client tools can connect to. Each key is a short
    # name mapped to host[:port]; the special key 'default' names the preferred
    # entry. Usually set in the per-user file (~/.config/net-mgr/config) and
    # read via NetMgr::Config->servers; pick one with `--server NAME`.
    servers => {},
    # net-chat: where a closed session's messages + uploaded files are archived
    # (one <archive_dir>/<name>/ per chat). Lives on the daemon hosting the chat.
    chat => {
        archive_dir => '/var/lib/net-mgr/chat',
    },
    # Fleet deploy targets for `make deploy` (build-time tooling, not read by
    # the daemon). hosts = space/comma list of [user@]host; the knobs apply to
    # every host and map onto install-on's options.
    deploy => {
        hosts     => '',     # e.g. "nas3, bigsony, clevo"
        sudo      => '',     # "sudo" to run the remote install as root
        ssh_opts  => '',     # e.g. "-p 2222 -i ~/.ssh/firewall"
        make_args => '',     # e.g. "FORCE=1"
    },
);

# Per-section, which keys should be coerced to integer seconds.
my %DURATION_KEYS = (
    manager    => { offline_after => 1 },
    scanner    => { presence_interval => 1, discover_interval => 1, reprobe_ports => 1 },
    ap_poll    => { interval => 1, ssh_timeout => 1 },
    timeouts   => { ap => 1, fping => 1, nmap => 1, dhcp => 1 },
    dns        => { ttl => 1 },
    scheduling => { 'scan-ap' => 1, presence => 1, discover => 1,
                    'find-peers' => 1, 'import-leases' => 1, 'push-dnsmasq' => 1 },
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

            # [uplinks]
            #   <label> = <role> <target> [via <iface>] [interval <duration>]
            # role     : 'active' (default 60s) or 'backup' (default 1h)
            # target   : ping target, e.g. 1.1.1.1
            # via      : optional interface to bind ping source to
            # interval : optional override (e.g. 30s, 5m, 1h)
            if ($section eq 'uplinks') {
                if ($line =~ /^([\w-]+)\s*=\s*(.*)$/) {
                    my ($label, $rhs) = ($1, $2);
                    my @t = grep { length } split /\s+/, $rhs;
                    my $role   = (@t && $t[0] =~ /^(active|backup)$/i) ? lc shift @t
                                                                       : 'active';
                    my $target = shift @t;
                    croak "$path:$lineno: [uplinks] $label needs a target"
                        unless defined $target;
                    my ($via, $interval);
                    while (@t) {
                        my $kw = shift @t;
                        if    (lc $kw eq 'via')      { $via      = shift @t }
                        elsif (lc $kw eq 'interval') { $interval = parse_duration(shift @t) }
                        else {
                            croak "$path:$lineno: [uplinks] $label: unknown token '$kw'";
                        }
                    }
                    $interval //= ($role eq 'backup' ? 3600 : 60);
                    $cfg->{uplinks}{$label} = {
                        role       => $role,
                        target     => $target,
                        via        => $via,
                        interval_s => $interval,
                    };
                    next;
                }
                croak "$path:$lineno: bad [uplinks] line: $line";
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
    manager    => [qw(listen log offline_after event_retention_days repo update_script)],
    mysql      => [qw(db defaults section)],
    scanner    => [qw(presence_interval
                       dnsmasq_event_port dnsmasq_event_check_interval)],
    scheduling => [qw(scan-ap presence discover find-peers import-leases push-dnsmasq)],
    paths      => '*',
    dns        => '*',
    bindings   => '*',                        # parsed for future use
    peers      => '*',                        # consumed by net-mgr-relay
    cluster    => [qw(members role priority prefer_lan internet_facing
                       election_interval proxy_listen control_prefix)],  # cluster role / election
                                              # control_prefix: ULA CIDR scoping
                                              # which v6 'auto' binds for the
                                              # control plane (IPV6-TRANSPORT-SPEC.md)
                                              # proxy_listen: net-mgr-relay's
                                              # loopback REFRESH socket
    uplinks    => '*',                        # consumed by net-uplink-probe
    dhcp       => '*',                        # placeholders used by net-gen-dnsmasq
    dnsmasq    => [qw(mode out_dir push_aps gateways)], # per-node dnsmasq sync (net-gen-dnsmasq --from-db)
    forward    => [qw(method allow_peers)],   # net-connect FORWARD backend
    servers    => '*',                        # client server list (see servers())
    chat       => [qw(archive_dir)],          # net-chat archive location
    deploy     => [qw(hosts sudo ssh_opts make_args)],  # make deploy targets
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

# Resolve the root MySQL option file a caller should hand to NetMgr::DB.
# The generic /root/.my.cnf is deprecated in favour of /etc/net-mgr/root.conf
# (next to the rest of net-mgr's config). Returns the configured/default path
# if readable; else the legacy /root/.my.cnf with a one-time deprecation
# warning; else the canonical path (so a later "not readable" error names it).
my %_mycnf_warned;
sub mysql_defaults_file {
    my ($class, $cfg) = @_;
    my $configured = (ref $cfg eq 'HASH') ? $cfg->{mysql}{defaults} : undef;
    my $canonical  = '/etc/net-mgr/root.conf';
    my $legacy     = '/root/.my.cnf';
    # Try the explicitly-configured path, then the canonical location, then the
    # deprecated /root/.my.cnf. Trying the canonical path even when the config
    # still pins the old one self-heals an existing install whose creds moved to
    # the new file while [mysql] defaults wasn't updated.
    my (@seen, $first);
    for my $p ($configured, $canonical, $legacy) {
        next unless defined $p && length $p;
        next if grep { $_ eq $p } @seen;
        push @seen, $p;
        $first //= $p;
        next unless -r $p;
        warn "net-mgr: using legacy MySQL option file '$p' "
           . "(deprecated — move it to '$canonical')\n"
            if $p eq $legacy && !$_mycnf_warned{$legacy}++;
        return $p;
    }
    return $first // $canonical;   # none readable: name what we looked for first
}

# Path to the per-user config (XDG: $XDG_CONFIG_HOME/net-mgr/config, else
# ~/.config/net-mgr/config). Undef if HOME is unset and XDG isn't given.
sub user_path {
    my $base = $ENV{XDG_CONFIG_HOME};
    $base ||= "$ENV{HOME}/.config" if defined $ENV{HOME} && length $ENV{HOME};
    return undef unless defined $base && length $base;
    return "$base/net-mgr/config";
}

# Merged [servers] from the system config then the per-user config (user wins).
# In list context returns (\%name_to_addr, $default_addr, $default_name);
# %name_to_addr maps a short name to "host:port" and excludes the special
# 'default' key, whose value names the preferred entry.
sub servers {
    my ($class) = @_;
    my %srv;
    my $default_name;
    for my $path ($ENV{NET_MGR_CONF} // '/etc/net-mgr/config', $class->user_path) {
        next unless defined $path && -e $path && -r _;
        my $cfg = eval { $class->load($path) };
        if ($@) { warn "net-mgr: skipping config $path: $@"; next }
        my $s = $cfg->{servers} or next;
        for my $k (keys %$s) {
            if ($k eq 'default') { $default_name = $s->{$k} }
            else                 { $srv{$k}      = $s->{$k} }
        }
    }
    my $default;
    $default = $srv{$default_name}
        if defined $default_name && exists $srv{$default_name};
    return wantarray ? (\%srv, $default, $default_name) : \%srv;
}

# Resolve a server selection to a "host:port" string. $sel may be a name from
# [servers], a literal host[:port], or undef. Returns undef if a given name is
# unknown (caller decides how to complain); undef $sel yields the configured
# default (or undef when none is set).
sub resolve_server {
    my ($class, $sel) = @_;
    my ($srv, $default) = $class->servers;
    return $srv->{$sel} if defined $sel && exists $srv->{$sel};
    return undef        if defined $sel && $sel !~ /[.:]/;   # bare unknown name
    return $sel         if defined $sel && length $sel;      # literal host[:port]
    return $default;                                          # default (maybe undef)
}

# Persist `$key = $value` in [$section] of the per-user config
# (~/.config/net-mgr/config), creating the file/dir/section as needed and
# preserving everything else (an existing $key in that section is replaced).
# Returns the written path; dies on failure.
sub save_user_value {
    my ($class, $section, $key, $value) = @_;
    die "save_user_value: section + key required\n"
        unless defined $section && length $section && defined $key && length $key;
    $value = '' unless defined $value;
    my $path = $class->user_path
        or die "save_user_value: no user config path (set HOME or XDG_CONFIG_HOME)\n";

    my @lines;
    if (-e $path) {
        open my $fh, '<', $path or die "save_user_value: read $path: $!\n";
        @lines = <$fh>;
        close $fh;
    }

    my $sec = lc $section;
    my @out;
    my ($in_sec, $done) = (0, 0);
    for my $line (@lines) {
        if ($line =~ /^\s*\[([^\]]+)\]\s*$/) {
            push @out, "$key = $value\n" if $in_sec && !$done and $done = 1;
            $in_sec = (lc $1 eq $sec) ? 1 : 0;
            push @out, $line;
            next;
        }
        if ($in_sec && $line =~ /^\s*\Q$key\E\s*=/) {
            push @out, "$key = $value\n" unless $done;   # replace existing
            $done = 1;
            next;
        }
        push @out, $line;
    }
    push @out, "$key = $value\n" if $in_sec && !$done and $done = 1;
    unless ($done) {                                      # section absent
        push @out, "\n" if @out && $out[-1] !~ /^\s*$/;
        push @out, "[$section]\n", "$key = $value\n";
    }

    (my $dir = $path) =~ s{/[^/]+$}{};
    if (length $dir && !-d $dir) {
        require File::Path;
        File::Path::make_path($dir);
    }
    my $tmp = "$path.tmp.$$";
    open my $wh, '>', $tmp or die "save_user_value: write $tmp: $!\n";
    print {$wh} @out;
    close $wh or die "save_user_value: close $tmp: $!\n";
    rename $tmp, $path or die "save_user_value: rename $tmp -> $path: $!\n";
    return $path;
}

# Persist the preferred server as `default = <sel>` in [servers]. $sel is a
# server name from [servers] or a literal host[:port].
sub save_default {
    my ($class, $sel) = @_;
    die "save_default: nothing to save\n" unless defined $sel && length $sel;
    return $class->save_user_value('servers', 'default', $sel);
}

1;
