#!/usr/bin/perl
# net-mgr-web.cgi — read-only HTML view of net-mgr's machine/port data.
#
# Views, selected by query string:
#   /net-mgr                    compact list: name + clickable service badges
#   /net-mgr?m=<id>             machine detail (MAC/vendor/IPs/ports)
#   /net-mgr?i=<mac>            unaffiliated interface detail
#   /net-mgr?view=tools         list of dashboard tools
#   /net-mgr?view=flake         disconnect histogram (range=1h|4h|24h|1w|4w)
#   /net-mgr?view=flakers       host ranking by disconnect count (same range=)
#   /net-mgr?view=lost          devices found by net-find-lost
#
# Connects to the manager socket (no DB credentials needed). Apache
# handles auth + IP restriction via the matching net-mgr.conf snippet.

use strict;
use warnings;
use lib '/usr/local/share/perl5';
use CGI qw(escapeHTML);
use Time::Local qw(timelocal);
use NetMgr::Client;

print "Content-Type: text/html; charset=utf-8\n\n";

# Query parsing first so views can decide which snapshots they need.
my %q;
for my $kv (split /&/, $ENV{QUERY_STRING} // '') {
    my ($k, $v) = split /=/, $kv, 2;
    next unless defined $k;
    $v //= '';
    $v =~ s/%([0-9A-Fa-f]{2})/chr hex $1/ge;
    $q{$k} = $v;
}

my $cli = eval { NetMgr::Client->new(listen => '127.0.0.1:7531') };
if (!$cli || $@) {
    print render_error("can't reach net-mgr daemon", $@);
    exit 0;
}
$cli->hello(consumer => "net-mgr-web.$$");

# Range presets for the disconnect histogram. Each entry defines the
# total span, bucket size, x-tick stride (in buckets), per-bucket time
# label format, and a human-readable bucket-unit string used in tooltips
# and the summary line. Defined before the routing block below so
# render_flake() (called from there) sees the hash populated.
my %FLAKE_RANGES = (
    '1h' => { label => '1 hour',   span => 3600,        bucket =>    60,
              tick => 10, tfmt => '%H:%M', unit => 'minute' },
    '4h' => { label => '4 hours',  span => 4*3600,      bucket =>   300,
              tick =>  6, tfmt => '%H:%M', unit => '5 minutes' },
    '24h'=> { label => '24 hours', span => 86400,       bucket =>  3600,
              tick =>  3, tfmt => '%H:00', unit => 'hour' },
    '1w' => { label => '1 week',   span => 7*86400,     bucket => 6*3600,
              tick =>  4, tfmt => '%a %H:00', unit => '6 hours' },
    '4w' => { label => '4 weeks',  span => 28*86400,    bucket => 86400,
              tick =>  7, tfmt => '%m-%d',  unit => 'day' },
);
my @FLAKE_ORDER = qw(1h 4h 24h 1w 4w);

# Lightweight views (don't need the full inventory).
if (defined $q{view} && $q{view} eq 'tools') {
    print render_tools();
    $cli->bye;
    exit 0;
}
if (defined $q{view} && $q{view} eq 'flake') {
    print render_flake();
    $cli->bye;
    exit 0;
}
if (defined $q{view} && $q{view} eq 'flakers') {
    print render_flakers();
    $cli->bye;
    exit 0;
}
if (defined $q{view} && $q{view} eq 'dhcp') {
    print render_dhcp();
    $cli->bye;
    exit 0;
}
if (defined $q{view} && $q{view} eq 'lost') {
    print render_lost();
    $cli->bye;
    exit 0;
}

my $machines  = $cli->snapshot(1, 'machines');
my $hostnames = $cli->snapshot(2, 'hostnames');
my $ifaces    = $cli->snapshot(3, 'interfaces');
my $addresses = $cli->snapshot(4, 'addresses', where => "family = 'v4'");
my $ports     = $cli->snapshot(5, 'ports');
my $aps       = $cli->snapshot(6, 'aps');
my $aliases   = $cli->snapshot(7, 'aliases');
my $friendly  = $cli->snapshot(8, 'friendly_names');

# For the iface-detail route, also pull recent events for that MAC so
# we can show some history on otherwise-anonymous interfaces. Bounded
# to 30d so the snapshot stays small.
my $iface_events;
if (defined $q{i}) {
    my $imac = lc $q{i};
    (my $safe = $imac) =~ s/'/''/g;
    $iface_events = $cli->snapshot(9, 'events',
        where => "mac = '$safe' AND ts > ago(2592000)");
}
$cli->bye;

# Indexes ------------------------------------------------------------

my %machine_by_id = map { $_->{id} => $_ } @$machines;
my %hostnames_by_machine;
push @{ $hostnames_by_machine{ $_->{machine_id} } }, $_->{name} for @$hostnames;
my %friendly_by_machine = map { $_->{machine_id} => $_->{name} } @$friendly;

my %addrs_by_mac;
push @{ $addrs_by_mac{ $_->{mac} } }, $_ for @$addresses;
my %ports_by_mac;
push @{ $ports_by_mac{ $_->{mac} } }, $_ for @$ports;
my %ap_by_mac = map { $_->{mac} => $_ } @$aps;
my %aliases_by_machine;
push @{ $aliases_by_machine{ $_->{machine_id} } }, $_ for @$aliases;

my %iface_by_machine;
my %iface_by_mac;
for my $i (@$ifaces) {
    my $mid = $i->{machine_id} // 0;
    push @{ $iface_by_machine{$mid} }, $i;
    $iface_by_mac{ $i->{mac} } = $i;
}

# Port → (scheme, default-port?). default-port=1 means the scheme has
# a well-known port that should be elided from the URL.
# Defined before the routing call so port_badge sees it populated.
my %SCHEME = (
    80   => ['http',  1],
    443  => ['https', 1],
    8080 => ['http',  0],
    8443 => ['https', 0],
    8000 => ['http',  0],
    22   => ['ssh',   0],
    445  => ['smb',   0],
    139  => ['smb',   0],
    21   => ['ftp',   0],
    3389 => ['rdp',   0],
    5900 => ['vnc',   0],
    5901 => ['vnc',   0],
    5800 => ['http',  0],   # VNC over HTTP
    631  => ['http',  0],   # CUPS
);

if (defined $q{m} && $q{m} =~ /^\d+$/) {
    print render_machine_detail($q{m} + 0);
} elsif (defined $q{i}) {
    print render_iface_detail($q{i});
} else {
    print render_list();
}

# Helpers ------------------------------------------------------------

sub ip_sort_key {
    my $ip = shift // '';
    return '999.999.999.999' unless $ip =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
    return sprintf "%03d.%03d.%03d.%03d", $1, $2, $3, $4;
}

# Pick a representative address for an interface or machine — first
# v4 in IP-sort order, undef if none. Used as the click-through target
# for protocol badges.
sub primary_addr {
    my (@macs) = @_;
    my @all;
    for my $m (@macs) {
        push @all, @{ $addrs_by_mac{$m} || [] };
    }
    return undef unless @all;
    @all = sort { ip_sort_key($a->{addr}) cmp ip_sort_key($b->{addr}) } @all;
    return $all[0]{addr};
}

# Sort tier for the compact list:
#   0 = has at least one HTTP/HTTPS service (most useful click-through)
#   1 = has some other clickable service (ssh/vnc/rdp/etc.)
#   2 = no clickable ports
sub tier {
    my ($ports) = @_;
    my $any_clickable = 0;
    for my $p (@$ports) {
        my $sd = $SCHEME{$p->{port}};
        next unless $sd && (($p->{proto} // 'tcp') eq 'tcp');
        my ($scheme) = @$sd;
        return 0 if $scheme eq 'http' || $scheme eq 'https';
        $any_clickable = 1;
    }
    return $any_clickable ? 1 : 2;
}

sub port_badge {
    my ($port_row, $first_addr) = @_;
    my $port  = $port_row->{port};
    my $proto = $port_row->{proto} // 'tcp';
    my $svc   = $port_row->{service} // '';
    my $label = $svc ne '' ? $svc : $port;
    my $title = "$port/$proto" . ($svc ? " ($svc)" : '');

    my $scheme_def = $SCHEME{$port};
    if ($first_addr && $scheme_def && $proto eq 'tcp') {
        my ($scheme, $default_port) = @$scheme_def;
        my $url = "$scheme://$first_addr"
                . ($default_port ? '' : ":$port");
        return sprintf '<a class=port href="%s" title="%s">%s</a>',
            escapeHTML($url), escapeHTML($title), escapeHTML($label);
    }
    return sprintf '<span class=port title="%s">%s</span>',
        escapeHTML($title), escapeHTML($label);
}

# Aggregate ports across all interfaces of one bucket (machine or
# single-iface) and dedupe by (port, proto). Returns ordered list.
sub aggregate_ports {
    my (@macs) = @_;
    my %seen;
    my @out;
    for my $m (@macs) {
        for my $p (@{ $ports_by_mac{$m} || [] }) {
            my $key = "$p->{port}/$p->{proto}";
            next if $seen{$key}++;
            push @out, $p;
        }
    }
    return sort { $a->{port} <=> $b->{port} } @out;
}

# Display label for a machine row in the compact list. Prefer the
# user-supplied friendly_name; fall back to primary_name; then to a
# hostnames entry; finally to the representative IP.
sub display_label {
    my ($mid, $primary_addr) = @_;
    if (my $f = $friendly_by_machine{$mid}) { return $f }
    my $m = $machine_by_id{$mid};
    if ($m && $m->{primary_name}) { return $m->{primary_name} }
    my $hns = $hostnames_by_machine{$mid};
    if ($hns && @$hns)            { return $hns->[0] }
    return $primary_addr // "(machine $mid)";
}

# Online status: if any iface is online, machine is online.
sub machine_online {
    my ($mid) = @_;
    return grep { $_->{online} } @{ $iface_by_machine{$mid} || [] };
}

# Strip a direction/medium suffix off a machine label to get a "family
# stem" — lets us match mediapc to mediapc-up, amfpc to amfpc-air,
# wndr8k2 to wndr8k2-down, etc. Returns lowercased stem (or empty
# string if there's no usable label).
sub family_stem {
    my ($label) = @_;
    return '' unless defined $label && length $label;
    my $s = lc $label;
    $s =~ s/-(up|down|dwn\d*|air|wired|wifi|eth\d*|wlan\d*)$//;
    return $s;
}

# Distinct /24 subnets a machine has addresses on. Used to label
# sibling links and to decide whether the sibling block is interesting.
sub machine_subnets {
    my ($mid) = @_;
    my %nets;
    for my $iface (@{ $iface_by_machine{$mid} || [] }) {
        for my $a (@{ $addrs_by_mac{ $iface->{mac} } || [] }) {
            next unless $a->{addr} =~ /^(\d+\.\d+\.\d+)\.\d+$/;
            $nets{"$1.0/24"} = 1;
        }
    }
    return sort keys %nets;
}

# Sibling machines: other machine_ids whose display label shares a
# family stem with this one. Returns sorted list of { id, label,
# subnets } hashes. The %_STEM_INDEX cache is built on first call.
my %_STEM_INDEX;
sub sibling_machines {
    my ($mid) = @_;
    if (!%_STEM_INDEX) {
        for my $other_mid (keys %iface_by_machine) {
            next unless $other_mid;
            my @macs = map { $_->{mac} } @{ $iface_by_machine{$other_mid} };
            my $stem = family_stem(display_label($other_mid, primary_addr(@macs)));
            next if $stem eq '';
            push @{ $_STEM_INDEX{$stem} }, $other_mid;
        }
    }
    my @macs = map { $_->{mac} } @{ $iface_by_machine{$mid} || [] };
    my $stem = family_stem(display_label($mid, primary_addr(@macs)));
    return () if $stem eq '';
    my @cands = grep { $_ != $mid } @{ $_STEM_INDEX{$stem} || [] };
    return () unless @cands;

    my @out;
    for my $sid (@cands) {
        my @sm = map { $_->{mac} } @{ $iface_by_machine{$sid} };
        push @out, {
            id      => $sid,
            label   => display_label($sid, primary_addr(@sm)),
            subnets => [ machine_subnets($sid) ],
        };
    }
    return sort { lc $a->{label} cmp lc $b->{label} } @out;
}

# Compact list ------------------------------------------------------

sub render_list {
    # Build (tier, label, html) tuples and sort. Tier 0 = has http/https,
    # 1 = has other clickable service, 2 = no clickable ports.
    my @entries;
    for my $mid (grep { $_ } keys %iface_by_machine) {
        my @macs = map { $_->{mac} } @{ $iface_by_machine{$mid} };
        my $first_addr = primary_addr(@macs);
        my $label = display_label($mid, $first_addr);
        my $online = machine_online($mid) ? 'online' : 'offline';
        my @ports = aggregate_ports(@macs);
        my @port_html = map { port_badge($_, $first_addr) } @ports;
        my $link = sprintf '<a class=hostlink href="?m=%d">%s</a>',
            $mid, escapeHTML($label);
        my $html = sprintf
            '<tr class="%s"><td class=name>%s</td><td>%s</td><td class=ports>%s</td></tr>',
            $online, $link, escapeHTML($first_addr // ''),
            join(' ', @port_html);
        push @entries, [ tier(\@ports), lc $label, $html ];
    }
    for my $iface (@{ $iface_by_machine{0} || [] }) {
        my $mac = $iface->{mac};
        my $first_addr = primary_addr($mac);
        my $label = $first_addr // $mac;
        my @ports = aggregate_ports($mac);
        my @port_html = map { port_badge($_, $first_addr) } @ports;
        my $online = $iface->{online} ? 'online' : 'offline';
        my $link = sprintf '<a class=hostlink href="?i=%s">%s</a>',
            escapeHTML($mac), escapeHTML($label);
        my $html = sprintf
            '<tr class="%s unknown"><td class=name>%s</td><td></td><td class=ports>%s</td></tr>',
            $online, $link, join(' ', @port_html);
        push @entries, [ tier(\@ports), lc $label, $html ];
    }
    @entries = sort { $a->[0] <=> $b->[0] || $a->[1] cmp $b->[1] } @entries;
    my @rows = map { $_->[2] } @entries;

    my $body  = join("\n", @rows);
    my $count = scalar @$machines;
    my $now   = scalar localtime;
    return wrap_page("net-mgr", <<HTML);
<div class="meta">$count machines · $now</div>
<table>
<tr><th>host</th><th>ip</th><th>services</th></tr>
$body
</table>
HTML
}

# Detail pages ------------------------------------------------------

sub render_machine_detail {
    my ($mid) = @_;
    my $m = $machine_by_id{$mid};
    my @ifs = @{ $iface_by_machine{$mid} || [] };
    if (!$m && !@ifs) {
        return wrap_page("not found",
            qq{<p style="color:#f55;">no machine with id=$mid</p>}
          . qq{<p><a href="?">back</a></p>});
    }
    my $name = $friendly_by_machine{$mid}
            // ($m && $m->{primary_name} ? $m->{primary_name} : "machine $mid");
    my @hns = @{ $hostnames_by_machine{$mid} || [] };
    my @als = @{ $aliases_by_machine{$mid}   || [] };

    my $info = '';
    $info .= "<dt>id</dt><dd>$mid</dd>";
    $info .= '<dt>names</dt><dd>'
           . join(', ', map { escapeHTML($_) } @hns)
           . '</dd>' if @hns;
    if (@als) {
        $info .= '<dt>aliases</dt><dd>'
               . join(', ', map {
                       my $a = $_;
                       my $s = escapeHTML($a->{name});
                       $s .= ' (' . escapeHTML($a->{prefer_subnet_cidr}) . ')'
                           if $a->{prefer_subnet_cidr};
                       $s;
                   } @als)
               . '</dd>';
    }

    my @sibs = sibling_machines($mid);
    if (@sibs) {
        my @items;
        for my $s (@sibs) {
            my $subs = @{ $s->{subnets} }
                ? ' <span class=src>(' . escapeHTML(join(', ', @{ $s->{subnets} })) . ')</span>'
                : '';
            push @items, sprintf '<a class=hostlink href="?m=%d">%s</a>%s',
                $s->{id}, escapeHTML($s->{label}), $subs;
        }
        $info .= '<dt>other interfaces</dt><dd>' . join(', ', @items) . '</dd>';
    }

    my @iface_blocks;
    for my $i (@ifs) {
        push @iface_blocks, render_iface_block($i);
    }

    my $body = "<h2>$name</h2>"
             . qq{<dl class=info>$info</dl>}
             . join("\n", @iface_blocks);
    return wrap_page("$name — net-mgr", $body, $name);
}

sub render_iface_detail {
    my ($mac) = @_;
    $mac = lc $mac;
    my $iface = $iface_by_mac{$mac};
    if (!$iface) {
        return wrap_page("not found",
            qq{<p style="color:#f55;">no interface $mac</p>}
          . qq{<p><a href="?">back</a></p>});
    }
    my $first_addr = primary_addr($mac);
    my $title = $first_addr // $mac;
    return wrap_page("$title — net-mgr", render_iface_block($iface), $title);
}

sub render_iface_block {
    my ($iface) = @_;
    my $mac = $iface->{mac};
    my @addrs = sort { ip_sort_key($a->{addr}) cmp ip_sort_key($b->{addr}) }
                @{ $addrs_by_mac{$mac} || [] };
    my $first_addr = @addrs ? $addrs[0]{addr} : undef;
    my $kind = $iface->{kind} // '';
    $kind .= ' (AP)' if $ap_by_mac{$mac};
    # Vendor: prefer the iface row's stored vendor; fall back to OUI
    # lookup so anonymous MACs at least show a manufacturer.
    my $vendor = $iface->{vendor} // '';
    if (!length $vendor) {
        my $oui = oui_vendor($mac);
        $vendor = "$oui (OUI)" if defined $oui;
    }
    my $online = $iface->{online} ? 'online' : 'offline';

    my $addr_html = @addrs
        ? join '', map {
            my $src = $_->{source} ? " <span class=src>($_->{source})</span>" : '';
            '<li><code>' . escapeHTML($_->{addr}) . '</code>' . $src . '</li>';
        } @addrs
        : '<li class=note>none on file</li>';

    my @port_rows;
    for my $p (sort { $a->{port} <=> $b->{port} } @{ $ports_by_mac{$mac} || [] }) {
        my $svc = $p->{service} // '';
        my $when = $p->{last_seen} // '';
        push @port_rows, sprintf
            '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>',
            $p->{port}, escapeHTML($p->{proto} // 'tcp'),
            escapeHTML($svc), port_badge($p, $first_addr);
    }
    my $port_html = @port_rows
        ? '<table class=ports><tr><th>port</th><th>proto</th><th>service</th><th></th></tr>'
          . join('', @port_rows) . '</table>'
        : '<p class=note>no ports observed</p>';

    # Recent events for this MAC, when fetched (iface-detail route only).
    my $events_html = '';
    if ($iface_events) {
        my @evs = grep { ($_->{mac} // '') eq $mac } @$iface_events;
        @evs = sort { ($b->{ts} // '') cmp ($a->{ts} // '') } @evs;
        my $shown = @evs > 20 ? 20 : scalar @evs;
        if ($shown) {
            my @rows;
            for my $e (@evs[0 .. $shown - 1]) {
                push @rows, sprintf
                    '<tr><td class=meta>%s</td><td>%s</td><td>%s</td></tr>',
                    escapeHTML($e->{ts} // ''),
                    escapeHTML($e->{type} // ''),
                    escapeHTML($e->{addr} // '');
            }
            my $more = @evs > $shown
                ? sprintf('<p class=note>showing %d of %d events</p>',
                          $shown, scalar @evs)
                : '';
            $events_html = '<dt>recent events</dt><dd>'
                         . '<table class=events>'
                         . '<tr><th>ts</th><th>type</th><th>addr</th></tr>'
                         . join('', @rows)
                         . '</table>'
                         . $more
                         . '</dd>';
        } else {
            $events_html = '<dt>recent events</dt>'
                         . '<dd class=note>none in last 30 days</dd>';
        }
    }

    return <<HTML;
<section class="iface $online">
<h3>$mac <span class=meta>$kind · $vendor · $online</span></h3>
<dl class=info>
  <dt>addresses</dt><dd><ul class=addrlist>$addr_html</ul></dd>
  $events_html
</dl>
$port_html
</section>
HTML
}

# OUI vendor lookup from the IEEE registry CSV. Returns the
# Organization Name for the MAC's first three octets, or undef if not
# found. The index is built lazily on first call and cached for the
# lifetime of the request.
my %_OUI;
my $_oui_loaded = 0;
sub oui_vendor {
    my ($mac) = @_;
    return undef unless defined $mac && $mac =~ /^([0-9a-f]{2}):([0-9a-f]{2}):([0-9a-f]{2})/i;
    my $key = uc "$1$2$3";
    if (!$_oui_loaded) {
        $_oui_loaded = 1;
        for my $path ('/usr/local/share/ieee-data/oui.csv',
                      '/var/lib/ieee-data/oui.csv') {
            next unless -r $path;
            if (open my $fh, '<', $path) {
                while (my $line = <$fh>) {
                    next unless $line =~ /^MA-L,([0-9A-F]{6}),"?([^",]+)/;
                    $_OUI{$1} = $2;
                }
                close $fh;
                last;
            }
        }
    }
    return $_OUI{$key};
}

sub render_tools {
    my $body = <<'HTML';
<ul class=toollist>
  <li><a href="?view=flake">Disconnect histogram</a> — count of
      <code>interface_offline</code> events bucketed over a chosen
      range (1h, 4h, 24h, 1w, 4w).</li>
  <li><a href="?view=flakers">Disconnect ranking</a> — hosts ranked
      by how many <code>interface_offline</code> events they generated
      over the same range options.</li>
  <li><a href="?view=dhcp">DHCP grants</a> — which AP / host gave out
      each IP, derived from the source tag on each address row.</li>
  <li><a href="?view=lost">Lost devices</a> — devices found by
      <code>net-find-lost</code> on a vendor-default subnet, with
      recovery status.</li>
</ul>
HTML
    return wrap_page("Tools — net-mgr", $body, "Tools");
}

sub render_lost {
    my $rows = eval { $cli->snapshot(11, 'lost_devices') };
    my $err  = $@;
    if ($err) {
        return wrap_page("Lost devices — net-mgr",
            qq{<p style="color:#f55;">snapshot failed: } . escapeHTML($err) . qq{</p>}
          . qq{<p>Restart the net-mgr daemon after upgrading so the }
          . qq{<code>lost_devices</code> table is snapshot-able.</p>},
            "Lost devices");
    }
    $rows ||= [];

    # Order: failed first (most actionable), then pending, no-handler,
    # attempted, then anything else; within each, most recent first.
    my %order = ('failed' => 0, 'pending' => 1, 'no-handler' => 2, 'attempted' => 3);
    my @sorted = sort {
        ($order{$a->{status}} // 9) <=> ($order{$b->{status}} // 9)
        || ($b->{last_seen} // '') cmp ($a->{last_seen} // '')
    } @$rows;

    my $count = scalar @sorted;
    my $now   = scalar localtime;

    my @body;
    push @body, qq{<p class=meta>$count entries · $now</p>};
    push @body, qq{<p class=meta>Populated by <code>net-find-lost</code> }
              . qq{(add <code>--recover --quiet</code> for a cron-friendly run that }
              . qq{also invokes matching recovery scripts). Each row is a device }
              . qq{that turned up on a vendor-default subnet and what we did about it.</p>};

    if (!@sorted) {
        push @body, '<p class=note>nothing recorded.</p>';
        return wrap_page("Lost devices — net-mgr", join("\n", @body), "Lost devices");
    }

    push @body, '<table class=lost>';
    push @body, '<tr><th>status</th><th>handler</th><th>ip</th><th>mac</th>'
              . '<th>vendor</th><th>iface</th><th>subnet</th>'
              . '<th>last seen</th><th>last attempt</th></tr>';
    for my $r (@sorted) {
        my $status_class = $r->{status} // 'unknown';
        $status_class =~ s/[^a-z0-9-]/-/g;
        my $mac = lc($r->{mac} // '');
        my $mac_link = $mac
            ? sprintf('<a class=hostlink href="?i=%s"><code>%s</code></a>',
                      escapeHTML($mac), escapeHTML($mac))
            : '';
        push @body, sprintf
            '<tr class="status-%s"><td class=status>%s</td><td>%s</td>'
          . '<td><code>%s</code></td><td>%s</td><td>%s</td>'
          . '<td><code>%s</code></td><td><code>%s</code></td>'
          . '<td class=meta>%s</td><td class=meta>%s</td></tr>',
            $status_class,
            escapeHTML($r->{status} // ''),
            escapeHTML($r->{handler} // '—'),
            escapeHTML($r->{ip} // ''),
            $mac_link,
            escapeHTML($r->{vendor} // ''),
            escapeHTML($r->{iface} // ''),
            escapeHTML($r->{subnet} // ''),
            escapeHTML($r->{last_seen} // ''),
            escapeHTML($r->{last_attempt} // '—');
    }
    push @body, '</table>';

    push @body, '<p class=note>status legend: '
              . '<span class="swatch s-failed"></span>failed '
              . '<span class="swatch s-pending"></span>pending '
              . '<span class="swatch s-no-handler"></span>no handler '
              . '<span class="swatch s-attempted"></span>attempted</p>';

    return wrap_page("Lost devices — net-mgr", join("\n", @body), "Lost devices");
}

sub render_flake {
    my $key = $q{range} // '24h';
    $key = '24h' unless exists $FLAKE_RANGES{$key};
    my $cfg = $FLAKE_RANGES{$key};
    my $span    = $cfg->{span};
    my $bucket  = $cfg->{bucket};
    my $nbuckets = int($span / $bucket);

    my $events = $cli->snapshot(1, 'events',
        where => "type = 'interface_offline' AND ts > ago($span)");

    my $now = time();
    # Buckets oldest at index 0 → newest at $nbuckets-1.
    my @counts = (0) x $nbuckets;
    for my $e (@$events) {
        my $ts = $e->{ts} // '';
        next unless $ts =~ /^(\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)/;
        my $epoch = eval { timelocal($6, $5, $4, $3, $2-1, $1) };
        next unless defined $epoch;
        my $age_b = int(($now - $epoch) / $bucket);
        next if $age_b < 0 || $age_b >= $nbuckets;
        $counts[$nbuckets - 1 - $age_b]++;
    }

    my $total = 0; $total += $_ for @counts;
    my $max = 1;
    for (@counts) { $max = $_ if $_ > $max }

    # SVG layout
    my $W = 720; my $H = 220;
    my $L = 40; my $R = 10; my $T = 10; my $B = 30;
    my $plot_w = $W - $L - $R;
    my $plot_h = $H - $T - $B;
    my $bar_gap = $nbuckets > 30 ? 1 : 2;
    my $bar_w = ($plot_w - $bar_gap * ($nbuckets - 1)) / $nbuckets;

    # Per-bucket time labels using the configured strftime format.
    my @labels;
    for my $i (0 .. $nbuckets - 1) {
        my $age_b = $nbuckets - 1 - $i;
        my @lt = localtime($now - $age_b * $bucket);
        push @labels, _strftime_lite($cfg->{tfmt}, @lt);
    }

    my $unit = $cfg->{unit};
    my @bars;
    for my $i (0 .. $nbuckets - 1) {
        my $h = $counts[$i] / $max * $plot_h;
        my $x = $L + $i * ($bar_w + $bar_gap);
        my $y = $T + $plot_h - $h;
        my $title = "$labels[$i] — $counts[$i] disconnect"
                  . ($counts[$i] == 1 ? '' : 's');
        push @bars, sprintf
            '<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" '
          . 'fill="#6cf"><title>%s</title></rect>',
            $x, $y, $bar_w, $h, escapeHTML($title);
    }

    # Y-axis: max value tick + zero line.
    my $axis = sprintf
        '<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#444"/>'
      . '<text x="%d" y="%d" fill="#888" font-size="11" '
        . 'text-anchor="end">%d</text>'
      . '<text x="%d" y="%d" fill="#888" font-size="11" '
        . 'text-anchor="end">0</text>',
        $L, $T + $plot_h, $L + $plot_w, $T + $plot_h,
        $L - 4, $T + 11, $max,
        $L - 4, $T + $plot_h, ;

    # X-axis labels every $tick buckets, anchored on the newest bar so
    # the rightmost label always shows the current bucket.
    my $tick = $cfg->{tick};
    my @xlabels;
    for (my $i = $nbuckets - 1; $i >= 0; $i -= $tick) {
        my $x = $L + $i * ($bar_w + $bar_gap) + $bar_w / 2;
        push @xlabels, sprintf
            '<text x="%.2f" y="%d" fill="#888" font-size="11" '
            . 'text-anchor="middle">%s</text>',
            $x, $H - 14, escapeHTML($labels[$i]);
    }

    my $bars   = join "\n  ", @bars;
    my $xlabs  = join "\n  ", @xlabels;
    my $note   = "$total disconnects in the last $cfg->{label} · "
               . "peak $max in one $unit";

    my $switcher = flake_nav('flake', $key);

    my $body = <<HTML;
$switcher
<p class=meta>$note</p>
<svg viewBox="0 0 $W $H" xmlns="http://www.w3.org/2000/svg" class=flake>
  $axis
  $bars
  $xlabs
</svg>
<p class=note>Newest bucket on the right. Each bar covers $unit. Hover
a bar for the count.</p>
HTML
    return wrap_page("Disconnects — net-mgr", $body,
        "Disconnects ($cfg->{label})");
}

# Shared nav for the flake/flakers pages: a "view: histogram | ranking"
# tab row and a "range: 1h · 4h · ..." switcher under it. $view is
# either 'flake' or 'flakers'; $key is the active range key.
sub flake_nav {
    my ($view, $key) = @_;
    my @views = (
        [ 'flake',   'histogram' ],
        [ 'flakers', 'ranking'   ],
    );
    my @vlinks;
    for my $v (@views) {
        if ($v->[0] eq $view) {
            push @vlinks, "<strong>$v->[1]</strong>";
        } else {
            push @vlinks, sprintf '<a href="?view=%s&amp;range=%s">%s</a>',
                $v->[0], $key, escapeHTML($v->[1]);
        }
    }
    my @rlinks;
    for my $k (@FLAKE_ORDER) {
        if ($k eq $key) {
            push @rlinks, "<strong>$FLAKE_RANGES{$k}{label}</strong>";
        } else {
            push @rlinks, sprintf '<a href="?view=%s&amp;range=%s">%s</a>',
                $view, $k, escapeHTML($FLAKE_RANGES{$k}{label});
        }
    }
    return '<p class=meta>view: ' . join(' · ', @vlinks) . '</p>'
         . '<p class=meta>range: ' . join(' · ', @rlinks) . '</p>';
}

sub render_flakers {
    my $key = $q{range} // '24h';
    $key = '24h' unless exists $FLAKE_RANGES{$key};
    my $cfg = $FLAKE_RANGES{$key};
    my $span = $cfg->{span};

    my $events    = $cli->snapshot(1, 'events',
        where => "type = 'interface_offline' AND ts > ago($span)");
    my $machines  = $cli->snapshot(2, 'machines');
    my $ifaces    = $cli->snapshot(3, 'interfaces');
    my $hostnames = $cli->snapshot(4, 'hostnames');
    my $friendly  = $cli->snapshot(5, 'friendly_names');
    my $addresses = $cli->snapshot(6, 'addresses', where => "family = 'v4'");

    my %iface_by_mac = map { $_->{mac} => $_ } @$ifaces;
    my %machine_by_id = map { $_->{id} => $_ } @$machines;
    my %hns_by_machine;
    push @{ $hns_by_machine{ $_->{machine_id} } }, $_->{name} for @$hostnames;
    my %fr_by_machine = map { $_->{machine_id} => $_->{name} } @$friendly;
    my %addrs_by_mac;
    push @{ $addrs_by_mac{ $_->{mac} } }, $_ for @$addresses;

    # Tally per-mac counts and the most recent event timestamp.
    my (%count, %last);
    for my $e (@$events) {
        my $mac = $e->{mac};
        next unless defined $mac && length $mac;
        $count{$mac}++;
        my $ts = $e->{ts} // '';
        $last{$mac} = $ts if !defined($last{$mac}) || $ts gt $last{$mac};
    }

    # Resolve a display name for each mac (machine friendly_name →
    # primary_name → first hostname → bare mac).
    my $name_for = sub {
        my ($mac) = @_;
        my $iface = $iface_by_mac{$mac};
        my $mid   = $iface && $iface->{machine_id};
        if ($mid) {
            return $fr_by_machine{$mid} if $fr_by_machine{$mid};
            my $m = $machine_by_id{$mid};
            return $m->{primary_name} if $m && $m->{primary_name};
            my $hns = $hns_by_machine{$mid};
            return $hns->[0] if $hns && @$hns;
        }
        return $mac;
    };
    my $link_for = sub {
        my ($mac) = @_;
        my $iface = $iface_by_mac{$mac};
        my $mid   = $iface && $iface->{machine_id};
        return $mid
            ? sprintf('?m=%d', $mid)
            : sprintf('?i=%s', $mac);
    };

    my @rows = sort {
           $count{$b} <=> $count{$a}
        || lc($name_for->($a)) cmp lc($name_for->($b))
    } keys %count;

    my $total   = 0; $total += $_ for values %count;
    my $hosts   = scalar @rows;
    my $note    = "$total disconnects across $hosts host"
                . ($hosts == 1 ? '' : 's')
                . " in the last $cfg->{label}";
    my $switcher = flake_nav('flakers', $key);

    my $table;
    if (!@rows) {
        $table = '<p class=note>No disconnect events in this range.</p>';
    } else {
        my @row_html;
        my $rank = 0;
        for my $mac (@rows) {
            $rank++;
            my $name = $name_for->($mac);
            my $link = $link_for->($mac);
            my $iface = $iface_by_mac{$mac};
            my $kind  = $iface && $iface->{kind} ? $iface->{kind} : '';
            my @addrs = sort { ip_sort_key($a->{addr}) cmp ip_sort_key($b->{addr}) }
                        @{ $addrs_by_mac{$mac} || [] };
            my $addr  = @addrs ? $addrs[0] : undef;
            my $ip    = $addr ? $addr->{addr} : '';
            # Classify by inspecting every source row for this MAC:
            # an observed dynamic lease (granter:DHCP) wins over a
            # static reservation (host:dhcp.master); arp/ssh/other
            # leave the row uncolored.
            my ($granter, $dhcp_kind);
            for my $a (@addrs) {
                my $src = $a->{source} // '';
                if (!$dhcp_kind && $src =~ /^(\d+\.\d+\.\d+\.\d+):DHCP$/) {
                    $granter = $1;
                    $dhcp_kind = 'dyn';
                } elsif (!$dhcp_kind && $src =~ /:dhcp\.master$/i) {
                    $dhcp_kind = 'stat';
                }
            }
            my $row_class = $dhcp_kind ? " class=$dhcp_kind" : '';
            my $ip_html = '';
            if (length $ip) {
                if (defined $granter) {
                    $ip_html = sprintf
                        '<a class=hostlink href="?view=dhcp#g-%s" '
                      . 'title="DHCP grant from %s"><code>%s</code></a>',
                        escapeHTML($granter), escapeHTML($granter),
                        escapeHTML($ip);
                } else {
                    $ip_html = '<code>' . escapeHTML($ip) . '</code>';
                }
            }
            push @row_html, sprintf
                '<tr%s><td class=rank>%d</td>'
              . '<td class=name><a class=hostlink href="%s">%s</a></td>'
              . '<td>%s</td>'
              . '<td>%s</td>'
              . '<td class=count>%d</td>'
              . '<td class=meta>%s</td></tr>',
                $row_class, $rank, escapeHTML($link), escapeHTML($name),
                $ip_html, escapeHTML($kind),
                $count{$mac}, escapeHTML($last{$mac} // '');
        }
        $table = '<table class=flakers>'
               . '<tr><th>#</th><th>host</th><th>ip</th><th>kind</th>'
               . '<th>disconnects</th><th>last seen</th></tr>'
               . join('', @row_html)
               . '</table>';
    }

    my $legend = '<p class=flakelegend>'
               . '<span class="swatch dyn"></span>dynamic DHCP lease'
               . '<span class="swatch stat"></span>static DHCP reservation'
               . '</p>';
    my $body = "$switcher<p class=meta>$note</p>$legend$table";
    return wrap_page("Disconnect ranking — net-mgr", $body,
        "Disconnect ranking ($cfg->{label})");
}

# Tiny strftime — handles only the directives FLAKE_RANGES uses, so we
# don't pull in POSIX just for this view. @lt is a localtime() list.
sub _strftime_lite {
    my ($fmt, @lt) = @_;
    my @wday = qw(Sun Mon Tue Wed Thu Fri Sat);
    my %sub = (
        '%H' => sprintf('%02d', $lt[2]),
        '%M' => sprintf('%02d', $lt[1]),
        '%m' => sprintf('%02d', $lt[4] + 1),
        '%d' => sprintf('%02d', $lt[3]),
        '%a' => $wday[$lt[6]],
    );
    $fmt =~ s/(%[HMmda])/$sub{$1}/g;
    return $fmt;
}

sub render_dhcp {
    my $machines  = $cli->snapshot(1, 'machines');
    my $ifaces    = $cli->snapshot(2, 'interfaces');
    my $addresses = $cli->snapshot(3, 'addresses', where => "family = 'v4'");

    my %name_by_id   = map { $_->{id} => $_->{primary_name} } @$machines;
    my %iface_by_mac = map { $_->{mac} => $_ } @$ifaces;

    # IP → name lookup so a granter source like "192.168.15.151:DHCP"
    # renders as "wndr8k1" / etc.
    my %name_by_ip;
    for my $a (@$addresses) {
        next unless $a->{mac} && $a->{addr};
        my $iface = $iface_by_mac{$a->{mac}};
        next unless $iface && $iface->{machine_id};
        my $name = $name_by_id{$iface->{machine_id}} // '';
        $name_by_ip{$a->{addr}} //= $name if length $name;
    }

    # Group address rows by granting IP. Skip everything that wasn't
    # tagged :DHCP (paper records, ARP, etc.).
    my %by_granter;
    for my $a (@$addresses) {
        my $src = $a->{source} // '';
        next unless $src =~ /^(\d+\.\d+\.\d+\.\d+):DHCP$/;
        my $g = $1;
        push @{ $by_granter{$g} }, $a;
    }

    my @sections;
    my $total = 0;
    for my $g (sort { ip_sort_key($a) cmp ip_sort_key($b) } keys %by_granter) {
        my @rows = sort {
            ip_sort_key($a->{addr}) cmp ip_sort_key($b->{addr})
        } @{ $by_granter{$g} };
        $total += scalar @rows;
        my $g_name = $name_by_ip{$g};
        my $hdr = $g_name
            ? sprintf '%s (<code>%s</code>) — %d',
                escapeHTML($g_name), escapeHTML($g), scalar @rows
            : sprintf '<code>%s</code> — %d',
                escapeHTML($g), scalar @rows;
        my @row_html;
        for my $a (@rows) {
            my $iface = $iface_by_mac{$a->{mac}};
            my $client_name = '';
            if ($iface && $iface->{machine_id}) {
                $client_name = $name_by_id{$iface->{machine_id}} // '';
            }
            my $client_link = $client_name
                ? sprintf '<a class=hostlink href="?m=%d">%s</a>',
                    $iface->{machine_id}, escapeHTML($client_name)
                : sprintf '<a class=hostlink href="?i=%s">%s</a>',
                    escapeHTML($a->{mac}), escapeHTML($a->{mac});
            push @row_html, sprintf
                '<tr><td>%s</td><td>%s</td><td><code>%s</code></td></tr>',
                escapeHTML($a->{addr}), $client_link, escapeHTML($a->{mac});
        }
        my $section_body = '<table><tr><th>ip</th><th>client</th><th>mac</th></tr>'
            . join('', @row_html) . '</table>';
        my $anchor = "g-$g";
        push @sections, qq{<h2 id="$anchor">$hdr</h2>$section_body};
    }

    if (!@sections) {
        push @sections, '<p class=note>No DHCP-sourced addresses found.</p>';
    }

    my $body = qq{<p class=meta>$total leases across }
             . scalar(keys %by_granter) . qq{ granters</p>}
             . join("\n", @sections);
    return wrap_page("DHCP grants — net-mgr", $body, "DHCP grants");
}

sub wrap_page {
    my ($title, $body, $h1) = @_;
    $h1 //= 'net-mgr';
    return <<HTML;
<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>@{[escapeHTML($title)]}</title>
<style>
body { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
       background: #111; color: #ccc; margin: 2em; }
h1, h2, h3 { margin: 0.4em 0; }
h1 { font-size: 1.4em; }
h2 { font-size: 1.2em; color: #eee; }
h3 { font-size: 1em; color: #aaa; font-family: inherit; }
.meta { color: #888; font-size: 0.9em; }
table { border-collapse: collapse; width: 100%; margin: 0.5em 0 1.5em; }
th, td { padding: 3px 8px; text-align: left;
         border-bottom: 1px solid #2a2a2a; }
th { background: #1a1a1a; color: #aaa; font-weight: normal;
     border-bottom: 1px solid #444; }
td.name { font-weight: bold; }
td.ports { line-height: 1.7em; }
code { color: #888; font-size: 0.9em; }
.port {
    display: inline-block; padding: 0 6px; margin: 0 1px;
    background: #1d2a3a; color: #6cf; border-radius: 3px;
    font-size: 0.85em; text-decoration: none;
}
a.port { color: #6cf; }
a.port:hover { background: #2a4060; }
a.hostlink { color: #eee; text-decoration: none; }
a.hostlink:hover { color: #6cf; text-decoration: underline; }
tr.offline td.name { color: #555; }
tr.offline a.hostlink { color: #555; }
tr.offline td { color: #555; }
tr.unknown td.name { color: #888; font-style: italic; }
section.iface { margin-bottom: 1.5em; padding-left: 0.5em;
                border-left: 2px solid #333; }
section.iface.offline { opacity: 0.55; }
dl.info { margin: 0.4em 0; }
dl.info dt { color: #888; }
dl.info dd { margin-left: 1.5em; }
ul.addrlist { list-style: none; padding-left: 0; margin: 0; }
ul.addrlist li { padding: 1px 0; }
span.src { color: #777; font-size: 0.85em; }
.note { color: #666; font-style: italic; }
nav { font-size: 0.9em; margin-bottom: 1em; }
nav a { color: #6cf; text-decoration: none; margin-right: 1em; }
nav a:hover { text-decoration: underline; }
ul.toollist { list-style: none; padding-left: 0; }
ul.toollist li { padding: 6px 0; }
ul.toollist a { color: #6cf; }
svg.flake { width: 100%; max-width: 720px;
            background: #181818; border-radius: 4px; }
svg.flake rect:hover { fill: #9df; }
table.flakers td.rank  { color: #888; text-align: right; width: 2.5em; }
table.flakers td.count { text-align: right; font-weight: bold; }
table.flakers td.meta  { color: #888; font-size: 0.9em; }
table.flakers tr.dyn   td { background: rgba(220, 60, 60, 0.18); }
table.flakers tr.stat  td { background: rgba(220, 200, 60, 0.14); }
table.events { font-size: 0.9em; }
table.events td { padding: 2px 8px; }
.flakelegend { font-size: 0.85em; color: #888; }
.flakelegend .swatch {
    display: inline-block; width: 0.9em; height: 0.9em;
    margin: 0 0.25em -1px 0.6em; border-radius: 2px;
    vertical-align: middle;
}
.flakelegend .swatch.dyn  { background: rgba(220, 60, 60, 0.6); }
.flakelegend .swatch.stat { background: rgba(220, 200, 60, 0.6); }
table.lost td, table.lost th { vertical-align: top; }
table.lost td.status { font-weight: bold; }
table.lost tr.status-failed     td { background: rgba(220, 60, 60, 0.22); }
table.lost tr.status-pending    td { background: rgba(220, 200, 60, 0.18); }
table.lost tr.status-no-handler td { background: rgba(150, 150, 150, 0.14); }
table.lost tr.status-attempted  td { background: rgba(60, 200, 100, 0.14); }
.note .swatch {
    display: inline-block; width: 0.9em; height: 0.9em;
    margin: 0 0.25em -1px 0.6em; border-radius: 2px;
    vertical-align: middle;
}
.note .swatch.s-failed     { background: rgba(220, 60, 60, 0.6); }
.note .swatch.s-pending    { background: rgba(220, 200, 60, 0.6); }
.note .swatch.s-no-handler { background: rgba(150, 150, 150, 0.6); }
.note .swatch.s-attempted  { background: rgba(60, 200, 100, 0.6); }
</style>
</head>
<body>
<nav><a href="?">&larr; hosts</a><a href="?view=tools">tools</a></nav>
<h1>@{[escapeHTML($h1)]}</h1>
$body
</body></html>
HTML
}

sub render_error {
    my ($msg, $detail) = @_;
    $detail //= '';
    chomp $detail;
    return wrap_page("net-mgr — error",
        qq{<p style="color:#f55;">@{[escapeHTML($msg)]}</p>}
      . qq{<pre>@{[escapeHTML($detail)]}</pre>});
}
