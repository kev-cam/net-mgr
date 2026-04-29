#!/usr/bin/perl
# net-mgr-web.cgi — read-only HTML view of net-mgr's machine/port data.
#
# Two views, selected by query string:
#   /net-mgr              compact list: name + clickable service badges
#   /net-mgr?m=<id>       detail page for one machine (MAC/vendor/IPs/ports)
#   /net-mgr?i=<mac>      detail for an unaffiliated interface
#
# Connects to the manager socket (no DB credentials needed). Apache
# handles auth + IP restriction via the matching net-mgr.conf snippet.

use strict;
use warnings;
use lib '/usr/local/share/perl5';
use CGI qw(escapeHTML);
use NetMgr::Client;

print "Content-Type: text/html; charset=utf-8\n\n";

my $cli = eval { NetMgr::Client->new(listen => '127.0.0.1:7531') };
if (!$cli || $@) {
    print render_error("can't reach net-mgr daemon", $@);
    exit 0;
}
$cli->hello(consumer => "net-mgr-web.$$");

my $machines  = $cli->snapshot(1, 'machines');
my $hostnames = $cli->snapshot(2, 'hostnames');
my $ifaces    = $cli->snapshot(3, 'interfaces');
my $addresses = $cli->snapshot(4, 'addresses', where => "family = 'v4'");
my $ports     = $cli->snapshot(5, 'ports');
my $aps       = $cli->snapshot(6, 'aps');
my $aliases   = $cli->snapshot(7, 'aliases');
$cli->bye;

# Indexes ------------------------------------------------------------

my %machine_by_id = map { $_->{id} => $_ } @$machines;
my %hostnames_by_machine;
push @{ $hostnames_by_machine{ $_->{machine_id} } }, $_->{name} for @$hostnames;

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

# Routing ------------------------------------------------------------

my %q;
for my $kv (split /&/, $ENV{QUERY_STRING} // '') {
    my ($k, $v) = split /=/, $kv, 2;
    next unless defined $k;
    $v //= '';
    $v =~ s/%([0-9A-Fa-f]{2})/chr hex $1/ge;
    $q{$k} = $v;
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

# Display label for a machine row in the compact list. Prefer
# primary_name; fall back to a hostnames entry; fall back to the
# representative IP.
sub display_label {
    my ($mid, $primary_addr) = @_;
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
    my $name = $m && $m->{primary_name} ? $m->{primary_name} : "machine $mid";
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
    my $vendor = $iface->{vendor} // '';
    my $online = $iface->{online} ? 'online' : 'offline';

    my $addr_html = join '', map {
        my $src = $_->{source} ? " <span class=src>($_->{source})</span>" : '';
        '<li><code>' . escapeHTML($_->{addr}) . '</code>' . $src . '</li>';
    } @addrs;

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

    return <<HTML;
<section class="iface $online">
<h3>$mac <span class=meta>$kind · $vendor · $online</span></h3>
<dl class=info>
  <dt>addresses</dt><dd><ul class=addrlist>$addr_html</ul></dd>
</dl>
$port_html
</section>
HTML
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
nav a { color: #6cf; text-decoration: none; }
nav a:hover { text-decoration: underline; }
</style>
</head>
<body>
<nav><a href="?">&larr; net-mgr</a></nav>
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
