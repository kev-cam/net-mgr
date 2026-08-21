package NetMgr::HE;
# Hurricane Electric tunnelbroker.net dynamic-endpoint update.
#
# HE only routes a 6in4 tunnel's traffic for the client IPv4 address it has on
# record; when the WAN rotates (Comcast roll, ISP failover) the tunnel goes
# one-way-dead until HE's record is updated. This module pushes the current
# IPv4 to HE's DDNS-style updater at ipv4.tunnelbroker.net/nic/update — same
# DynDNS v2 protocol curl/scripts have used for years. Idempotent: an unchanged
# IP returns 'nochg' and we treat that as success.
#
# Usage:
#   my ($ok, $msg) = NetMgr::HE::update_endpoint(
#       tunnel_id   => $cfg->{tunnel_id},      # public tunnel ID (numeric)
#       secret_name => $cfg->{update_secret},  # name in /etc/net-mgr/secrets/
#       ip          => $current_wan_ipv4,      # optional; HE auto-detects if absent
#       log         => sub { $self->_log($_[0]) },
#   );
#
# Auth is HTTP Basic with the per-tunnel update KEY (NOT your tunnelbroker
# password) — get it from the tunnel's Advanced tab. Stored as `user:key` in
# /etc/net-mgr/secrets/<name> via NetMgr::Secret; never logged.

use strict;
use warnings;
use NetMgr::Secret;

# update_endpoint(%opts) — returns ($ok, $msg). $msg is HE's response code
# (good/nochg/badauth/...) on a clean exchange, or a transport-level error.
sub update_endpoint {
    my (%o) = @_;
    my $log = $o{log} || sub {};
    my $tid = $o{tunnel_id};
    my $sec = $o{secret_name};
    return (0, "tunnel_id not set") unless defined $tid && length $tid;
    return (0, "update_secret not set") unless defined $sec && length $sec;
    my ($user, $key, $err) = NetMgr::Secret::get_userpass($sec);
    if ($err) { $log->("he-update: $err"); return (0, $err); }

    my $curl = _which('curl') or return (0, "curl not found in PATH");

    # HE's documented DDNS endpoint. Passing `myip=` is optional; with no myip
    # HE uses the source IP it sees on the request, which is correct when this
    # node IS the tunnel endpoint (gateway3 hits HE FROM the WAN it's announcing).
    my $url = "https://ipv4.tunnelbroker.net/nic/update?hostname=$tid";
    $url .= "&myip=$o{ip}" if defined $o{ip} && length $o{ip};

    # Pass creds via --netrc-file on a temp file rather than -u user:pass on the
    # command line — keeps the update key out of `ps`/the process table.
    require File::Temp;
    my ($fh, $nrc) = File::Temp::tempfile('he-netrc.XXXXXX', TMPDIR => 1, UNLINK => 1);
    chmod 0600, $nrc;
    print $fh "machine ipv4.tunnelbroker.net login $user password $key\n";
    close $fh;

    my @cmd = ($curl, '-sS', '--max-time', '15',
               '--netrc-file', $nrc, '--basic',
               '--user-agent', 'net-mgr/he-update', $url);
    my $out = `@cmd 2>&1`;
    my $rc  = $? >> 8;
    unlink $nrc;
    $out =~ s/\s+\z//;

    # HE's response is one line: a verb (good/nochg/badauth/abuse/...) + the IP.
    # Treat 'good' and 'nochg' as success; everything else as failure. NEVER log
    # the URL or any credential — only the response verb + IP.
    if ($rc != 0) {
        $log->("he-update: curl rc=$rc: " . substr($out, 0, 80));
        return (0, "curl rc=$rc");
    }
    my ($verb, $rest) = split / /, $out, 2;
    $verb = lc($verb // '');
    if ($verb eq 'good' || $verb eq 'nochg') {
        $log->("he-update: tunnel=$tid $verb"
             . (defined $rest && length $rest ? " ($rest)" : ""));
        return (1, $verb);
    }
    $log->("he-update: tunnel=$tid FAILED — $out");
    return (0, $out);
}

# update_record(%opts) — set a Hurricane Electric HOSTED DNS record (dns.he.net)
# to an address, via the same DynDNS v2 protocol update_endpoint() uses for
# tunnels. Returns ($ok, $msg).
#
# Different service, same wire protocol:
#   tunnelbroker  ipv4.tunnelbroker.net/nic/update   hostname = tunnel ID
#   hosted DNS    dyn.dns.he.net/nic/update          hostname = the FQDN
#
# The credential is the PER-RECORD key generated when you tick "Enable entry
# for dynamic DNS" on the record in dns.he.net — NOT the dns.he.net account
# password. One key per record, stored bare in /etc/net-mgr/secrets/<name>.
#
# Works for both A and AAAA: the record you enabled DDNS on fixes the type, so
# passing an IPv6 literal in `ip` updates the AAAA. Omit `ip` entirely and HE
# uses the source address it sees — correct when the calling node sits behind
# the very WAN being published, and the reason net-ddnx needs no WAN probe.
sub update_record {
    my (%o) = @_;
    my $log  = $o{log} || sub {};
    my $host = $o{hostname};
    my $sec  = $o{secret_name};
    return (0, "hostname not set") unless defined $host && length $host;
    return (0, "secret_name not set") unless defined $sec && length $sec;
    my ($key, $err) = NetMgr::Secret::get($sec);
    if ($err) { $log->("ddnx: $err"); return (0, $err); }
    $key =~ s/\s+\z// if defined $key;
    return (0, "secret '$sec' is empty") unless defined $key && length $key;

    my $curl = _which('curl') or return (0, "curl not found in PATH");

    # POST body in a 0600 temp file rather than -d on the command line: argv is
    # world-readable via ps, and this body carries the update key.
    require File::Temp;
    my ($fh, $body) = File::Temp::tempfile('he-ddnx.XXXXXX', TMPDIR => 1, UNLINK => 1);
    chmod 0600, $body;
    my $post = "hostname=$host&password=$key";
    $post .= "&myip=$o{ip}" if defined $o{ip} && length $o{ip};
    print $fh $post;
    close $fh;

    my @cmd = ($curl, '-sS', '--max-time', '20',
               '--user-agent', 'net-mgr/ddnx',
               '--data', '@' . $body,
               'https://dyn.dns.he.net/nic/update');
    my $out = `@cmd 2>&1`;
    my $rc  = $? >> 8;
    unlink $body;
    $out =~ s/\s+\z//;

    if ($rc != 0) {
        $log->("ddnx: curl rc=$rc: " . substr($out, 0, 80));
        return (0, "curl rc=$rc");
    }
    # Same verb vocabulary as the tunnel updater. 'nochg' means HE already had
    # this address — success, and the common case on a periodic run.
    my ($verb, $rest) = split / /, $out, 2;
    $verb = lc($verb // '');
    if ($verb eq 'good' || $verb eq 'nochg') {
        $log->("ddnx: $host $verb" . (defined $rest && length $rest ? " ($rest)" : ""));
        return (1, $verb);
    }
    # badauth here almost always means the record's DDNS key, not the account
    # password — say so, because it is the mistake everyone makes first.
    $log->("ddnx: $host FAILED — $out"
         . ($verb eq 'badauth' ? " (secret must be the record's DDNS key)" : ""));
    return (0, $out);
}

sub _which {
    my ($prog) = @_;
    for my $d (split /:/, $ENV{PATH} || '/usr/local/bin:/usr/bin:/bin') {
        my $p = "$d/$prog";
        return $p if -x $p;
    }
    return undef;
}

1;
