package NetMgr::Ddns;
# Run DDNS-refresh hooks when the WAN (Internet-facing) IPv4 changes.
#
# The hooks are executables (or symlinks) in a directory — default
# /etc/net-mgr/ddns — run run-parts style whenever the WAN IP changes, e.g. to
# push the new address to a dynamic-DNS provider or re-point the Hurricane
# Electric tunnel endpoint (he_net). net-mgr only detects the change and runs
# the hooks; each hook knows how to update its own provider.
#
# Each hook is invoked as:  <hook> <new_ip> <old_ip> <iface>
# and with the environment:  NET_MGR_WAN_IP / NET_MGR_WAN_IP_OLD / NET_MGR_WAN_IF
#
# The last-seen IP is remembered in a state file (default /var/lib/net-mgr/wan-ip)
# so a restart doesn't re-fire the hooks, and an IP that changed while the daemon
# was down is still caught on the next check.

use strict;
use warnings;
use Exporter 'import';
use NetMgr::Tunnel ();

our @EXPORT_OK = qw(hooks run_hooks check);

# Sorted executable hook paths in $dir (run-parts rules: skip dotfiles and
# editor/package backup suffixes).
sub hooks {
    my ($dir) = @_;
    return () unless defined $dir && -d $dir;
    opendir my $dh, $dir or return ();
    my @h;
    for my $f (sort readdir $dh) {
        next if $f =~ /^\./;
        next if $f =~ /(?:~|\.bak|\.swp|\.dpkg-[\w-]+|\.rpm\w+)$/;
        my $p = "$dir/$f";
        push @h, $p if -f $p && -x $p;
    }
    closedir $dh;
    return @h;
}

# run_hooks(dir=>, new=>, old=>, iface=>, log=>, run=>) — run every hook with
# (new,old,iface) as argv + env. Returns the count run.
sub run_hooks {
    my (%o) = @_;
    my $log = $o{log} || sub {};
    my $n = 0;
    for my $hook (hooks($o{dir})) {
        my $ok;
        if ($o{run}) {
            $ok = $o{run}->($hook, $o{new}, $o{old}, $o{iface});
        } else {
            local $ENV{NET_MGR_WAN_IP}     = $o{new}   // '';
            local $ENV{NET_MGR_WAN_IP_OLD} = $o{old}   // '';
            local $ENV{NET_MGR_WAN_IF}     = $o{iface} // '';
            $ok = system($hook, ($o{new} // ''), ($o{old} // ''), ($o{iface} // '')) == 0;
        }
        $log->("ddns: ran $hook " . ($ok ? "ok" : "FAILED"));
        $n++;
    }
    return $n;
}

# check(dir=>, statefile=>, ext_if=>, log=>, run=>) — detect a WAN IP change and
# run the hooks. First-ever sighting only records the IP (no hooks); a real
# change runs them. Returns ($changed, $ip).
sub check {
    my (%o) = @_;
    my ($iface, $ip) = NetMgr::Tunnel::external_ipv4($o{ext_if});
    return (0, undef) unless defined $ip;            # WAN down — nothing to do
    my $statefile = $o{statefile} || '/var/lib/net-mgr/wan-ip';
    my $old = _read($statefile);
    return (0, $ip) if defined $old && $old eq $ip;  # unchanged

    my $n = 0;
    $n = run_hooks(dir => $o{dir}, new => $ip, old => $old, iface => $iface,
                   log => $o{log}, run => $o{run})
        if defined $old;                             # only on a real change
    _write($statefile, $ip);
    ($o{log} || sub {})->("ddns: WAN IP "
        . (defined $old ? "$old -> $ip — ran $n hook(s)" : "= $ip (first seen, recorded)"));
    return ((defined $old ? 1 : 0), $ip);
}

sub _read {
    my ($f) = @_;
    open my $fh, '<', $f or return undef;
    local $/; my $v = <$fh>; close $fh;
    $v //= ''; $v =~ s/\s+//g;
    return length $v ? $v : undef;
}

sub _write {
    my ($f, $v) = @_;
    open my $fh, '>', $f or return 0;
    print $fh "$v\n"; close $fh;
    return 1;
}

1;
