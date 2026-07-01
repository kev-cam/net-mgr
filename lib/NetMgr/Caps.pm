package NetMgr::Caps;
# NetMgr::Caps — cheap runtime probes for the capabilities each mesh
# node advertises via HEARTBEAT. Populated once at daemon boot and
# cached; the state_fn closure that decorates every outbound HEARTBEAT
# reads from the cache, so probing must NOT do anything that could
# stall the event loop.
#
# Consumers: NetMgr::Manager's state_fn (advertise) + master-side
# _handle_heartbeat (persist), bin/net-cluster --capable=<x> (query).
# Add a probe by dropping a { key => shell_test } pair into %PROBE;
# the shell_test MUST print 'yes' on success and anything else (or
# nothing) on failure. The key becomes the comma-separated token you
# see in HEARTBEAT's capabilities= field.

use strict;
use warnings;

# One-shot probes. Kept short and stdlib-only so a stripped install
# without hciconfig/iptables/etc. just quietly reports the capability
# as absent. Each command's stderr is redirected — a missing binary
# should read as "no", not as an error.
my %PROBE = (
    # Bluetooth adapter present. hci0 is enough; presence in
    # /sys/class/bluetooth means the kernel side is loaded. Doesn't
    # verify the adapter is powered/up (that flaps); consumers who
    # care can round-trip a fresh probe.
    ble => q{ls /sys/class/bluetooth/hci0 >/dev/null 2>&1 && echo yes},

    # sysctl-observable forwarding flags.
    ipv6_fwd  => q{[ "$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null)" = 1 ] && echo yes},
    ipv4_fwd  => q{[ "$(cat /proc/sys/net/ipv4/ip_forward       2>/dev/null)" = 1 ] && echo yes},

    # Full-gateway signal: ipv4 forwarding + at least one MASQUERADE
    # rule + a default route. Any one of the three alone isn't enough
    # to claim "I route traffic outbound".
    gateway   => q{fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null); m=$(iptables -t nat -S POSTROUTING 2>/dev/null | grep -c -- '-j MASQUERADE'); d=$(ip -4 route show default 2>/dev/null | wc -l); [ "$fwd" = 1 ] && [ "$m" -gt 0 ] && [ "$d" -gt 0 ] && echo yes},

    # WiFi AP: hostapd running is the simplest signal. NetMgr's
    # wifi_sockets table would be more accurate but requires DB access
    # from the probe path (avoided intentionally).
    wifi_ap   => q{pgrep -x hostapd >/dev/null 2>&1 && echo yes},

    # Build toolchains — matters when the master picks a host to
    # (re)build the bitchat helper, etc. Look at PATH only; installed
    # via ~/.cargo/bin isn't visible to the daemon (running as root).
    cargo     => q{command -v cargo >/dev/null 2>&1 && echo yes},
    rustc     => q{command -v rustc >/dev/null 2>&1 && echo yes},

    # Overlay tunnels + DNS resolver. Cheap heuristics.
    wireguard => q{command -v wg >/dev/null 2>&1 && echo yes},
    dnsmasq   => q{pgrep -x dnsmasq >/dev/null 2>&1 && echo yes},
);

# Cache — populated on first call, reused thereafter. state_fn fires
# on the mesh HB cadence (a few seconds); re-probing every tick would
# be wasteful and hciconfig(1) etc. are surprisingly slow.
my $CACHE;

# Return an arrayref of capability keys the local node advertises.
# Ordering is stable (sort keys) so the same set produces the same
# capabilities= string every HB, which makes replicated-from
# deduplication trivial.
sub local_caps {
    return $CACHE if $CACHE;
    my @have;
    for my $k (sort keys %PROBE) {
        my $out = `$PROBE{$k} 2>/dev/null`;
        chomp $out;
        push @have, $k if $out eq 'yes';
    }
    return $CACHE = \@have;
}

# Force a re-probe. Call after a hotplug event (BLE dongle in/out) or
# a service state change (hostapd starting). No callers wired today —
# lives here for the netif-hook to grow into.
sub refresh {
    $CACHE = undef;
    return local_caps();
}

# Convenience: the comma-separated string used on the wire.
sub as_string {
    return join(',', @{ local_caps() });
}

1;
