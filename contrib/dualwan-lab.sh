#!/usr/bin/env bash
# dualwan-lab.sh — rehearse gateway2/gateway3 dual-WAN failover inside WSL2,
# with zero contact with the real 192.168.15.0/24 network.
#
#   bash dualwan-lab.sh shell            interactive sandbox, `lab help` inside
#   bash dualwan-lab.sh test all         run every scenario, print PASS/FAIL
#   bash dualwan-lab.sh test anchor      one scenario
#
# Everything lives in a private user+mount+net namespace created by unshare(1).
# No root, no sudo, no systemd unit, no change to WSL's eth0 or to Windows.
# When the outer process exits, every namespace/veth/dnsmasq dies with it.
#
# Modelled on the measured topology:
#   LAN 192.168.15.0/24
#     gw3  192.168.15.252   WAN 203.0.113.252 -> isp-cc (COMCAST)   [active]
#     gw2  192.168.15.251   WAN 192.168.0.181 -> isp-tm (TMOBILE)   [backup]
#     VIP  192.168.15.250   (starts on gw3, used by the "Floating .250" design)
#   1.1.1.1 is anycast: it exists on lo inside BOTH isp namespaces, so a probe
#   for it resolves to whichever WAN the packet actually took. The far end
#   announces its own name, which is the "which uplink am I on?" oracle.
#
# LEASE (default 120s, dnsmasq's own floor) is the time telescope: the real net
# runs 86400s leases, so 1 lab second stands for SCALE = 86400/LEASE real
# seconds. Every renewal-latency number the lab prints is also printed scaled.
set -uo pipefail

LAB=${LAB_DIR:-/tmp/dualwan-lab}
LEASE=${LEASE:-120}
SCALE=$(( 86400 / LEASE ))

# ---------------------------------------------------------------- host side
if [ "${LAB_SANDBOX:-}" != 1 ]; then
    for t in unshare ip dnsmasq python3; do
        command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 1; }
    done
    zcat /proc/config.gz 2>/dev/null | grep -q '^CONFIG_NET_NS=y' || \
        echo "note: could not confirm CONFIG_NET_NS=y in this kernel; continuing" >&2
    lsmod | grep -q '^bridge' || echo "note: bridge module not loaded; if 'ip link add type bridge' fails, run: sudo modprobe bridge" >&2
    exec unshare --user --map-root-user --mount --net --propagation private \
         env LAB_SANDBOX=1 LAB_DIR="$LAB" LEASE="$LEASE" bash "$0" "$@"
fi

# ------------------------------------------------------------- sandbox side
mount -t tmpfs none /run/netns 2>/dev/null || true   # rootless `ip netns` needs this
rm -rf "$LAB"; mkdir -p "$LAB"/{gw3,gw2,cli1,cli2}
mkdir -p "$LAB"/gw3/opts "$LAB"/gw2/opts

NS_ALL="isp-cc isp-tm gw3 gw2 cli1 cli2"
FAILED=0
say()  { printf '%s\n' "$*"; }
hdr()  { printf '\n=== %s\n' "$*"; }
ok()   { printf '  PASS  %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; FAILED=1; }
assert_eq() { [ "$2" = "$3" ] && ok "$1 ($2)" || bad "$1: expected '$3', got '$2'"; }
scaled() { printf '%ss lab  =  %s real (x%s)' "$1" "$(fmt_real $(( $1 * SCALE )))" "$SCALE"; }
fmt_real() { local s=$1; printf '%dh%02dm' $(( s/3600 )) $(( (s%3600)/60 )); }

# ------------------------------------------------------------ helper python
cat > "$LAB/labdhcp.py" <<'PYEOF'
#!/usr/bin/env python3
"""Minimal DHCP client: DORA, apply, then renew at T1. Logs every packet it
sends, so "did the client re-DHCP during failover?" is answerable from its own
log without tcpdump (which this image does not have)."""
import argparse, json, os, random, socket, struct, subprocess, sys, time

MAGIC = b'\x63\x82\x53\x63'
DISCOVER, OFFER, REQUEST, ACK, NAK = 1, 2, 3, 5, 6

def hwaddr(dev):
    with open('/sys/class/net/%s/address' % dev) as f:
        return bytes(int(x, 16) for x in f.read().strip().split(':'))

def build(mtype, xid, chaddr, ciaddr='0.0.0.0', opts=b'', bcast=True):
    p = struct.pack('!BBBBIHH4s4s4s4s16s64s128s', 1, 1, 6, 0, xid, 0,
                    0x8000 if bcast else 0, socket.inet_aton(ciaddr),
                    b'\0'*4, b'\0'*4, b'\0'*4,
                    chaddr + b'\0'*(16-len(chaddr)), b'\0'*64, b'\0'*128)
    return p + MAGIC + bytes([53, 1, mtype]) + opts + bytes([55, 4, 1, 3, 6, 51]) + b'\xff'

def parse(data):
    if len(data) < 240 or data[236:240] != MAGIC:
        return None
    o, i = {}, 240
    while i < len(data):
        c = data[i]
        if c == 255: break
        if c == 0: i += 1; continue
        l = data[i+1]; o[c] = data[i+2:i+2+l]; i += 2 + l
    return dict(xid=struct.unpack('!I', data[4:8])[0],
                yiaddr=socket.inet_ntoa(data[16:20]),
                chaddr=data[28:34], opts=o)

def ip4(v):  return socket.inet_ntoa(v[:4]) if v else None
def u32(v):  return struct.unpack('!I', v[:4])[0] if v else None

def sock(dev):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.setsockopt(socket.SOL_SOCKET, 25, dev.encode())      # SO_BINDTODEVICE
    s.bind(('0.0.0.0', 68))
    return s

def collect(s, xid, want, secs):
    out, end = [], time.time() + secs
    while time.time() < end:
        s.settimeout(max(0.05, end - time.time()))
        try: data, _ = s.recvfrom(2048)
        except socket.timeout: break
        r = parse(data)
        if r and r['xid'] == xid and r['opts'].get(53, b'\0')[0] in want:
            out.append(r)
    return out

class Log:
    def __init__(self, d):
        self.d = d
    def ev(self, **kw):
        kw['ts'] = round(time.time(), 3)
        line = json.dumps(kw, sort_keys=True)
        print(line, flush=True)
        if self.d:
            with open(os.path.join(self.d, 'events.log'), 'a') as f:
                f.write(line + '\n')
            for k in ('ip', 'router', 'server'):
                if kw.get(k):
                    with open(os.path.join(self.d, k), 'w') as f:
                        f.write(kw[k])

def apply(dev, ip, mask, router):
    subprocess.run(['ip', 'addr', 'replace', '%s/%s' % (ip, mask), 'dev', dev], check=False)
    subprocess.run(['ip', 'route', 'replace', 'default', 'via', router, 'dev', dev], check=False)

def main():
    a = argparse.ArgumentParser()
    a.add_argument('mode', choices=['discover', 'run'])
    a.add_argument('--dev', required=True)
    a.add_argument('--state', default='')
    a.add_argument('--wait', type=float, default=2.0)
    a.add_argument('--renewals', type=int, default=99)
    g = a.parse_args()

    ch, s, log = hwaddr(g.dev), sock(g.dev), Log(g.state)
    # Real clients retransmit; so do we. The first broadcast onto a freshly
    # built bridge is routinely lost, and a lab that flakes teaches nothing.
    offers, xid = [], 0
    for _ in range(3):
        xid = random.getrandbits(32)
        s.sendto(build(DISCOVER, xid, ch), ('255.255.255.255', 67))
        offers = collect(s, xid, (OFFER,), g.wait)
        if offers: break

    if g.mode == 'discover':
        seen = {}
        for r in offers:
            sid = ip4(r['opts'].get(54))
            if sid in seen: continue
            seen[sid] = 1
            print('OFFER server=%s yiaddr=%s router=%s lease=%s' %
                  (sid, r['yiaddr'], ip4(r['opts'].get(3)), u32(r['opts'].get(51))))
        print('OFFERS=%d' % len(seen))
        return 0 if seen else 1

    if not offers:
        log.ev(ev='no-offer'); return 1
    r = offers[0]
    sid, ip = ip4(r['opts'].get(54)), r['yiaddr']
    log.ev(ev='offer', ip=ip, server=sid, offers=len(offers))
    req = build(REQUEST, xid, ch, opts=bytes([54, 4]) + socket.inet_aton(sid) +
                bytes([50, 4]) + socket.inet_aton(ip))
    acks = []
    for _ in range(3):
        s.sendto(req, ('255.255.255.255', 67))
        acks = collect(s, xid, (ACK, NAK), 2)
        if acks: break
    if not acks:
        log.ev(ev='no-ack'); return 1
    ack = acks[0]
    router = ip4(ack['opts'].get(3))
    mask = sum(bin(b).count('1') for b in ack['opts'].get(1, b'\xff\xff\xff\x00'))
    lease = u32(ack['opts'].get(51)) or 120
    t1 = u32(ack['opts'].get(58)) or lease // 2
    apply(g.dev, ip, mask, router)
    log.ev(ev='bound', ip=ip, router=router, server=sid, lease=lease, t1=t1)

    for _ in range(g.renewals):
        time.sleep(t1)
        xid = random.getrandbits(32)
        log.ev(ev='renew-sent', server=sid)
        acks = []
        for _ in range(3):
            s.sendto(build(REQUEST, xid, ch, ciaddr=ip, bcast=False), (sid, 67))
            acks = collect(s, xid, (ACK, NAK), 2)
            if acks: break
        if not acks:
            log.ev(ev='renew-timeout'); continue
        ack = acks[0]
        nr = ip4(ack['opts'].get(3))
        lease = u32(ack['opts'].get(51)) or lease
        t1 = u32(ack['opts'].get(58)) or lease // 2
        if nr and nr != router:
            router = nr
            apply(g.dev, ip, mask, router)
            log.ev(ev='router-changed', ip=ip, router=router, server=sid)
        else:
            log.ev(ev='renewed', ip=ip, router=router, server=sid)
    return 0

sys.exit(main())
PYEOF

cat > "$LAB/wanid.py" <<'PYEOF'
#!/usr/bin/env python3
"""Which uplink did that packet take? A UDP responder pinned inside each ISP
namespace answers with its own name. Also does gratuitous ARP and a one-shot
DNS A lookup, so the lab needs no arping/dig/tcpdump."""
import argparse, socket, struct, sys, time

def server(g):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((g.bind, g.port))
    while True:
        d, peer = s.recvfrom(512)
        s.sendto(('%s src=%s' % (g.name, peer[0])).encode(), peer)

def probe(g):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(g.timeout)
    try:
        s.sendto(b'?', (g.host, g.port))
        print(s.recvfrom(512)[0].decode())
        return 0
    except (socket.timeout, OSError):
        print('DEAD')          # no route / no answer — same thing to a user
        return 1

def garp(g):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((g.dev, 0))
    mac = s.getsockname()[4][:6]
    ip = socket.inet_aton(g.ip)
    pkt = (b'\xff'*6 + mac + b'\x08\x06' +
           struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2) +
           mac + ip + b'\xff'*6 + ip)
    for _ in range(3):
        s.send(pkt); time.sleep(0.05)
    print('GARP %s from %s' % (g.ip, g.dev))
    return 0

def dns(g):
    q = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
    for part in g.name.split('.'):
        q += bytes([len(part)]) + part.encode()
    q += b'\0' + struct.pack('!HH', 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
    try:
        s.sendto(q, (g.server, 53)); d = s.recvfrom(512)[0]
    except (socket.timeout, OSError):
        print('DNS-DEAD'); return 1
    i = 12
    while d[i]: i += d[i] + 1
    i += 5
    while i + 12 <= len(d):
        i += 2 if d[i] & 0xc0 else (lambda: 0)()
        rtype, _, _, rdl = struct.unpack('!HHIH', d[i:i+10])
        i += 10
        if rtype == 1:
            print(socket.inet_ntoa(d[i:i+4])); return 0
        i += rdl
    print('DNS-NOANSWER'); return 1

a = argparse.ArgumentParser(); sub = a.add_subparsers(dest='m', required=True)
p = sub.add_parser('server'); p.add_argument('--bind', required=True); p.add_argument('--port', type=int, default=9999); p.add_argument('--name', required=True)
p = sub.add_parser('probe');  p.add_argument('--host', required=True); p.add_argument('--port', type=int, default=9999); p.add_argument('--timeout', type=float, default=1.0)
p = sub.add_parser('garp');   p.add_argument('--dev', required=True); p.add_argument('--ip', required=True)
p = sub.add_parser('dns');    p.add_argument('--server', required=True); p.add_argument('--name', default='whoami.lab')
g = a.parse_args()
sys.exit({'server': server, 'probe': probe, 'garp': garp, 'dns': dns}[g.m](g))
PYEOF

# ------------------------------------------------------------------ topology
build_topology() {
    for n in $NS_ALL; do
        ip netns add "$n"; ip -n "$n" link set lo up
        # A DHCP client has no address yet, so the server's reply arrives from a
        # source it has no route to. rp_filter defaults to 2 (loose) here and
        # would drop it — real clients dodge this with AF_PACKET; we just turn
        # the check off inside the lab.
        ip netns exec "$n" sysctl -qw net.ipv4.conf.all.rp_filter=0
        ip netns exec "$n" sysctl -qw net.ipv4.conf.default.rp_filter=0
    done
    ip link add br-lan type bridge forward_delay 0; ip link set br-lan up

    lan() {   # lan <ns> <ifname> <peer> <cidr>
        ip link add "$3" type veth peer name "$2" netns "$1"
        ip link set "$3" master br-lan; ip link set "$3" up
        ip -n "$1" link set "$2" up
        [ -n "${4:-}" ] && ip -n "$1" addr add "$4" dev "$2"
    }
    lan gw3  lan3 br-gw3 192.168.15.252/24
    lan gw2  lan2 br-gw2 192.168.15.251/24
    lan cli1 eth0 br-cli1 ""
    lan cli2 eth0 br-cli2 ""

    # WAN A: gw3 <-> isp-cc (Comcast)
    ip link add cc-gw type veth peer name wan3 netns gw3
    ip link set cc-gw netns isp-cc
    ip -n isp-cc addr add 203.0.113.1/24 dev cc-gw;  ip -n isp-cc link set cc-gw up
    ip -n gw3    addr add 203.0.113.252/24 dev wan3; ip -n gw3 link set wan3 up
    ip -n gw3    route add default via 203.0.113.1 dev wan3
    ip -n isp-cc route add 192.168.15.0/24 via 203.0.113.252 dev cc-gw
    ip -n isp-cc addr add 1.1.1.1/32 dev lo

    # WAN B: gw2 <-> isp-tm (T-Mobile) — real gw2 numbering
    ip link add tm-gw type veth peer name wan2 netns gw2
    ip link set tm-gw netns isp-tm
    ip -n isp-tm addr add 192.168.0.1/24 dev tm-gw;  ip -n isp-tm link set tm-gw up
    ip -n gw2    addr add 192.168.0.181/24 dev wan2; ip -n gw2 link set wan2 up
    ip -n gw2    route add default via 192.168.0.1 dev wan2
    ip -n isp-tm route add 192.168.15.0/24 via 192.168.0.181 dev tm-gw
    ip -n isp-tm addr add 1.1.1.1/32 dev lo

    for n in gw3 gw2; do ip netns exec "$n" sysctl -qw net.ipv4.ip_forward=1; done

    # Per-uplink probe tables. Without these, a health probe pinned to the WAN
    # *device* stops working the moment the default route moves off that device
    # — the gateway then cannot tell that the dead uplink came back. Pinning the
    # probe to the WAN *source address* plus an `ip rule` survives the swap.
    ip -n gw3 route add default via 203.0.113.1 dev wan3 table 100
    ip -n gw3 rule  add from 203.0.113.252 lookup 100
    ip -n gw2 route add default via 192.168.0.1 dev wan2 table 100
    ip -n gw2 rule  add from 192.168.0.181 lookup 100

    # Make the fake ISPs behave like real ones: arp_ignore=1 stops them
    # answering ARP for 1.1.1.1 (which lives on their lo). Without this, a
    # device-bound probe reaches the target with no route at all — a lab
    # artifact that would hide the real failure mode below.
    for n in isp-cc isp-tm; do
        ip netns exec "$n" sysctl -qw net.ipv4.conf.all.arp_ignore=1
        ip netns exec "$n" sysctl -qw net.ipv4.conf.default.arp_ignore=1
    done

    ip netns exec isp-cc python3 "$LAB/wanid.py" server --bind 1.1.1.1 --name COMCAST &
    ip netns exec isp-tm python3 "$LAB/wanid.py" server --bind 1.1.1.1 --name TMOBILE &
    sleep 0.3
}

# ------------------------------------------------------------------- dnsmasq
# $1 = gw3|gw2 ; router option comes from the optsdir so it can be rewritten at
# runtime (dhcp-option= in the conf file could only be changed by a restart —
# dnsmasq(8) NOTES: "SIGHUP does NOT re-read the configuration file").
set_router_opt() { printf 'option:router,%s\n' "$2" > "$LAB/$1/opts/router"; }

start_dnsmasq() {
    local g=$1 lanip rangelo rangehi
    case $g in
      gw3) lanip=192.168.15.252; rangelo=192.168.15.100; rangehi=192.168.15.199 ;;
      gw2) lanip=192.168.15.251; rangelo=192.168.15.119; rangehi=192.168.15.139 ;;
    esac
    [ -f "$LAB/$g/opts/router" ] || set_router_opt "$g" "$lanip"
    ip netns exec "$g" dnsmasq --no-daemon --user=root --group=root \
        --conf-file=/dev/null --interface="lan${g#gw}" --bind-interfaces \
        --dhcp-range="$rangelo,$rangehi,$LEASE" --no-ping \
        --dhcp-optsdir="$LAB/$g/opts" \
        --dhcp-leasefile="$LAB/$g/leases" \
        --log-dhcp --log-facility="$LAB/$g/dnsmasq.log" \
        --no-resolv --address="/whoami.lab/$lanip" \
        --pid-file="$LAB/$g/pid" >>"$LAB/$g/stdout" 2>&1 &
    echo $! > "$LAB/$g/shpid"
    sleep 0.6
}
stop_dnsmasq() { [ -f "$LAB/$1/shpid" ] && kill "$(cat "$LAB/$1/shpid")" 2>/dev/null; sleep 0.3; }
hup_dnsmasq()  { kill -HUP "$(cat "$LAB/$1/shpid")" 2>/dev/null; sleep 0.5; }

# --------------------------------------------------------------------- client
client_lease()  {
    rm -f "$LAB/$1/router"
    ip netns exec "$1" python3 "$LAB/labdhcp.py" run --dev eth0 --state "$LAB/$1" \
        >>"$LAB/$1/stdout" 2>&1 &
    echo $! > "$LAB/$1/dhcppid"
    local w=0
    while [ ! -s "$LAB/$1/router" ] && [ $w -lt 20 ]; do sleep 0.5; w=$((w+1)); done
}
client_offers() { ip netns exec "$1" python3 "$LAB/labdhcp.py" discover --dev eth0 --wait "${2:-2}"; }
count_offers()  { client_offers "$1" "${2:-2}" | awk -F= '/^OFFERS=/{print $2}'; }
client_router() { cat "$LAB/$1/router" 2>/dev/null || echo NONE; }
client_events() { wc -l < "$LAB/$1/events.log" 2>/dev/null || echo 0; }
wan_of()        { ip netns exec "$1" python3 "$LAB/wanid.py" probe --host 1.1.1.1 --timeout 1 | awk '{print $1}'; }
dns_of()        { ip netns exec "$1" python3 "$LAB/wanid.py" dns --server "$2" --name whoami.lab; }

# ------------------------------------------------------------- fault injection
# carrier    : gw3's WAN loses link (easy case, the one everyone tests)
# blackhole  : link stays UP, the far end stops answering (the T-Mobile/Comcast
#              "associated but no service" case — the one that breaks naive
#              link-state failover). Implemented by removing the anycast target.
wan_fail() {
    case "$1:$2" in
      comcast:carrier)   ip -n gw3 link set wan3 down ;;
      comcast:blackhole) ip -n isp-cc addr del 1.1.1.1/32 dev lo ;;
      tmobile:carrier)   ip -n gw2 link set wan2 down ;;
      tmobile:blackhole) ip -n isp-tm addr del 1.1.1.1/32 dev lo ;;
    esac
}
wan_heal() {
    case "$1:$2" in
      comcast:carrier)   ip -n gw3 link set wan3 up; ip -n gw3 route replace default via 203.0.113.1 dev wan3 ;;
      comcast:blackhole) ip -n isp-cc addr add 1.1.1.1/32 dev lo 2>/dev/null ;;
      tmobile:carrier)   ip -n gw2 link set wan2 up; ip -n gw2 route replace default via 192.168.0.1 dev wan2 ;;
      tmobile:blackhole) ip -n isp-tm addr add 1.1.1.1/32 dev lo 2>/dev/null ;;
    esac
    return 0
}

# Put the lab back to its as-built state between scenarios.
reset_lab() {
    for c in cli1 cli2; do
        [ -f "$LAB/$c/dhcppid" ] && kill "$(cat "$LAB/$c/dhcppid")" 2>/dev/null
        ip netns exec "$c" ip addr flush dev eth0 2>/dev/null
        ip netns exec "$c" ip route flush dev eth0 2>/dev/null
        rm -f "$LAB/$c"/*
    done
    [ -f "$LAB/gw3/anchorpid" ] && kill "$(cat "$LAB/gw3/anchorpid")" 2>/dev/null
    stop_dnsmasq gw3; stop_dnsmasq gw2
    wan_heal comcast blackhole; wan_heal tmobile blackhole
    ip -n gw3 link set wan3 up; ip -n gw2 link set wan2 up; ip -n gw2 link set lan2 up
    ip -n gw3 route replace default via 203.0.113.1 dev wan3
    ip -n gw2 route replace default via 192.168.0.1 dev wan2
    ip -n gw3 addr del 192.168.15.250/24 dev lan3 2>/dev/null
    ip -n gw2 addr del 192.168.15.250/24 dev lan2 2>/dev/null
    set_router_opt gw3 192.168.15.252; set_router_opt gw2 192.168.15.251
    rm -f "$LAB"/gw3/leases "$LAB"/gw2/leases
    sleep 0.5
    return 0
}

# ---- the Anchor mechanism, in 12 lines. The probe is exactly what
# bin/net-uplink-probe:124-125 runs (ping -c1 -W2 -q -I <via> <target>), but with
# via = the WAN SOURCE ADDRESS rather than the WAN device name, so the `ip rule`
# above keeps the probe on Comcast after the default route has moved to gw2.
anchor_daemon() {
    ip netns exec gw3 bash -c '
      fails=0
      # State is read from the kernel, never remembered: a supervisor that
      # restarts must not assume it knows where the default route points.
      cur() { ip route show default | grep -q 203.0.113.1 && echo comcast || echo tmobile; }
      while :; do
        if ping -c1 -W2 -q -I 203.0.113.252 1.1.1.1 >/dev/null 2>&1; then
          fails=0
          if [ "$(cur)" = tmobile ]; then
            ip route replace default via 203.0.113.1 dev wan3
            echo "$(date +%s) anchor: back on COMCAST"
          fi
        else
          fails=$((fails+1))
          if [ $fails -ge 2 ] && [ "$(cur)" = comcast ]; then
            ip route replace default via 192.168.15.251 dev lan3
            echo "$(date +%s) anchor: failed over to TMOBILE via gw2"
          fi
        fi
        sleep 1
      done' >>"$LAB/gw3/anchor.log" 2>&1 &
    echo $! > "$LAB/gw3/anchorpid"
}

# ------------------------------------------------------------------ scenarios
sc_baseline() {
    hdr "baseline — gw3 alone serves the LAN, clients egress via Comcast"
    start_dnsmasq gw3
    client_lease cli1
    assert_eq "cli1 router option" "$(client_router cli1)" 192.168.15.252
    assert_eq "cli1 egress uplink"  "$(wan_of cli1)" COMCAST
    assert_eq "DNS answered by"     "$(dns_of cli1 192.168.15.252)" 192.168.15.252
}

sc_twin_race() {
    hdr "twin-race — what happens when gateway2's dnsmasq is simply switched on"
    start_dnsmasq gw3; start_dnsmasq gw2
    set_router_opt gw2 192.168.15.251; hup_dnsmasq gw2
    local n; n=$(count_offers cli1)
    client_offers cli1 2 | sed 's/^/    /'
    assert_eq "distinct DHCP servers answering one DISCOVER" "$n" 2
    say "  ^ two servers, two routers, first-to-answer wins: the client can land"
    say "    on either uplink at random. A 'twin' needs one of them muted."
    say "  mitigation under test: mute gw2 by taking its LAN socket away"
    ip -n gw2 link set lan2 down; sleep 0.5
    n=$(count_offers cli1)
    assert_eq "distinct servers answering with gw2 muted (link down)" "$n" 1
    local t0 t1
    t0=$(date +%s%N); ip -n gw2 link set lan2 up; sleep 0.2
    n=$(count_offers cli1); t1=$(date +%s%N)
    say "  unmute-to-serving: $(( (t1-t0)/1000000 )) ms including the DISCOVER (servers answering: $n)"
    say "  NOTE: dnsmasq has no runtime 'stop answering DHCP' switch —"
    say "  --dhcp-ignore is config, and SIGHUP does not re-read the config file"
    say "  (dnsmasq(8) NOTES). Muting means dropping the socket or the process."
}

sc_optsdir_flip() {
    hdr "optsdir-flip — moving the router option at runtime, and what it costs"
    start_dnsmasq gw3
    set_router_opt gw3 192.168.15.252; hup_dnsmasq gw3
    client_lease cli1
    assert_eq "cli1 bound with router" "$(client_router cli1)" 192.168.15.252
    local before; before=$(client_events cli1)

    say "  rewriting dhcp-optsdir file: option:router -> 192.168.15.251"
    set_router_opt gw3 192.168.15.251
    sleep 1
    say "  a brand-new client, WITHOUT any signal to dnsmasq:"
    local newrouter; newrouter=$(client_offers cli2 2 | awk '/^OFFER /{print $4}' | head -1)
    assert_eq "hot-reload of dhcp-optsdir with no SIGHUP" "$newrouter" "router=192.168.15.251"
    say "  (dnsmasq 2.92 inotify-watches an optsdir and picks up a CHANGED file"
    say "   on its own — no signal, no restart. This is the only runtime-mutable"
    say "   knob it has; --dhcp-option= in the conf file is not one, because"
    say "   'SIGHUP does NOT re-read the configuration file' — dnsmasq(8) NOTES.)"
    hup_dnsmasq gw3
    newrouter=$(client_offers cli2 2 | awk '/^OFFER /{print $4}' | head -1)
    assert_eq "new client's router after SIGHUP too" "$newrouter" "router=192.168.15.251"

    say "  now the existing client: it keeps the OLD router until it renews."
    assert_eq "cli1 still on old router right after the flip" "$(client_router cli1)" 192.168.15.252
    local t0=$(date +%s) waited=0
    while [ "$(client_router cli1)" = 192.168.15.252 ] && [ $waited -lt $(( LEASE )) ]; do
        sleep 1; waited=$(( $(date +%s) - t0 ))
    done
    if [ "$(client_router cli1)" = 192.168.15.251 ]; then
        ok "cli1 followed the flip after ${waited}s — $(scaled $waited)"
    else
        bad "cli1 never followed the flip within ${waited}s"
    fi
    say "  >>> THIS IS THE 24h CONSTRAINT, MEASURED: a router-option change"
    say "      propagates at lease/2. At LEASE=86400 that is ~12h, and the tail"
    say "      is the full 24h for a client that just renewed. Any design that"
    say "      switches uplinks by rewriting option:router is a MIGRATION tool,"
    say "      not a failover tool."
    say "  events cli1 logged: $before -> $(client_events cli1)"
}

sc_anchor() {
    hdr "anchor — the uplink moves, the clients do not"
    start_dnsmasq gw3
    client_lease cli1
    local before_ev; before_ev=$(client_events cli1)
    assert_eq "pre-failure uplink" "$(wan_of cli1)" COMCAST
    anchor_daemon; sleep 1

    say "  injecting: Comcast link stays UP, far end goes dark (blackhole)"
    wan_fail comcast blackhole
    local t0=$(date +%s) w=0 res=DEAD
    while [ $w -lt 20 ]; do
        res=$(wan_of cli1); [ "$res" = TMOBILE ] && break
        sleep 1; w=$(( $(date +%s) - t0 ))
    done
    assert_eq "post-failure uplink" "$res" TMOBILE
    say "  outage window: ${w}s (probe 1s + 2 consecutive failures)"
    assert_eq "cli1 router option unchanged" "$(client_router cli1)" 192.168.15.252
    assert_eq "cli1 DHCP events during failover (0 = never re-leased)" \
              "$(client_events cli1)" "$before_ev"
    sed -n '1,5p' "$LAB/gw3/anchor.log" 2>/dev/null | sed 's/^/    /'

    say "  --- the stuck-down trap: default route still points at gw2, but"
    say "      Comcast is healthy again. Can the probe tell? ---"
    kill "$(cat "$LAB/gw3/anchorpid")" 2>/dev/null; sleep 1
    wan_heal comcast blackhole
    if ip netns exec gw3 ping -c1 -W2 -q -I wan3 1.1.1.1 >/dev/null 2>&1; then
        bad "device-form probe (ping -I wan3) unexpectedly worked"
    else
        ok "'via wan3' (device form) is BLIND to healthy Comcast after failover"
        say "        net-uplink-probe:124-125 builds exactly this command, and"
        say "        the [uplinks] sample at net-uplink-probe:5-9 is 'via eth0'."
        say "        With that form the gateway can never see its dead uplink"
        say "        recover: failover becomes one-way."
    fi
    if ip netns exec gw3 ping -c1 -W2 -q -I 203.0.113.252 1.1.1.1 >/dev/null 2>&1; then
        ok "'via 203.0.113.252' (source-address form) + ip rule DOES see it"
    else
        bad "source-address probe failed"
    fi
    ip -n gw3 rule del from 203.0.113.252 lookup 100
    if ip netns exec gw3 ping -c1 -W2 -q -I 203.0.113.252 1.1.1.1 >/dev/null 2>&1; then
        bad "source-address probe worked without its ip rule"
    else
        ok "...and it is blind too once 'ip rule from <wan src> lookup 100' is gone"
        say "        => a per-uplink table+rule is a HARD PREREQUISITE for any of"
        say "        the three designs, and it does not exist on gw2/gw3 today."
    fi
    ip -n gw3 rule add from 203.0.113.252 lookup 100

    say "  restarting the daemon: it should now fail back to Comcast"
    anchor_daemon
    t0=$(date +%s); w=0
    while [ $w -lt 20 ]; do
        res=$(wan_of cli1); [ "$res" = COMCAST ] && break
        sleep 1; w=$(( $(date +%s) - t0 ))
    done
    assert_eq "uplink after heal" "$res" COMCAST
    assert_eq "cli1 DHCP events across the whole test" "$(client_events cli1)" "$before_ev"
    kill "$(cat "$LAB/gw3/anchorpid")" 2>/dev/null
}

sc_vip() {
    hdr "vip — floating 192.168.15.250, and the clients it strands"
    ip -n gw3 addr add 192.168.15.250/24 dev lan3
    set_router_opt gw3 192.168.15.250
    start_dnsmasq gw3
    client_lease cli1                      # leases AFTER the VIP exists -> .250
    assert_eq "cli1 router option" "$(client_router cli1)" 192.168.15.250
    assert_eq "cli1 uplink" "$(wan_of cli1)" COMCAST

    # cli2 stands in for every client holding a pre-VIP lease: router = .252.
    ip netns exec cli2 ip addr replace 192.168.15.90/24 dev eth0
    ip netns exec cli2 ip route replace default via 192.168.15.252 dev eth0
    assert_eq "cli2 (pre-VIP lease) uplink" "$(wan_of cli2)" COMCAST

    say "  Comcast dies (link up, far end dark) — the VRRP trigger"
    wan_fail comcast blackhole
    assert_eq "cli1 while the VIP is still on the dead gateway" "$(wan_of cli1)" DEAD

    say "  moving the VIP gw3 -> gw2 (what VRRP would do on Comcast failure)"
    ip -n gw3 addr del 192.168.15.250/24 dev lan3
    ip -n gw2 addr add 192.168.15.250/24 dev lan2
    ip netns exec gw2 python3 "$LAB/wanid.py" garp --dev lan2 --ip 192.168.15.250 | sed 's/^/    /'
    local t0=$(date +%s) w=0 res=DEAD
    while [ $w -lt 15 ]; do
        res=$(wan_of cli1); [ "$res" = TMOBILE ] && break
        sleep 1; w=$(( $(date +%s) - t0 ))
    done
    assert_eq "cli1 uplink after VIP move" "$res" TMOBILE
    say "  VIP move visible to cli1 after ${w}s"
    ip netns exec cli1 ip neigh show 192.168.15.250 | sed 's/^/    ARP: /'
    say "  and the client that never got the VIP as its router:"
    res=$(wan_of cli2)
    if [ "$res" = DEAD ]; then
        ok "cli2 is STRANDED (expected) — it still points at .252, which is dead"
    else
        bad "cli2 unexpectedly reached the Internet as $res"
    fi
    say "  >>> the VIP only helps clients whose lease already names it. Getting"
    say "      every client onto .250 is the same lease/2 migration as above."
}

# ------------------------------------------------------------------ lab shell
lab() {
    case "${1:-help}" in
      status)
        for n in $NS_ALL; do
            printf '\n--- %s\n' "$n"; ip -n "$n" -br addr show | sed 's/^/  /'
            ip -n "$n" route show | sed 's/^/  route /'
        done
        printf '\nclients: cli1 router=%s uplink=%s | cli2 router=%s uplink=%s\n' \
            "$(client_router cli1)" "$(wan_of cli1)" "$(client_router cli2)" "$(wan_of cli2)" ;;
      wan-fail) wan_fail "$2" "${3:-blackhole}" ;;
      wan-heal) wan_heal "$2" "${3:-blackhole}" ;;
      dnsmasq)  case "$2" in start) start_dnsmasq "$3";; stop) stop_dnsmasq "$3";; hup) hup_dnsmasq "$3";; esac ;;
      router)   set_router_opt "$2" "$3"; hup_dnsmasq "$2" ;;
      lease)    client_lease "$2" ;;
      offers)   client_offers "$2" "${3:-2}" ;;
      uplink)   wan_of "$2" ;;
      anchor)   anchor_daemon ;;
      enter)    ip netns exec "$2" bash --norc ;;
      log)      tail -n 30 "$LAB/$2/dnsmasq.log" ;;
      *) cat <<'H'
lab status                     addresses, routes, where each client egresses
lab dnsmasq start|stop|hup gw2|gw3
lab router gw3 192.168.15.251  rewrite dhcp-optsdir option:router + SIGHUP
lab lease cli1                 run the DHCP client (DORA + renew loop)
lab offers cli1 [secs]         one DISCOVER, list every OFFER that comes back
lab uplink cli1                COMCAST | TMOBILE | DEAD
lab wan-fail comcast blackhole|carrier      (also: tmobile)
lab wan-heal comcast blackhole|carrier
lab anchor                     start the route-failover daemon in gw3
lab enter gw3                  shell inside a namespace
lab log gw3                    tail that gateway's dnsmasq log
H
      ;;
    esac
}

# ----------------------------------------------------------------- entrypoint
build_topology
case "${1:-shell}" in
  test)
    case "${2:-all}" in
      all)  sc_baseline;     reset_lab
            sc_twin_race;    reset_lab
            sc_optsdir_flip; reset_lab
            sc_anchor;       reset_lab
            sc_vip ;;
      *)    "sc_${2//-/_}" ;;
    esac
    printf '\n=== %s   (lease=%ss, time scale x%s vs the real 24h lease)\n' \
        "$([ $FAILED = 0 ] && echo 'ALL ASSERTIONS PASSED' || echo 'SOME ASSERTIONS FAILED')" \
        "$LEASE" "$SCALE"
    exit $FAILED ;;
  shell)
    say "dual-WAN lab up. LEASE=${LEASE}s (x$SCALE vs the real 24h lease)."
    say "Nothing here touches the real network. Type 'lab help'. Exit destroys it all."
    for f in $(compgen -A function); do export -f "$f"; done
    export LAB LEASE SCALE NS_ALL
    exec bash --norc -i ;;
  exec)
    # Non-interactive sibling of `shell`: build the topology, export the same
    # helpers, then run a script inside it. `shell` execs `bash -i`, which wants
    # a tty and so cannot be driven from a pipe — this is the entry point a test
    # harness uses to rehearse something against the lab.
    #   dualwan-lab.sh exec /path/to/script.sh [args...]
    for f in $(compgen -A function); do export -f "$f"; done
    export LAB LEASE SCALE NS_ALL
    shift
    [ $# -ge 1 ] || { say "usage: $0 exec SCRIPT [args...]"; exit 2; }
    exec bash --norc "$@" ;;
  *) say "usage: $0 [shell|exec SCRIPT|test [all|baseline|twin-race|optsdir-flip|anchor|vip]]"; exit 2 ;;
esac
