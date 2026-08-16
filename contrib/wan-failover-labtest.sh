set -uo pipefail
FO=/mnt/c/cygwin64/usr/local/src/net-mgr/sbin/net-mgr-wan-failover
CONF=/tmp/wanfo.conf; STATE=/tmp/wanfo.state; rm -f $STATE
cat > $CONF <<CONF
primary_via   = 203.0.113.1
primary_dev   = wan3
primary_src   = 203.0.113.252
backup_via    = 192.168.15.251
backup_dev    = lan3
probe_targets = 1.1.1.1
table         = 100
fail_after    = 2
ok_after      = 3
CONF
fo(){ ip netns exec gw3 perl $FO --config $CONF --state $STATE "$@" 2>&1; }
dflt(){ ip netns exec gw3 ip -4 route show default | head -1; }

start_dnsmasq gw3 >/dev/null 2>&1
client_lease cli1 >/dev/null 2>&1
echo "ROUTER=$(client_router cli1)"
echo "B_UPLINK=$(wan_of cli1)"
echo "B_PATH=$(dflt)"

wan_fail comcast blackhole >/dev/null 2>&1
for i in 1 2 3; do fo check >/dev/null 2>&1; done
echo "C_PATH=$(dflt)"
echo "C_UPLINK=$(wan_of cli1)"
echo "C_ROUTER=$(client_router cli1)"

wan_heal comcast blackhole >/dev/null 2>&1
for i in 1 2 3 4; do fo check >/dev/null 2>&1; done
echo "D_PATH=$(dflt)"
echo "D_UPLINK=$(wan_of cli1)"
echo "D_DEFAULTS=$(ip netns exec gw3 ip -4 route show default | wc -l)"
