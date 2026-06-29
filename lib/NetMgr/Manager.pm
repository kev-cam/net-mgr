package NetMgr::Manager;
# Main net-mgr daemon. Listens on a TCP socket, accepts producer
# observations + subscriber connections, applies UPSERTs to MySQL,
# detects state transitions, and (in stage-2) streams matching rows
# to subscribers.
#
# Stage 1 (this module): producer side only.
#   - HELLO/OBSERVE/GONE/BYE handling
#   - DB upsert + event-logging based on change-info
#   - ERR/OK replies
#
# Stage 2 will add SUBSCRIBE/UNSUB/TRIGGER and streaming.

use strict;
use warnings;
use Carp qw(croak);
use IO::Socket::INET;
use IO::Socket::IP;     # IPv6-capable listener (control plane); INET kept for dnsmasq event listeners
use NetMgr::Addr qw(split_hostport join_hostport local_addrs addr_in_prefix);
use NetMgr::Vlan ();
use NetMgr::Tunnel ();
use NetMgr::Ddns ();
use IO::Select;
use Time::HiRes qw(time);
use FindBin ();
use POSIX ();
use NetMgr::Protocol qw(parse_line format_ok format_err format_row format_eos format_ready);
use NetMgr::Where    qw(parse eval_ast);
use NetMgr::ChatArchive ();
use NetMgr::Auth     ();
use NetMgr::Mesh     ();
use NetMgr::Election ();
use NetMgr::AutoDiscover ();

# Logical tables a SUBSCRIBE may target.
my %SUBSCRIBABLE = map { $_ => 1 } qw(
    machines hostnames interfaces addresses ports aps
    associations dhcp_leases events aliases dhcp_vars
    subnet_routers friendly_names wifi_sockets lost_devices
    peers uplinks isp_links
    forwarding_rules zone_classes interface_zones wifi_zones
    audit_annotations wifi_scan_results wifi_radio_state
    chat_sessions chat_members chat_messages chat_presence
    host_keys dhcp_ranges dhcp_reservations
    mesh_tunnels
);

# Tables whose contents are sensitive (credentials etc.); SUBSCRIBE
# is allowed only when the calling connection has completed AUTH.
my %SUBSCRIBABLE_AUTH = map { $_ => 1 } qw(
    isp_secrets
    chat_authorized_keys
);

sub new {
    my ($class, %args) = @_;
    croak "config required" unless $args{config};
    croak "db required"     unless $args{db};
    my $log_fh = $args{log_fh};
    $log_fh = \*STDERR unless defined $log_fh;
    my $self = bless {
        config    => $args{config},
        db        => $args{db},
        log_fh    => $log_fh,
        listeners => {},      # fd → { sock, host, port }
        select    => undef,
        clients   => {},      # fd → { sock, source/consumer, buffer, peer }
        triggers  => {},      # pid → { cli_fd, name, started_at } pending TRIGGER WAITs
        dnsmasq_listeners => {}, # "host:port" → { sock, host, port, buffer }
        started_at => time(),    # for STATUS uptime reporting
        stop      => 0,
        auth_state => NetMgr::Auth::new_state(
            signers_path    => '/etc/net-mgr/allowed_signers',
            authorized_keys => $> == 0 ? '/root/.ssh/authorized_keys'
                                       : ((getpwuid($>))[7] // '') . '/.ssh/authorized_keys',
        ),
        # Chat-only authorization: a dedicated, lower-privilege key list.
        # A key here may use the chat verbs but gets scope='chat' — NO
        # mesh-mutation rights (FORWARD/NAT/SET_GATEWAY) and no access to
        # auth-gated tables. Independent of ~/.ssh/authorized_keys (no
        # fallback) so chat access is decoupled from SSH login, and being on
        # allowed_signers is not required (that grants far more than chat needs).
        chat_auth_state => NetMgr::Auth::new_state(
            signers_path    => '/etc/net-mgr/allowed_chat',
            authorized_keys => undef,
        ),
        # Self-update authorization: a dedicated allowlist of keys permitted to
        # fire `self_update` (git pull --ff-only + reinstall) over the mesh — so
        # an authorized operator can redeploy a node without ssh, but a merely
        # auth'd peer cannot. Strict (no authorized_keys fallback). A key here can
        # AUTH (Tier 3) and is flagged may_update; loopback/local root is exempt.
        update_auth_state => NetMgr::Auth::new_state(
            signers_path    => '/etc/net-mgr/allowed_updaters',
            authorized_keys => undef,
        ),
        # he_net (internet-uplink) authorization: a dedicated allowlist of keys
        # permitted to drive `he_net` (bring the HE 6in4 tunnel up/down) over the
        # mesh. Same model as allowed_updaters — a key here can AUTH (Tier 4) and
        # is flagged may_internet; loopback/local root is exempt. Lets an operator
        # manage a gateway's uplink without full scope or ssh.
        internet_auth_state => NetMgr::Auth::new_state(
            signers_path    => '/etc/net-mgr/allowed_internet',
            authorized_keys => undef,
        ),
        # debug/query authorization: a dedicated allowlist of keys permitted to
        # run POLL (read-only state probes — ipv6/ifaces/routes/fw_state) over the
        # mesh. Same model as above — a key here can AUTH (Tier 5) and is flagged
        # may_debug; loopback/local root is exempt. This allowlist only RESTRICTS
        # when it exists AND [debug] enabled is on; absent file = POLL is open
        # (back-compat), [debug] enabled=off = POLL is refused for everyone.
        debug_auth_state => NetMgr::Auth::new_state(
            signers_path    => '/etc/net-mgr/allowed_debug',
            authorized_keys => undef,
        ),
        version => _read_version(),
        cluster => _load_cluster_state($args{config}),
    }, $class;
    return $self;
}

# The code version reported by STATUS — the git describe string stamped
# into share/net-mgr/version at `make install` (falls back to the source
# tree's .version for from-source runs, else 'unknown').
sub _read_version {
    for my $f ('/usr/local/share/net-mgr/version',
               (__FILE__ =~ m{(.*)/lib/NetMgr/Manager\.pm$} ? "$1/.version" : ())) {
        next unless defined $f && -r $f;
        open my $fh, '<', $f or next;
        chomp(my $v = <$fh> // '');
        close $fh;
        return $v if length $v;
    }
    return 'unknown';
}

# Parse [cluster] config into a normalised state hash. Returns a
# hashref with defaults filled in even when [cluster] is absent —
# absent config means a single-node "cluster" (this host alone),
# which always has quorum and is its own master.
sub _load_cluster_state {
    my ($cfg) = @_;
    my $c = $cfg->{cluster} // {};
    my @members;
    my $auto_spec;
    if (defined $c->{members}) {
        # The directive may be a literal comma-list ("kc-qernel,nas3")
        # or an auto-discovery directive ("auto:DMZ", "auto:Private/lab",
        # bare "auto"). Auto-mode starts with an empty members list;
        # the daemon fills it in periodically via NetMgr::AutoDiscover.
        my $raw = $c->{members};
        $raw =~ s/^\s+|\s+$//g;
        if (my $spec = NetMgr::AutoDiscover::parse_spec($raw)) {
            $auto_spec = $spec;
        } else {
            @members = grep { length }
                       map  { s/^\s+|\s+$//gr }
                       split /,/, $raw;
        }
    }
    # Default membership: auto-discover / follow. A node joins the cluster
    # automatically — no [cluster] section required — finding the other net-mgr
    # instances itself instead of a hand-maintained roster. role=excluded opts
    # back out; role=master (set explicitly, e.g. on nas3) makes a node the
    # authority. Everyone else defaults to follower (see role default below).
    if (!defined $c->{members} && ($c->{role} // 'follower') ne 'excluded') {
        $auto_spec = NetMgr::AutoDiscover::parse_spec('auto');
    }
    # Cluster identity: [cluster] name, else [cluster] domain, else the DNS
    # domain ([dns] domain). The cluster name defaults to the domain.
    my $domain = $c->{domain};
    $domain //= $cfg->{dns}{domain} if ref $cfg->{dns} eq 'HASH';
    $domain =~ s/^\s+|\s+$//g if defined $domain;
    $domain = undef unless defined $domain && length $domain;
    my $cluster_name = $c->{name};
    $cluster_name =~ s/^\s+|\s+$//g if defined $cluster_name;
    $cluster_name = $domain unless defined $cluster_name && length $cluster_name;
    my $self_name = _local_member_name();
    my %state = (
        members          => \@members,
        auto_spec        => $auto_spec,        # undef = static members
        name             => $cluster_name,     # cluster identity; defaults to domain
        domain           => $domain,           # defaults to [dns] domain
        role             => $c->{role}        // 'follower',  # auto|master|follower|excluded; default follow
        master           => $c->{master},     # config override: NAME == self → claim; else follow NAME
        priority         => $c->{priority}    // 100,
        prefer_lan       => exists $c->{prefer_lan} ? ($c->{prefer_lan} ? 1 : 0) : 1,
        internet_facing  => $c->{internet_facing},        # 0|1|undef (=auto)
        election_interval=> $c->{election_interval} // 60,
        self_name        => $self_name,
        is_member        => (!@members || grep { $_ eq $self_name } @members) ? 1 : 0,
        # Self-declared capabilities — this daemon's claim of what
        # it can do. Comma-separated tag list. Treated as advisory
        # by peers (each peer's local %peer_caps is authoritative
        # for what THEY grant — see _load_peer_caps).
        capabilities     => _split_caps($c->{capabilities}),
        # Local authority table: peer name → arrayref of capability
        # tags this daemon grants. Source: /etc/net-mgr/peers (or
        # the path given by [cluster] peers_file). This is THIS
        # daemon's opinion of who's allowed to do what; election
        # filters use it. Other daemons may have different opinions
        # — operator's job to keep them in sync.
        peers_file       => $c->{peers_file} // '/etc/net-mgr/peers',
        peer_caps        => _load_peer_caps($c->{peers_file}
                                            // '/etc/net-mgr/peers'),
    );
    return \%state;
}

sub _split_caps {
    my ($s) = @_;
    return [] unless defined $s && length $s;
    return [ grep { length } map { s/^\s+|\s+$//gr } split /[,\s]+/, $s ];
}

# Load /etc/net-mgr/peers (or whatever path was configured).
# Format is one peer per line, "name: cap1, cap2, ...". Lines
# starting with # are comments; blank lines are ignored. An empty
# capability list ("name:") means the peer is recognised but
# granted nothing — useful for explicitly denying all capabilities.
# Missing file = empty table (no peers granted anything; equivalent
# to a one-node deployment).
sub _load_peer_caps {
    my ($path) = @_;
    my %caps;
    return \%caps unless -r $path;
    open my $fh, '<', $path or return \%caps;
    while (my $line = <$fh>) {
        $line =~ s/[\r\n]+\z//;
        $line =~ s/\s*#.*//;
        $line =~ s/^\s+|\s+$//g;
        next unless length $line;
        if ($line =~ /^([\w.-]+)\s*:\s*(.*)$/) {
            my ($name, $rest) = ($1, $2);
            $caps{$name} = _split_caps($rest);
        }
    }
    close $fh;
    return \%caps;
}

# Identity used in cluster rosters. Hostname's first label (so the
# config can reasonably use bare names like 'kc-qernel' rather than
# fully-qualified). Override via env for testing.
sub _local_member_name {
    return $ENV{NET_MGR_CLUSTER_NAME} if defined $ENV{NET_MGR_CLUSTER_NAME};
    require Sys::Hostname;
    my $h = Sys::Hostname::hostname();
    $h =~ s/\..*//;
    return $h;
}

# ---- logging ----------------------------------------------------------
# Method named _log to avoid any collision with the `log` builtin.

sub _log {
    my ($self, $msg) = @_;
    my $fh = $self->{log_fh};
    return unless defined $fh;
    my $ts = _ts();
    print {$fh} "$ts $msg\n";
}

sub _ts {
    my @t = localtime;
    return sprintf "%04d-%02d-%02d %02d:%02d:%02d",
        $t[5]+1900, $t[4]+1, $t[3], $t[2], $t[1], $t[0];
}

# ---- listener / loop --------------------------------------------------

# A host:port the daemon's own forked children (and local tools) can connect()
# to in order to reach us. Derived from the actual bound listeners, never the
# raw bind spec: a wildcard bind (0.0.0.0 / ::, or 'auto' which resolves to it)
# is reachable on loopback, so prefer 127.0.0.1:<port>; otherwise hand back a
# concrete bound address.
sub _self_connect_addr {
    my ($self) = @_;
    my @l = values %{ $self->{listeners} || {} };
    return '127.0.0.1:7531' unless @l;
    for my $b (@l) {
        return "127.0.0.1:$b->{port}"
            if $b->{host} eq '0.0.0.0' || $b->{host} eq '::'
            || $b->{host} eq '::1' || $b->{host} =~ /^127\./;
    }
    my $b = $l[0];
    return join_hostport($b->{host}, $b->{port});   # brackets a v6 host
}

sub start_listener {
    my ($self) = @_;
    # Attach our IPv6 networks first (control VLAN + any he6in4 uplink). A vlan
    # sets control_prefix as a side effect, so its address exists before the v6
    # 'auto' enumeration below picks it up.
    $self->_attach_ipv6_vlans;
    my $spec = $self->{config}{manager}{listen} || 'all';
    my @binds = _resolve_listen_spec($spec, $self->{config}{cluster}{control_prefix},
                                     $self->{config}{manager}{listen_exclude});
    croak "no listen addresses resolved from '$spec'" unless @binds;

    $self->{select} = IO::Select->new;
    for my $b (@binds) {
        # IO::Socket::IP binds either family; V6Only on v6 binds so a v6 listener
        # doesn't shadow the matching v4 one (we bind them as separate sockets).
        my $is_v6 = ($b->{host} // '') =~ /:/;
        my $sock = IO::Socket::IP->new(
            LocalAddr => $b->{host},
            LocalPort => $b->{port},
            Listen    => 16,
            ReuseAddr => 1,
            Proto     => 'tcp',
            ($is_v6 ? (V6Only => 1) : ()),
        );
        if (!$sock) {
            $self->_log("WARN: bind $b->{host}:$b->{port} failed: $!");
            next;
        }
        my $fd = fileno($sock);
        $self->{listeners}{$fd} = { sock => $sock, host => $b->{host}, port => $b->{port} };
        $self->{select}->add($sock);
        $self->_log("listening on $b->{host}:$b->{port}");
    }
    croak "no listeners could be bound from '$spec'" unless %{ $self->{listeners} };
    $self->_start_mesh;
    return [ map { $_->{sock} } values %{ $self->{listeners} } ];
}

# Re-evaluate an 'all'/'auto' listen spec against the CURRENT interfaces and
# adjust the bound listeners — bind addresses that appeared (WiFi associated, a
# USB NIC was plugged in) and drop ones whose interface went away. This is what
# keeps a daemon that started before its WiFi was up from staying stuck on
# loopback. Runs from the periodic 'netif' trigger and on SIGHUP (so an
# if-up/down or NetworkManager-dispatcher hook can poke it for an instant
# update). Additive against the LIVE IO::Select — never resets it, so client and
# mesh fds are untouched. A no-op for an explicit address list (static by intent).
sub _recheck_listeners {
    my ($self) = @_;
    my $spec = $self->{config}{manager}{listen} || 'all';
    return unless grep { lc($_) eq 'all' || lc($_) eq 'auto' }
                  map { s/^\s+|\s+$//gr } split /,/, $spec;
    my @want = _resolve_listen_spec($spec, $self->{config}{cluster}{control_prefix},
                                    $self->{config}{manager}{listen_exclude});
    my %want = map { ("$_->{host}|$_->{port}" => $_) } @want;
    my %have;
    for my $fd (keys %{ $self->{listeners} }) {
        my $l = $self->{listeners}{$fd};
        $have{"$l->{host}|$l->{port}"} = $fd;
    }
    # Bind newly-appeared addresses.
    for my $key (sort keys %want) {
        next if $have{$key};
        my $b = $want{$key};
        my $is_v6 = ($b->{host} // '') =~ /:/;
        my $sock = IO::Socket::IP->new(
            LocalAddr => $b->{host}, LocalPort => $b->{port},
            Listen    => 16, ReuseAddr => 1, Proto => 'tcp',
            ($is_v6 ? (V6Only => 1) : ()),
        );
        if (!$sock) { $self->_log("WARN: rebind $b->{host}:$b->{port} failed: $!"); next; }
        my $fd = fileno($sock);
        $self->{listeners}{$fd} = { sock => $sock, host => $b->{host}, port => $b->{port} };
        $self->{select}->add($sock);
        $self->_log("listening on $b->{host}:$b->{port} (interface appeared)");
    }
    # Drop listeners whose address vanished — but never loopback or a wildcard
    # bind, which don't ride a transient interface.
    for my $key (sort keys %have) {
        next if $want{$key};
        my ($host) = split /\|/, $key, 2;
        next if $host eq '127.0.0.1' || $host eq '0.0.0.0'
             || $host eq '::'        || $host eq '::1';
        my $fd = $have{$key};
        my $l  = delete $self->{listeners}{$fd};
        $self->{select}->remove($l->{sock});
        eval { $l->{sock}->close };
        $self->_log("stopped listening on $host:$l->{port} (interface gone)");
    }
    # The set of local interfaces just changed (or might have). Re-publish our
    # interface inventory to the cluster DB so other nodes see our current
    # addresses immediately — without this a WiFi association / USB-NIC plug
    # waits for the next 5-min find-peers sweep to surface us, and the GUI
    # shows our IPs as 'free' until then.
    $self->_register_self_interfaces;
}

# Publish THIS host's machine row + every non-loopback interface (mac, kind,
# and v4 addresses) into the cluster DB. Cluster replication then makes the
# rows visible everywhere — without this, an interface we just brought up is
# unknown to the mesh until another producer (net-discover, ARP, dnsmasq lease)
# happens to notice us. Called on startup (sbin/net-mgr's register_self
# delegates here) and on every netif rescan (_recheck_listeners, above).
# Idempotent: every upsert is keyed by mac / (mac,addr) so re-runs just bump
# last_seen. WiFi interfaces are tagged kind=wifi via /sys/class/net/<n>/wireless.
sub _register_self_interfaces {
    my ($self) = @_;
    my $inv = $self->_collect_self_inventory or return;
    $self->_apply_self_inventory($inv);
    # Replication only flows master → followers, so a follower's "self" rows
    # would otherwise stay local — invisible to anyone viewing this host's
    # subnets from another node. Forward to the master so it upserts the same
    # rows and replication carries them back out to the whole cluster.
    $self->_publish_self_to_master($inv);
}

# Snapshot the host's interface inventory — `ip -o link show` for (iface, mac)
# and `ip -br -4 addr show` for the v4 addresses each iface carries. Returns a
# hashref { host, ifaces => [{ name, mac, kind, online, addrs => [v4...] }] }
# or undef when the hostname is empty. Pure (one fork+exec per `ip` call).
sub _collect_self_inventory {
    my ($self) = @_;
    require Sys::Hostname;
    my $host = Sys::Hostname::hostname();
    $host =~ s/\..*$//;
    return undef unless length $host;
    # iface -> mac. Strip @parent suffix VLANs add ("enp19s0.10@enp19s0"); the
    # MAC and v4 address rows we care about live on the same key regardless of
    # the VLAN sub-iface.
    my %iface_mac;
    if (open my $lh, '-|', 'ip', '-o', 'link', 'show') {
        while (<$lh>) {
            next unless /^\d+:\s+(\S+?):\s+/;
            my $name = $1;
            $name =~ s/\@.*//;
            next if $name eq 'lo';
            if (m{link/ether\s+([0-9a-f:]+)}i) {
                $iface_mac{$name} = lc $1;
            }
        }
        close $lh;
    }
    my (%iface_addrs, %iface_state);
    if (open my $ah, '-|', 'ip', '-br', '-4', 'addr', 'show') {
        while (<$ah>) {
            chomp;
            my ($iface, $state, @addrs) = split ' ';
            next unless $iface && $iface ne 'lo';
            $iface =~ s/\@.*//;
            $iface_state{$iface} = $state;
            for my $a (@addrs) {
                $a =~ s|/.*||;
                next if $a =~ /^127\./ || $a =~ /^169\.254\./;
                push @{ $iface_addrs{$iface} }, $a;
            }
        }
        close $ah;
    }
    my @ifaces;
    for my $name (sort keys %iface_mac) {
        push @ifaces, {
            name   => $name,
            mac    => $iface_mac{$name},
            kind   => ((-d "/sys/class/net/$name/wireless") ? 'wifi' : 'ethernet'),
            online => (($iface_state{$name} // '') eq 'UP' ? 1 : 0),
            addrs  => $iface_addrs{$name} // [],
        };
    }
    return { host => $host, ifaces => \@ifaces };
}

# Write the inventory to the local DB: machines + hostnames + interfaces +
# addresses, each upsert wrapped in eval (so a single bad row doesn't poison
# the rest). Called locally on every node, AND on the master when a follower
# OBSERVE-publishes its inventory (so the data lands in the master's DB and
# replicates back out cluster-wide).
sub _apply_self_inventory {
    my ($self, $inv) = @_;
    my $db = $self->{db} or return;
    my $host = $inv->{host};
    return unless defined $host && length $host;
    # One machine row per host, keyed by primary_name (matches the historical
    # convention; the user manages -lx / -air / -vm via /etc/hostname).
    my ($mid) = $db->dbh->selectrow_array(
        "SELECT id FROM machines WHERE primary_name = ?", undef, $host);
    if ($mid) {
        $db->upsert_machine(id => $mid, primary_name => $host, online => 1);
    } else {
        my $r = $db->upsert_machine(primary_name => $host, online => 1);
        $mid = $r->{now}{id} if $r && $r->{now};
    }
    return unless $mid;
    $db->upsert_hostname(machine_id => $mid, name => $host, source => 'self');
    my $stamp_source = "$host:self";
    for my $i (@{ $inv->{ifaces} || [] }) {
        my $mac = $i->{mac};
        next unless defined $mac && length $mac;
        eval {
            $db->upsert_interface(
                mac => $mac, machine_id => $mid,
                kind => ($i->{kind} // 'ethernet'),
                online => ($i->{online} ? 1 : 0), live => 1,
            );
        };
        $self->_log("register_self: upsert_interface $i->{name}/$mac failed: $@") if $@;
        for my $addr (@{ $i->{addrs} || [] }) {
            eval {
                $db->upsert_address(
                    mac => $mac, family => 'v4', addr => $addr,
                    source => $stamp_source, live => 1,
                );
            };
            $self->_log("register_self: upsert_address $mac $addr failed: $@") if $@;
        }
    }
}

# Forward our inventory to the cluster master so it can write the same rows
# and replication propagates them cluster-wide. No-op when we ARE the master
# (rows are already local and will replicate), or when we have no master
# (single-node deploy / mid-election). Best-effort: a failure just means the
# row is local-only until the next retry (Manager retries on every netif
# rescan / startup).
sub _publish_self_to_master {
    my ($self, $inv) = @_;
    my $cs = $self->{cluster} || {};
    my $self_name = $cs->{self_name} // '';
    my $cr = $self->{cluster_runtime} || {};
    my $master = $cr->{master_member};
    return if !defined $master || !length $master;
    return if $master eq $self_name;            # we ARE master — already local
    my $addr = $self->{mesh} ? $self->{mesh}->address_for($master) : '';
    return unless $addr;
    require MIME::Base64;
    require JSON::PP;
    my $payload = eval { JSON::PP->new->canonical(1)->encode($inv) };
    return if $@ || !defined $payload;
    my $b64 = MIME::Base64::encode_base64($payload, '');
    my $ok = $self->_forward_observe_to_master($addr,
        kind => 'publish_self', inv_b64 => $b64);
    $self->_log("publish_self: forwarded inventory to master '$master' ("
              . scalar(@{ $inv->{ifaces} || [] }) . " ifaces) " . ($ok ? "OK" : "FAILED"));
}

# Attach this node to the "network_management" control VLAN: create the 802.1Q
# sub-interface and address it (NetMgr::Vlan). On by default; [cluster]
# control_attach=off opts out. control_prefix defaults to a ULA derived from the
# dmz subnet. Requires control_vlan_id (must match the switch trunk) — without it
# we log and skip rather than create a mis-tagged interface. Sets control_prefix
# so the listener's v6 'auto' binds the new address.
sub _attach_ipv6_vlans {
    my ($self) = @_;
    my $nets = $self->_ipv6_vlan_networks;
    for my $name ($self->_ipv6_vlan_order($nets)) {
        my $e = $nets->{$name};
        my $type = lc($e->{type} // 'he6in4');
        if    ($type eq 'vlan')   { $self->_attach_vlan_network($name, $e) }
        elsif ($type eq 'he6in4') { $self->_he_net_startup_net($name, $e) }
        elsif ($type eq 'relay')  { $self->_attach_relay_network($name, $e) }
        else { $self->_log("ipv6_vlan '$name': unknown type '$type'") }
    }
}

# Effective IPv6 networks: the config's [ipv6_vlan "name"] entries, plus the
# default-on network_management VLAN, with per-type defaults filled and the
# legacy [cluster] control_* mapped in for back-compat. Explicit config wins
# over both, so the config file carries only overrides.
sub _ipv6_vlan_networks {
    my ($self) = @_;
    my $cfg  = $self->{config};
    my %nets = %{ $cfg->{ipv6_vlan} || {} };       # named sections from config

    my $cl = $cfg->{cluster} || {};
    my %nm;
    $nm{id}     = $cl->{control_vlan_id} if defined $cl->{control_vlan_id} && length $cl->{control_vlan_id};
    $nm{prefix} = $cl->{control_prefix}  if defined $cl->{control_prefix}  && length $cl->{control_prefix};
    $nm{addr}   = $cl->{control_addr}    if defined $cl->{control_addr}    && length $cl->{control_addr};
    $nm{attach} = $cl->{control_attach}  if defined $cl->{control_attach}  && length $cl->{control_attach};
    $nets{network_management} = { type => 'vlan', %nm, %{ $nets{network_management} || {} } };

    for my $name (keys %nets) {
        my $e = $nets{$name};
        my $type = lc($e->{type} // 'he6in4');
        my %defs = $type eq 'vlan'   ? (attach => 'on', addr => 'ipv4', prefix => 'auto')
                 : $type eq 'he6in4' ? (mode => 'off', local_suffix => '2', forwarding => 1)
                 : ();
        $nets{$name} = { type => $type, %defs, %$e };
    }
    return \%nets;
}

# Network names in attach order: vlan (control plane) first, then he6in4, then
# relay (which rides the control VLAN, so it must come after it). Ties broken by
# name for determinism.
sub _ipv6_vlan_order {
    my ($self, $nets) = @_;
    my %pri = (vlan => 0, he6in4 => 1, relay => 2);
    return sort {
        (($pri{ lc($nets->{$a}{type} // 'he6in4') } // 9)
         <=> ($pri{ lc($nets->{$b}{type} // 'he6in4') } // 9)) || $a cmp $b
    } keys %$nets;
}

# Attach a type=vlan IPv6 network (the control plane) — create the 802.1Q
# sub-interface and address it (NetMgr::Vlan). Reads the network's
# id/prefix/addr/attach; prefix=auto derives from the dmz subnet.
sub _attach_vlan_network {
    my ($self, $name, $e) = @_;
    my $attach = lc($e->{attach} // 'on');
    return if $attach =~ /^(off|no|0|false|disabled)$/;

    my $prefix = $e->{prefix} // 'auto';
    if (!length $prefix || lc($prefix) eq 'auto') {
        my $dmz_net = $self->_dmz_subnet_net;       # e.g. 192.168.15.0
        $prefix = $dmz_net && NetMgr::Vlan::derive_prefix($dmz_net);
    }
    unless ($prefix) {
        $self->_log("ipv6_vlan '$name': no prefix and no dmz subnet to derive one; skipping");
        return;
    }
    my $id = $e->{id};
    unless (defined $id && $id ne '' && $id =~ /^\d+$/) {
        $self->_log("ipv6_vlan '$name': id (802.1Q tag) not set; not creating the VLAN. Set [ipv6_vlan \"$name\"] id = <tag>.");
        return;
    }
    my $parent = NetMgr::Vlan::parent_for_subnet();
    unless ($parent) {
        $self->_log("ipv6_vlan '$name': no parent interface (no 192.168.* address); skipping");
        return;
    }
    my $mode = $e->{addr} // 'ipv4';
    my @dmz_ipv4;
    if ($mode eq 'ipv4') {
        my $p24 = NetMgr::Vlan::prefix_ipv4_24($prefix);
        @dmz_ipv4 = grep { index($_, $p24) == 0 } local_addrs('v4') if $p24;
        unless (@dmz_ipv4) {
            $self->_log("ipv6_vlan '$name': no DMZ IPv4 (" . ($p24 // '?') . "*); skipping");
            return;
        }
    }
    my (undef, undef, $err) = NetMgr::Vlan::attach(
        parent => $parent, id => $id, prefix => $prefix, name => $name,
        addr => $mode, ipv4_addrs => \@dmz_ipv4,
        log => sub { $self->_log($_[0]) },
    );
    $self->_log("ipv6_vlan '$name': $err") if $err;
    # The control plane rides this VLAN — let the listener's v6 'auto' bind it.
    $self->{config}{cluster}{control_prefix} = $prefix;
}

# Bring a type=he6in4 network up at startup if mode=on (NetMgr::Tunnel). The
# OBSERVE handler (_obs_he_net) drives it on demand regardless of mode.
sub _he_net_startup_net {
    my ($self, $name, $e) = @_;
    return unless lc($e->{mode} // 'off') eq 'on';
    # Overlay any missing config keys from mesh_tunnels (the DB is the source of
    # truth for tunnel topology; the config file is for OVERRIDES only). So a
    # node like gateway3 with an empty [ipv6_vlan "he_net"] block but a matching
    # mesh_tunnels row comes up with the right server/prefix.
    $e = $self->_merge_tunnel_from_db($name, $e);
    my (undef, $err) = NetMgr::Tunnel::up(
        name => $name, server => $e->{server}, prefix => $e->{prefix},
        local_suffix => ($e->{local_suffix} // '2'),
        forwarding => (defined $e->{forwarding} ? $e->{forwarding} : 1),
        ext_if => ($e->{ext_if} || undef),
        log => sub { $self->_log($_[0]) },
    );
    if ($err) {
        $self->_log("ipv6_vlan '$name': startup bring-up failed: $err");
        return;
    }
    # Push the current WAN IPv4 to HE so the tunnel keeps routing across Comcast
    # WAN rotations (HE only routes the client IPv4 it has on record). Idempotent
    # — HE returns 'nochg' when the registration is already correct, so it's safe
    # to fire on every bring-up. No-op unless tunnel_id + update_secret are set.
    $self->_he_update_endpoint($name, $e);
}

# Overlay missing fields of an [ipv6_vlan he6in4] config entry from the
# cluster-replicated mesh_tunnels table. Lookup by (owner_node=self_name,
# kind='he6in4'). Config keys WIN: a value explicitly set in [ipv6_vlan "..."]
# is never overridden by the DB. The merge is non-destructive — returns a NEW
# hashref so the caller's config dict isn't mutated. Silent on DB error (the
# tunnel still runs from whatever config has set; this is a fallback, not the
# only source). See sql/schema.sql `mesh_tunnels` for the column reference.
sub _merge_tunnel_from_db {
    my ($self, $name, $e) = @_;
    return $e unless $self->{db};
    my $kind = lc($e->{type} // 'he6in4');
    return $e unless $kind eq 'he6in4';
    my $owner = $self->{cluster}{self_name};
    return $e unless defined $owner && length $owner;
    my $row = eval { $self->{db}->get_mesh_tunnel($owner, $kind) };
    return $e if $@ || !$row;
    # Build a fresh hash so callers' configs don't get mutated.
    my %m = %$e;
    # Map DB columns -> [ipv6_vlan] keys. Config wins; only fill what's empty.
    $m{server}        //= $row->{server_v4}     if !defined $m{server}        || !length $m{server};
    $m{prefix}        //= $row->{tunnel_prefix} if !defined $m{prefix}        || !length $m{prefix};
    $m{tunnel_id}     //= $row->{provider_id}   if !defined $m{tunnel_id}     || !length $m{tunnel_id};
    # The routed prefix isn't directly used by the tunnel itself, but a future
    # relay-on-the-gateway path will want it; the column is also what relay
    # nodes look up when their config has no prefix.
    $m{routed_prefix} //= $row->{routed_prefix} if !defined $m{routed_prefix} || !length $m{routed_prefix};
    # secret_name on the row → update_secret in the [ipv6_vlan] shape consumed
    # by _he_update_endpoint. The actual SECRET file is read locally on the
    # node that has it (the cluster master); other nodes route through master.
    $m{update_secret} //= $row->{secret_name}   if !defined $m{update_secret} || !length $m{update_secret};
    return \%m;
}

# Push gateway3's current WAN IPv4 to HE for one [ipv6_vlan he6in4] entry. Reads
# the per-tunnel update key from /etc/net-mgr/secrets/<update_secret> via
# NetMgr::Secret (never logs the credential). Called from _he_net_startup_net (on
# every tunnel bring-up — idempotent self-heal) and from _check_ddns (on a real
# WAN-IP change — fast convergence). Quiet no-op when tunnel_id/update_secret
# aren't configured.
sub _he_update_endpoint {
    my ($self, $name, $e) = @_;
    # provider_id + secret_name from mesh_tunnels fill the gaps; config wins.
    $e = $self->_merge_tunnel_from_db($name, $e);
    return unless defined $e->{tunnel_id} && length $e->{tunnel_id};
    my $secret_name = $e->{update_secret};
    require NetMgr::HE;
    require NetMgr::Secret;
    # Fast path: this node holds the secret — fire the curl directly. Two ways
    # to "hold": secret_name is set AND the file is readable, OR HE auto-detect
    # works because THIS node IS the tunnel endpoint (source IP = WAN).
    if (defined $secret_name && length $secret_name) {
        my ($val, $err) = NetMgr::Secret::get($secret_name);
        if (defined $val) {
            my ($ok, $msg) = NetMgr::HE::update_endpoint(
                tunnel_id   => $e->{tunnel_id},
                secret_name => $secret_name,
                ip          => $e->{myip},        # optional override
                log         => sub { $self->_log("ipv6_vlan '$name': " . $_[0]) },
            );
            return $ok;
        }
        # Secret not local — fall through to master routing.
    }
    # Slow path: forward to the cluster master (who holds the secret). The
    # master looks up mesh_tunnels for owner_node=<this node> and reads its
    # local secret. We pass myip explicitly so HE registers OUR WAN, not the
    # master's. No-op silently if there's no master, no route to it, or this
    # IS the master (in which case the secret should be local — log so the
    # operator can diagnose).
    my $self_name = $self->{cluster}{self_name};
    my $master    = ($self->{cluster_runtime} || {})->{master_member};
    if (!defined $master || !length $master) {
        $self->_log("ipv6_vlan '$name': no secret locally and no master known — skipping");
        return 0;
    }
    if ($master eq $self_name) {
        $self->_log("ipv6_vlan '$name': I am master but secret '"
                  . ($secret_name // '?')
                  . "' is unreadable on me — place it in /etc/net-mgr/secrets/");
        return 0;
    }
    my $addr = $self->{mesh} ? $self->{mesh}->address_for($master) : '';
    if (!$addr) {
        $self->_log("ipv6_vlan '$name': no address for master '$master' — skipping HE update");
        return 0;
    }
    # Look up our current WAN so the master can pass it as myip=.
    my (undef, $wan_v4) = NetMgr::Tunnel::external_ipv4($e->{ext_if});
    my %kv = (kind => 'he_update', target => $self_name, name => $name);
    $kv{myip} = $wan_v4 if defined $wan_v4 && length $wan_v4;
    my $rc = $self->_forward_observe_to_master($addr, %kv);
    if ($rc) {
        $self->_log("ipv6_vlan '$name': HE update forwarded to master '$master' (myip="
                  . ($wan_v4 // '?') . ")");
    } else {
        $self->_log("ipv6_vlan '$name': HE update forward to master '$master' failed");
    }
    return $rc;
}

# Send an OBSERVE to the master and return its OK/ERR as 1/0. Auth-signed with
# this node's mesh key (the master's may_internet allowlist must include it).
sub _forward_observe_to_master {
    my ($self, $master_addr, %kv) = @_;
    require NetMgr::Client;
    my $cli = eval { NetMgr::Client->new(listen => $master_addr, timeout => 6) };
    return 0 if $@ || !$cli;
    eval { $cli->hello(consumer => "he_update.$$") };
    if ($@) { eval { $cli->bye }; return 0 }
    eval { $cli->auth };
    if ($@) {
        $self->_log("forward to master: auth failed: $@");
        eval { $cli->bye };
        return 0;
    }
    my $r = eval { $cli->observe(%kv) };
    eval { $cli->bye };
    return 0 if $@ || !defined $r;
    return ($r =~ /^OK\b/) ? 1 : 0;
}

# All [ipv6_vlan he6in4] entries with HE update configured. Used by _check_ddns
# so a single WAN-IP change refreshes every tunnel on this node (a future
# multi-tunnel setup — Comcast primary + T-Mobile fallback — fires both).
sub _he_update_endpoints {
    my ($self) = @_;
    my $nets = $self->{config}{ipv6_vlan} || {};
    for my $name (sort keys %$nets) {
        my $e = $nets->{$name};
        next unless ref $e eq 'HASH';
        next unless lc($e->{type} // 'he6in4') eq 'he6in4';
        next unless $e->{tunnel_id} && $e->{update_secret};
        $self->_he_update_endpoint($name, $e);
    }
}

# Periodic DDNS check: if the WAN IP changed, run the /etc/net-mgr/ddns hooks
# (NetMgr::Ddns) AND push the new IP to HE for every he6in4 with tunnel_id set.
# Fired by _check_periodic_triggers at the [ddns] interval.
sub _check_ddns {
    my ($self) = @_;
    my $dc = $self->{config}{ddns} || {};
    my ($changed) = NetMgr::Ddns::check(
        dir       => $dc->{dir}       || '/etc/net-mgr/ddns',
        statefile => $dc->{statefile} || '/var/lib/net-mgr/wan-ip',
        ext_if    => ($dc->{ext_if} || undef),
        log       => sub { $self->_log($_[0]) },
    );
    $self->_he_update_endpoints if $changed;
}

# Attach a type=relay IPv6 network: relay the he_net uplink to this node over the
# control VLAN. This node gets a global address from the HE routed prefix on the
# control-VLAN interface (routed_prefix + its DMZ IPv4, the same derivation as the
# control addresses) and — unless it IS the uplink — routes ::/0 to the uplink's
# routed-prefix address. Idempotent. keys:
#   prefix   the HE routed /64 (global, distinct from the he6in4 tunnel /64)
#   gateway  the uplink's DMZ IPv4 (its routed-prefix address is derived)
sub _attach_relay_network {
    my ($self, $name, $e) = @_;
    my $prefix  = $e->{prefix};
    my $gw_ipv4 = $e->{gateway};
    unless ($prefix && $gw_ipv4) {
        $self->_log("ipv6_vlan '$name' (relay): needs prefix (routed /64) + gateway (uplink DMZ IPv4); skipping");
        return;
    }
    # The LAN segment the uplink is on is the gateway's own /24 — derive it
    # straight from the gateway IPv4. This is robust everywhere: it doesn't
    # depend on a dmz-zoned subnet or a control prefix being known on THIS node
    # (a gateway/leaf may know neither), and the gateway address inherently names
    # the segment the relay clients (and the uplink itself) share.
    my $nets    = $self->_ipv6_vlan_networks;
    my $nm      = $nets->{network_management} || {};
    my ($p24)   = $gw_ipv4 =~ /^(\d+\.\d+\.\d+\.)\d+$/;
    unless ($p24) {
        $self->_log("ipv6_vlan '$name' (relay): gateway '$gw_ipv4' is not a dotted IPv4; skipping");
        return;
    }
    my @my_ipv4 = grep { index($_, $p24) == 0 } local_addrs('v4');
    unless (@my_ipv4) {
        $self->_log("ipv6_vlan '$name' (relay): no IPv4 on the gateway's segment ($p24"."0/24); skipping");
        return;
    }
    # Interface to ride: the control VLAN if attached, else the DMZ LAN interface
    # (the one carrying the dmz /24 — where the uplink is reachable). A gateway has
    # several 192.168.* interfaces, so match the dmz /24 specifically.
    my $parent  = NetMgr::Vlan::parent_for_subnet(qr/^\Q$p24\E/);
    my $vlan_if = ($parent && defined $nm->{id} && $nm->{id} =~ /^\d+$/)
                ? "$parent.$nm->{id}" : undef;
    my $ctrl_if = ($vlan_if && `ip -o link show $vlan_if 2>/dev/null`) ? $vlan_if : $parent;
    unless ($ctrl_if) {
        $self->_log("ipv6_vlan '$name' (relay): no interface to ride; skipping");
        return;
    }
    # Self-assign global addresses from the routed prefix on the control VLAN.
    my $is_gw = grep { $_ eq $gw_ipv4 } @my_ipv4;
    # Enable IPv6 on the interface first — a v6-disabled iface (disable_ipv6=1,
    # common on gateways that default IPv6 off per-port) makes `ip -6 addr add`
    # fail with EPERM ("Permission denied") even as root. Write /proc directly so
    # dotted VLAN ifnames don't trip the sysctl key parser.
    _enable_ipv6_iface($ctrl_if);
    my $have  = `ip -6 -o addr show dev $ctrl_if 2>/dev/null`;
    for my $ip (@my_ipv4) {
        my $addr = NetMgr::Vlan::ipv4_addr($ip, $prefix) or next;
        next if index($have, $addr) >= 0;
        # Add the global address, checking the result — a silent system() here
        # logged "global $addr" even when the add failed (e.g. an iproute2 that
        # rejects 'nodad'), which read as success while nothing landed. Retry
        # without 'nodad' if the flag is what it choked on.
        my $out = `ip -6 addr add $addr/64 dev $ctrl_if nodad 2>&1`;
        if ($? && $out =~ /nodad|invalid|Error:/i) {
            $out = `ip -6 addr add $addr/64 dev $ctrl_if 2>&1`;
        }
        chomp $out;
        if ($?) {
            $self->_log("ipv6_vlan '$name' (relay): FAILED to add $addr on $ctrl_if: $out");
            next;
        }
        # Read back — distinguishes a clean add from one that vanished moments
        # later (something else flushing the interface).
        my $back = `ip -6 -o addr show dev $ctrl_if 2>/dev/null`;
        if (index($back, $addr) >= 0) {
            $self->_log("ipv6_vlan '$name' (relay): $ctrl_if global $addr");
        } else {
            $self->_log("ipv6_vlan '$name' (relay): added $addr on $ctrl_if but it VANISHED (flushed by something else?)");
        }
    }
    # Default route via the uplink, unless we ARE the uplink (he_net set ::/0).
    unless ($is_gw) {
        my $gw_addr = NetMgr::Vlan::ipv4_addr($gw_ipv4, $prefix);
        my $route = `ip -6 route show default 2>/dev/null`;
        if ($gw_addr && $route !~ /\Q$gw_addr\E/) {
            system('ip', '-6', 'route', 'replace', '::/0', 'via', $gw_addr, 'dev', $ctrl_if);
            $self->_log("ipv6_vlan '$name' (relay): ::/0 via $gw_addr dev $ctrl_if");
        }
    }
}

# Enable IPv6 on a single interface (disable_ipv6=0) by writing /proc directly.
# A v6-disabled interface rejects `ip -6 addr add` with EPERM even for root, so
# managed IPv6 (the relay address, the he6in4 tunnel address) must clear this
# first. Surgical — only the named interface's own knob, never conf/all (writing
# 'all' would propagate to every interface). No-op if already enabled / unwritable.
sub _enable_ipv6_iface {
    my ($iface) = @_;
    return unless defined $iface && length $iface;
    my $p = "/proc/sys/net/ipv6/conf/$iface/disable_ipv6";
    return unless -w $p;
    if (open my $fh, '>', $p) { print $fh "0\n"; close $fh; }
}

# Periodic ipv6_vlan keep-up: re-establish any managed IPv6 network that should
# be up but isn't — the WAN wasn't ready at boot, the he6in4 tunnel was lost, a
# VLAN sub-interface went away, etc. Re-runs the type-appropriate attach (both
# idempotent), only when the interface lacks LOWER_UP, so it's quiet when
# everything is up. Fired by _check_periodic_triggers at the [scheduling]
# ipv6_vlan cadence (auto-enabled to 60s when there's a network to keep up).
sub _check_ipv6_vlans {
    my ($self) = @_;
    my $nets = $self->_ipv6_vlan_networks;
    for my $name ($self->_ipv6_vlan_order($nets)) {
        my $e = $nets->{$name};
        my $type = lc($e->{type} // 'he6in4');
        # relay has no single interface to test — its attach is idempotent, so
        # just re-run it (re-adds the global address / ::/0 route if they're gone).
        if ($type eq 'relay') { $self->_attach_relay_network($name, $e); next }
        my ($ifname, $want);
        if ($type eq 'vlan') {
            $want = lc($e->{attach} // 'on') !~ /^(off|no|0|false|disabled)$/
                 && defined $e->{id} && $e->{id} =~ /^\d+$/;
            if ($want) {
                my $parent = NetMgr::Vlan::parent_for_subnet();
                $ifname = $parent ? "$parent.$e->{id}" : undef;
            }
        } elsif ($type eq 'he6in4') {
            $want   = lc($e->{mode} // 'off') eq 'on';
            $ifname = $name;
        }
        next unless $want && $ifname;
        my $st = `ip -o link show $ifname 2>/dev/null`;
        next if $st =~ /LOWER_UP/;            # already up
        $self->_log("ipv6_vlan '$name' ($ifname): not up — re-establishing");
        if    ($type eq 'vlan')   { $self->_attach_vlan_network($name, $e) }
        elsif ($type eq 'he6in4') { $self->_he_net_startup_net($name, $e) }
    }
}

# The dmz subnet's network address (e.g. 192.168.15.0), for deriving the
# default control prefix. Returns undef if no dmz subnet is known.
sub _dmz_subnet_net {
    my ($self) = @_;
    require NetMgr::Subnets;
    for my $s (NetMgr::Subnets::all()) {
        return $s->{net}
            if (($s->{zone} // '') eq 'dmz') || (($s->{name} // '') =~ /^dmz$/i);
    }
    return undef;
}

# Bring up the cluster mesh — one persistent outbound TCP connection
# to every other [cluster] member, sharing our IO::Select. No-op when
# the roster is empty (single-node deployment) or just contains self.
sub _start_mesh {
    my ($self) = @_;
    my $cs = $self->{cluster} || {};
    my @others = grep { $_ ne $cs->{self_name} } @{ $cs->{members} // [] };
    if (!@others && !$cs->{auto_spec}) {
        $self->_log("mesh: roster has no peers, mesh disabled");
        return;
    }
    $self->{mesh} = NetMgr::Mesh->new(
        select    => $self->{select},
        self_name => $cs->{self_name},
        members   => $cs->{members},
        log       => sub { $self->_log($_[0]) },
        # State broadcast in every outbound HEARTBEAT — kept tight so
        # peers can score us without a STATUS round-trip. Mirror the
        # CLUSTER_ROLE runtime values when set; else fall back to the
        # static [cluster] config.
        state_fn  => sub {
            my $cr = $self->{cluster_runtime} // {};
            return (
                role     => ($cr->{role}     // $cs->{role}),
                priority => $cs->{priority},
                master   => ($cr->{master_member} // ''),
                schema_v => (eval { $self->{db}->current_schema_version } // 0),
            );
        },
    );
    if ($cs->{auto_spec}) {
        $self->_log("mesh: started in auto-discovery mode ("
                  . _auto_spec_desc($cs->{auto_spec}) . ")");
        # Prime immediately so the first mesh tick has peers to dial.
        $self->_auto_discover;
        $self->{next_auto_discover} = time + 300;    # 5 min cadence
    } else {
        $self->_log("mesh: started with " . scalar(@others) . " peer(s): "
                  . join(',', @others));
    }
}

# Pull a fresh members list from NetMgr::AutoDiscover and reconcile
# Mesh's peer table. Best-effort: errors are logged and the
# previously-discovered list stays in effect.
sub _auto_discover {
    my ($self) = @_;
    my $cs = $self->{cluster} or return;
    my $spec = $cs->{auto_spec} or return;
    return unless $self->{mesh};
    my ($names, $ip_for) = eval {
        NetMgr::AutoDiscover::discover(
            db        => $self->{db},
            spec      => $spec,
            self_name => $cs->{self_name},
            log       => sub { $self->_log($_[0]) },
        );
    };
    if ($@) {
        my $e = $@; chomp $e;
        $self->_log("auto-discover failed: $e");
        return;
    }
    # Pass the name -> address map so the mesh can dial by IP — DNS for the
    # cluster name is unreliable (gateway3 has no PTR for nas3, only for
    # gateway2). The address map comes from peers.host on the same row whose
    # cluster_member named the peer.
    $self->{mesh}->set_members($names || [], $ip_for || {});
}

sub _auto_spec_desc {
    my ($s) = @_;
    my $c = $s->{zone_class};
    my $n = $s->{zone_name};
    return 'auto (no zone filter)' unless defined $c;
    return "auto:$c" . (defined $n ? "/$n" : '');
}

# Parse a manager.listen spec into a list of { host, port } entries.
# 'auto'        → every 192.168.*.* address on this host + 127.0.0.1
# 'a:p, b:p, …' → one per entry; missing port defaults to 7531
# 'a, b, …'     → ditto, port 7531 implicit
# 'host'        → single entry, port 7531
sub _resolve_listen_spec {
    my ($spec, $control_prefix, $exclude) = @_;
    my $default_port = 7531;
    my @out;
    my %seen;   # "host|port" — '|' not ':', since v6 hosts contain ':'
    for my $tok (grep { length } map { s/^\s+|\s+$//gr } split /,/, $spec) {
        if (lc $tok eq 'all' || lc $tok eq 'auto') {
            # 'all' (the default): bind every LAN-facing address on the host —
            # any interface, present or future (a periodic rescan tracks WiFi/USB
            # coming and going). Private/ULA only, so the control port is never
            # exposed on a public WAN by default; carve out interfaces/IPs/CIDRs
            # with [manager] listen_exclude, or list a public address explicitly.
            # 'auto' is the older, narrower alias (192.168.* + control_prefix).
            my @autos = lc $tok eq 'all'
                ? _all_listen_ips($exclude, $control_prefix)
                : _local_192_168_ips();
            push @autos, local_addrs('v6', $control_prefix)
                if lc $tok eq 'auto' && $control_prefix;
            for my $ip (@autos) {
                next if $seen{"$ip|$default_port"}++;
                push @out, { host => $ip, port => $default_port };
            }
            push @out, { host => '127.0.0.1', port => $default_port }
                unless $seen{"127.0.0.1|$default_port"}++;
            next;
        }
        my ($host, $port) = split_hostport($tok);   # bracket-aware ([v6]:port)
        $host = $tok unless defined $host && length $host;
        $port //= $default_port;
        next if $seen{"$host|$port"}++;
        push @out, { host => $host, port => $port };
    }
    return @out;
}

# Enumerate every LAN-facing unicast address on the host for `listen = all`:
# all interfaces, both families, MINUS loopback, link-local, public addresses
# (so we never bind the control port on a WAN), and anything matched by
# listen_exclude (interface names, bare IPs, or CIDRs). Addresses inside the
# control_prefix are always kept even if they fall outside the private ranges.
sub _all_listen_ips {
    my ($exclude, $control_prefix) = @_;
    my @ex = _parse_listen_exclusions($exclude);
    my @ips;
    for my $fam ('-4', '-6') {
        for my $line (`ip -br $fam addr show 2>/dev/null`) {
            chomp $line;
            my ($iface, undef, @addrs) = split ' ', $line;
            next unless defined $iface && $iface ne 'lo';
            next if grep { ($_->{iface} // '') eq $iface } @ex;
            for my $a (@addrs) {
                $a =~ s|/.*||;
                next if $a =~ /^fe80:/i || $a =~ /^169\.254\./;   # link-local
                next if $a =~ /^127\./  || $a eq '::1';           # loopback
                next unless _is_private_addr($a)
                         || ($control_prefix && addr_in_prefix($a, $control_prefix));
                next if grep {
                       ($_->{ip}   && $_->{ip} eq $a)
                    || ($_->{cidr} && addr_in_prefix($a, $_->{cidr}))
                } @ex;
                push @ips, $a;
            }
        }
    }
    return @ips;
}

# A private/ULA address (the only ones `all` binds without an explicit listing).
sub _is_private_addr {
    my ($a) = @_;
    return 1 if $a =~ /^10\./ || $a =~ /^192\.168\./
             || $a =~ /^172\.(1[6-9]|2\d|3[01])\./;          # RFC1918 v4
    return 1 if $a =~ /^f[cd][0-9a-f][0-9a-f]:/i;            # fc00::/7 ULA
    return 0;
}

# Parse listen_exclude into { iface | ip | cidr } tokens. A token with '/' is a
# CIDR; a bare IPv4/IPv6 literal is an address; anything else is an interface.
sub _parse_listen_exclusions {
    my ($spec) = @_;
    my @ex;
    for my $tok (grep { length } map { s/^\s+|\s+$//gr } split /[,\s]+/, ($spec // '')) {
        if    ($tok =~ m{/})                       { push @ex, { cidr  => $tok } }
        elsif ($tok =~ /^[\d.]+$/ || $tok =~ /:/)  { push @ex, { ip    => $tok } }
        else                                       { push @ex, { iface => $tok } }
    }
    return @ex;
}

# Pick the address forked producers should connect to. They run on this
# same host, so prefer 127.0.0.1 if we're listening on it (the 'auto'
# default puts loopback in the list). Otherwise fall back to the first
# bound address.
sub _child_connect_addr {
    my ($self) = @_;
    for my $l (values %{ $self->{listeners} }) {
        return "127.0.0.1:$l->{port}" if $l->{host} eq '127.0.0.1';
    }
    my ($l) = values %{ $self->{listeners} };
    return $l ? "$l->{host}:$l->{port}" : '127.0.0.1:7531';
}

# Enumerate IPv4 addresses on this host that fall under 192.168.0.0/16.
# Skips loopback. Best-effort via the `ip` command (already a hard
# dependency for the daemon's other paths).
sub _local_192_168_ips {
    my @ips;
    for my $line (`ip -br -4 addr show 2>/dev/null`) {
        chomp $line;
        my ($iface, $state, @addrs) = split ' ', $line;
        next unless defined $iface;
        next if $iface eq 'lo';
        for my $a (@addrs) {
            $a =~ s|/.*||;
            push @ips, $a if $a =~ /^192\.168\./;
        }
    }
    return @ips;
}

sub stop  { $_[0]->{stop} = 1 }

sub run {
    my ($self) = @_;
    $self->start_listener unless %{ $self->{listeners} };

    # Every connection that was joined to a chat session before the
    # last restart is gone; clear stale presence so the roster starts
    # empty (re-populated as clients CHAT_JOIN again).
    eval { $self->{db}->clear_chat_presence } if $self->{db};

    local $SIG{INT}  = sub { $self->stop };
    local $SIG{TERM} = sub { $self->stop };
    local $SIG{PIPE} = 'IGNORE';
    # SIGHUP = "rescan interfaces now" — an if-up/down or NetworkManager-dispatcher
    # hook sends it when a link changes. Just set a flag; the rebind happens in the
    # loop below (binding sockets inside a signal handler isn't safe).
    local $SIG{HUP}  = sub { $self->{rescan_requested} = 1 };

    while (!$self->{stop}) {
        my @ready = $self->{select}->can_read(1.0);
        for my $fh (@ready) {
            my $fd = fileno($fh);
            if ($self->{listeners}{$fd}) {
                $self->_accept($self->{listeners}{$fd}{sock});
            } elsif ($self->{mesh} && $self->{mesh}->is_mesh_fd($fd)) {
                $self->{mesh}->handle_readable($fh);
            } else {
                $self->_handle_readable($fh);
            }
        }
        $self->{mesh}->tick                if $self->{mesh};
        $self->_run_election               if $self->{mesh};
        if ($self->{next_auto_discover}
            && time >= $self->{next_auto_discover}) {
            $self->_auto_discover;
            $self->{next_auto_discover} = time + 300;
        }
        if ($self->{rescan_requested}) {
            delete $self->{rescan_requested};
            $self->_recheck_listeners;
        }
        $self->_reap_triggers              if %{ $self->{triggers} };
        $self->_check_periodic_triggers;
        $self->_age_out_offline;
        $self->_purge_old_events;
        $self->_check_dnsmasq_listeners;
    }
    $self->_log("shutting down");
    $self->{mesh}->shutdown if $self->{mesh};
    for my $c (values %{ $self->{clients} }) {
        eval { $c->{sock}->close };
    }
    for my $l (values %{ $self->{listeners} }) {
        eval { $l->{sock}->close };
    }
}

sub _accept {
    my ($self, $listener) = @_;
    my $cli = $listener->accept or return;
    $cli->blocking(0);
    my $peer = sprintf "%s:%d", $cli->peerhost // '?', $cli->peerport // 0;
    my $fd   = fileno($cli);
    $self->{clients}{$fd} = {
        sock     => $cli,
        peer     => $peer,
        buffer   => '',
        kind     => undef,    # 'producer' | 'consumer'
        ident    => undef,    # source=... or consumer=...
        subs     => {},       # id → { table, mode, where_ast }
        forwards => {},       # slot port → { method, target, cookie|pid }
        auth     => undef,    # { key_id, nonce_b64 } once AUTH starts;
                              # { key_id, verified=>1 } once verified
    };
    $self->{select}->add($cli);
    $self->_log("connect $peer fd=$fd");
}

sub _handle_readable {
    my ($self, $fh) = @_;
    my $fd  = fileno($fh);
    # dnsmasq event-socket listeners: handled inline (no client struct).
    for my $key (keys %{ $self->{dnsmasq_listeners} }) {
        my $L = $self->{dnsmasq_listeners}{$key};
        return $self->_handle_dnsmasq_data($key)
            if fileno($L->{sock}) == $fd;
    }
    my $cli = $self->{clients}{$fd} or return;
    my $n   = sysread($fh, my $buf, 8192);
    if (!defined $n) {
        return if $!{EAGAIN} || $!{EWOULDBLOCK};
        $self->_drop_client($fd, "read error: $!");
        return;
    }
    if ($n == 0) {
        $self->_drop_client($fd, 'eof');
        return;
    }
    $cli->{buffer} .= $buf;
    while ($cli->{buffer} =~ s/^([^\n]*)\n//) {
        my $line = $1;
        $self->_handle_line($cli, $line);
    }
}

sub _drop_client {
    my ($self, $fd, $why) = @_;
    my $cli = delete $self->{clients}{$fd} or return;
    # Drop this connection's chat presence and tell roster subscribers.
    # conn_id is the fd, so any rows this connection left behind go now.
    if ($self->{db}) {
        my $gone = eval { $self->{db}->delete_presence_for_conn($fd) } || [];
        for my $row (@$gone) {
            $self->_emit_change(table => 'chat_presence', op => 'delete', row => $row);
        }
    }
    # Tear down any port forwards this connection still owns. Same
    # rationale as for subscriptions, but FORWARDs leave kernel side-
    # effects (iptables rules, socat children) so we have to do it
    # explicitly rather than relying on hash deletion.
    if ($cli->{forwards} && %{ $cli->{forwards} }) {
        for my $slot (keys %{ $cli->{forwards} }) {
            my $f = $cli->{forwards}{$slot};
            eval { $self->_remove_forward($f) };
            $self->_log("warn: tearing down slot=$slot on disconnect failed: $@")
                if $@;
        }
    }
    $self->{select}->remove($cli->{sock});
    eval { $cli->{sock}->close };
    $self->_log("disconnect $cli->{peer} fd=$fd ($why)");
}

sub _send {
    my ($self, $cli, $line) = @_;
    return unless $cli && $cli->{sock};
    my $data = "$line\n";
    # Serialize wide chars to UTF-8 bytes before syswrite. A chat body with
    # non-ASCII (e.g. an em-dash) comes back from the DB as a Perl wide
    # string; syswrite on it not only warns "Wide character" but desyncs the
    # byte-vs-char length/offset arithmetic below and aborts the daemon.
    utf8::encode($data) if utf8::is_utf8($data);
    my $left = length $data;
    my $off  = 0;
    while ($left > 0) {
        my $n = syswrite($cli->{sock}, $data, $left, $off);
        if (!defined $n) {
            if ($!{EAGAIN} || $!{EWOULDBLOCK}) {
                # Send buffer full — happens under a big burst (e.g. a
                # snapshot+stream subscription to every table, esp. when the
                # peer reads slowly because it applies each row to its DB).
                # Do NOT return: that truncates this line mid-write, and the
                # next _send concatenates onto the stump — the peer then sees
                # merged lines (…last_seenROW…) and its parser dies, killing
                # replication. Wait (bounded) for the socket to drain and finish.
                my $wv = ''; vec($wv, fileno($cli->{sock}), 1) = 1;
                my $ready = select(undef, my $w = $wv, undef, 30);
                if (!$ready) {
                    $self->_drop_client(fileno($cli->{sock}), "write stalled");
                    return;
                }
                next;            # retry syswrite from the same offset
            }
            $self->_drop_client(fileno($cli->{sock}), "write error: $!");
            return;
        }
        $left -= $n; $off += $n;
    }
}

sub _handle_line {
    my ($self, $cli, $line) = @_;

    # Intercept FORWARD_TO before parse_line — parse_line croaks on
    # unknown verbs, and this one wraps an inner command we don't want
    # this daemon to parse in its own context. Syntax:
    #   FORWARD_TO peer=NAME <verb> <args ...>
    if ($line =~ /^\s*FORWARD_TO\s+peer=(\S+)\s+(.+)$/i) {
        return $self->_handle_forward_to($cli, $1, $2);
    }

    my $cmd = eval { parse_line($line) };
    if ($@) {
        $self->_send($cli, format_err("parse: $@"));
        $self->_log("err parse from $cli->{peer}: $@");
        return;
    }
    return unless $cmd;

    my $verb = $cmd->{verb};
    if    ($verb eq 'HELLO')     { $self->_handle_hello($cli, $cmd) }
    elsif ($verb eq 'OBSERVE')   { $self->_handle_observe($cli, $cmd) }
    elsif ($verb eq 'GONE')      { $self->_handle_gone($cli, $cmd) }
    elsif ($verb eq 'SUBSCRIBE') { $self->_handle_subscribe($cli, $cmd) }
    elsif ($verb eq 'UNSUB')     { $self->_handle_unsub($cli, $cmd) }
    elsif ($verb eq 'TRIGGER')   { $self->_handle_trigger($cli, $cmd) }
    elsif ($verb eq 'POLL')      { $self->_handle_poll($cli, $cmd) }
    elsif ($verb eq 'BYE')       { $self->_drop_client(fileno($cli->{sock}), 'bye') }
    elsif ($verb eq 'STATUS')    { $self->_handle_status($cli) }
    elsif ($verb eq 'CLUSTER_ROLE') { $self->_handle_cluster_role($cli, $cmd) }
    elsif ($verb eq 'HEARTBEAT') { $self->_handle_heartbeat($cli, $cmd) }
    elsif ($verb eq 'FORWARD')   { $self->_handle_forward($cli, $cmd) }
    elsif ($verb eq 'UNFORWARD') { $self->_handle_unforward($cli, $cmd) }
    elsif ($verb eq 'NAT_MASQUERADE') { $self->_handle_nat_masquerade($cli, $cmd) }
    elsif ($verb eq 'SET_GATEWAY')    { $self->_handle_set_gateway($cli, $cmd) }
    elsif ($verb eq 'AUTH')           { $self->_handle_auth($cli, $cmd) }
    elsif ($verb eq 'AUTH_RESPONSE')  { $self->_handle_auth_response($cli, $cmd) }
    elsif ($verb eq 'CHAT_OPEN')      { $self->_handle_chat_open($cli, $cmd) }
    elsif ($verb eq 'CHAT_SET')       { $self->_handle_chat_set($cli, $cmd) }
    elsif ($verb eq 'CHAT_CLOSE')     { $self->_handle_chat_close($cli, $cmd) }
    elsif ($verb eq 'CHAT_JOIN')      { $self->_handle_chat_join($cli, $cmd) }
    elsif ($verb eq 'CHAT_LEAVE')     { $self->_handle_chat_leave($cli, $cmd) }
    elsif ($verb eq 'CHAT_ALLOW')     { $self->_handle_chat_member_op($cli, $cmd, 'allow') }
    elsif ($verb eq 'CHAT_DENY')      { $self->_handle_chat_member_op($cli, $cmd, 'deny') }
    elsif ($verb eq 'CHAT_APPROVE')   { $self->_handle_chat_member_op($cli, $cmd, 'approve') }
    elsif ($verb eq 'CHAT_REJECT')    { $self->_handle_chat_member_op($cli, $cmd, 'reject') }
    elsif ($verb eq 'CHAT_PUT')       { $self->_handle_chat_put($cli, $cmd) }
    elsif ($verb eq 'CHAT_GET')       { $self->_handle_chat_get($cli, $cmd) }
    elsif ($verb eq 'CHAT_LS')        { $self->_handle_chat_ls($cli, $cmd) }
    elsif ($verb eq 'CHAT_RM')        { $self->_handle_chat_rm($cli, $cmd) }
    elsif ($verb eq 'CHAT_KEYS')      { $self->_handle_chat_keys($cli, $cmd) }
    elsif ($verb eq 'CHAT_DELETE')    { $self->_handle_chat_delete($cli, $cmd) }
    else {
        $self->_send($cli, format_err("verb $verb not handled"));
    }
}

sub _handle_status {
    my ($self, $cli) = @_;
    my @listeners = map { "$_->{host}:$_->{port}" } values %{ $self->{listeners} };
    my ($producers, $consumers, $unknown) = (0, 0, 0);
    for my $c (values %{ $self->{clients} }) {
        my $k = $c->{kind} // '';
        if    ($k eq 'producer') { $producers++ }
        elsif ($k eq 'consumer') { $consumers++ }
        else                     { $unknown++ }
    }
    my $schema_v = eval { $self->{db}->current_schema_version } // 0;
    my $cs = $self->{cluster} // {};
    # Runtime role override pushed by net-mgr-relay's election. When
    # set, it wins over the static [cluster] role in the config — that
    # static value is the *eligibility* declaration (auto/master/
    # follower/excluded), this is what was actually elected.
    my $cr = $self->{cluster_runtime} // {};
    my $live_role = $cr->{role} // $cs->{role};
    my $internet_facing = defined $cs->{internet_facing}
                        ? ($cs->{internet_facing} ? 1 : 0)
                        : _detect_internet_facing();
    # Reachable count: self is always reachable + however many
    # cluster mesh peers have a live connection or recent heartbeat.
    # Falls back to 1 when no mesh (single-node deployment).
    my $roster_n = scalar @{ $cs->{members} // [] };
    my $mesh_reach = $self->{mesh} ? $self->{mesh}->reachable : 0;
    my $reachable = 1 + $mesh_reach;
    my $quorum_ok = ($roster_n <= 1) ? 1
                                     : ($reachable >= int($roster_n / 2) + 1);
    my $mesh_summary = $self->{mesh} ? $self->{mesh}->summary : '';
    $self->_send($cli, format_ok(
        version            => $self->{version} // 'unknown',
        started_at         => $self->{started_at},
        now                => time(),
        listeners          => join(',', sort @listeners),
        clients            => scalar(keys %{ $self->{clients} }),
        producers          => $producers,
        consumers          => $consumers,
        unknown            => $unknown,
        triggers_pending   => scalar(keys %{ $self->{triggers} }),
        schema_version     => $schema_v,
        cluster_member     => $cs->{self_name},
        cluster_name       => $cs->{name}   // '',   # cluster identity (defaults to domain)
        cluster_domain     => $cs->{domain} // '',
        cluster_role       => $live_role,
        cluster_role_config => $cs->{role},
        cluster_role_reason => $cr->{reason} // '',
        cluster_master     => $cr->{master_member} // '',
        cluster_master_addr=> ($cr->{master_member} && $self->{mesh})
                              ? $self->{mesh}->address_for($cr->{master_member})
                              : '',
        cluster_role_since => $cr->{since}         // 0,
        cluster_priority   => $cs->{priority},
        cluster_prefer_lan => $cs->{prefer_lan},
        cluster_internet_facing => $internet_facing,
        # Static config roster (empty in auto mode); see cluster_mesh
        # for the live mesh roster discovered at runtime.
        cluster_members    => join(',', @{ $cs->{members} // [] }),
        # Auto-discovery directive when [cluster] members is auto:…;
        # empty when the operator passed a static comma list.
        cluster_auto_spec  => $cs->{auto_spec} ? _auto_spec_desc($cs->{auto_spec}) : '',
        # Whether THIS daemon's local peer_caps table is gating
        # eligibility (and how many entries it has) — the most
        # frequent reason role stays 'auto' in a healthy mesh.
        cluster_peer_caps_active =>
            scalar(keys %{ $cs->{peer_caps} // {} }) ? 1 : 0,
        cluster_is_member  => $cs->{is_member},
        # Self-declared (advisory; consumers may verify against
        # their own peer_caps table before trusting it).
        cluster_capabilities => join(',', @{ $cs->{capabilities} // [] }),
        # Count of entries in this daemon's local /etc/net-mgr/peers
        # table — operators can spot-check that peers agree on roster
        # size and authority spread.
        cluster_peer_auth_count => scalar(keys %{ $cs->{peer_caps} // {} }),
        reachable_members  => $reachable,
        quorum_ok          => $quorum_ok,
        cluster_mesh       => $mesh_summary,
    ));
}

# Re-evaluate who should be master. Called every main-loop iteration
# (cheap: a small in-memory sort + a hash compare). Updates
# $self->{cluster_runtime} whenever the decision changes, and logs.
# This makes the daemon's own election authoritative — the older
# 60s-tick election in net-mgr-relay is now redundant (it still runs
# and pushes CLUSTER_ROLE, but its value gets overwritten almost
# immediately by the next election here).
sub _run_election {
    my ($self) = @_;
    my $cs = $self->{cluster} // {};
    # Eligible to elect when we have either a static roster OR an
    # auto-discovery directive in effect. Without that, this is a
    # single-node deploy with no cluster intent — leave role alone.
    return unless @{ $cs->{members} // [] } || $cs->{auto_spec};

    # Config-driven authoritative override: `[cluster] master = NAME` skips the
    # election entirely. If NAME is us, claim mastership; otherwise follow it.
    # This is the escape hatch for the chicken-and-egg case (a fresh follower
    # whose mesh HBs haven't started flowing yet would self-elect because
    # peers can't vote). Per the design intent: config files are for
    # OVERRIDES — election is the default; this is the override.
    if (my $forced = $cs->{master}) {
        my $self_name = $cs->{self_name} // '';
        my $role = ($forced eq $self_name) ? 'master' : 'follower';
        my $cur = $self->{cluster_runtime} // {};
        my $cur_key = ($cur->{role} // '') . '|' . ($cur->{master_member} // '');
        my $new_key = "$role|$forced";
        return if $cur_key eq $new_key;
        $self->{cluster_runtime} = {
            role          => $role,
            master_member => $forced,
            since         => time(),
            reason        => "config: master=$forced",
        };
        $self->_log("override: config master=$forced → role=$role");
        return;
    }

    # Decide with the configured role AS-IS. A 'follower' is NEVER an election
    # candidate: it follows the elected master, or waits headless if none is
    # reachable yet — it must not self-promote. (This used to coerce a
    # config-follower to 'auto' so it could re-promote if the master vanished.
    # But with auto-discover/follow as the DEFAULT role, that made every node
    # self-elect master the moment it booted isolated: a fresh follower with an
    # empty mesh wins its own election, then advertises master and the real
    # master defers to it — a split brain. For failover, configure role=auto,
    # not follower.)
    my $self_role_for_decide = $cs->{role};
    my $decision = NetMgr::Election::decide(
        self_name  => $cs->{self_name},
        self_state => {
            role            => $self_role_for_decide,
            priority        => $cs->{priority},
            prefer_lan      => $cs->{prefer_lan},
            internet_facing => defined $cs->{internet_facing}
                             ? $cs->{internet_facing}
                             : _detect_internet_facing(),
        },
        mesh_snap => $self->{mesh}->snapshot,
        peer_caps => $cs->{peer_caps},
        # In auto-discovery mode there is no known "expected
        # cluster size" — we only know what's reachable right now.
        # Quorum's job is split-brain detection ("I can see N of
        # M, am I isolated?"), which is meaningless without M.
        # Skip the roster_n arg so decide() defaults to reachable
        # count and quorum trivially passes. Static-list mode
        # still uses the configured size, where split-brain is
        # detectable.
        ($cs->{auto_spec}
            ? ()
            : (roster_n => scalar @{ $cs->{members} })),
    );

    my $cur = $self->{cluster_runtime} // {};
    my $cur_key = ($cur->{role}          // '') . '|'
                . ($cur->{master_member} // '');
    my $new_key = $decision->{role} . '|' . $decision->{master_member};
    return if $cur_key eq $new_key;
    $self->{cluster_runtime} = {
        role          => $decision->{role},
        master_member => $decision->{master_member},
        since         => time(),
        reason        => $decision->{reason},
    };
    $self->_log("election: $decision->{reason} → role=$decision->{role} "
              . "master=" . ($decision->{master_member} || '-')
              . " quorum=$decision->{reachable}/$decision->{roster_n}");
}

# FORWARD_TO peer=NAME <inner verb...>
# — proxy the inner command to NAME's daemon, pump replies back
# verbatim. Single-hop only (the inner request goes out tagged with
# hop=1, and the destination's HELLO handler records that so it
# refuses to FORWARD_TO again).
#
# Synchronous: blocks the daemon's run loop until the inner exchange
# completes (or the per-line timeout fires). Acceptable v1 for
# single-reply verbs and snapshot subscriptions on a LAN. Streaming
# subscriptions through forwarding aren't supported — the destination
# would keep sending ROW lines indefinitely and we'd never know to
# stop reading.
sub _handle_forward_to {
    my ($self, $cli, $peer, $inner) = @_;
    if (($cli->{hop} // 0) > 0) {
        return $self->_send($cli,
            format_err("FORWARD_TO: nested forwarding rejected (hop=$cli->{hop})"));
    }
    # Pick the destination address. Prefer a live mesh socket's
    # peerhost — that's a peer we've already proved we can reach.
    # Fall back to "name:7531" and let the kernel resolve.
    my $addr = '';
    $addr = $self->{mesh}->address_for($peer) if $self->{mesh};
    $addr = "$peer:7531" unless length $addr;
    my ($host, $port) = split /:/, $addr, 2;
    $port = ($port && $port =~ /^\d+$/) ? $port + 0 : 7531;

    my $sock = IO::Socket::INET->new(
        PeerAddr => $host,
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5,
    );
    if (!$sock) {
        return $self->_send($cli,
            format_err("FORWARD_TO: connect $addr failed: $!"));
    }

    my $orig_ident = $cli->{ident} // 'anon';
    eval {
        syswrite($sock, "HELLO consumer=fwd:$orig_ident hop=1\n");
        my $hello_reply = _read_one_line($sock, 5);
        die "HELLO failed: " . ($hello_reply // 'no reply') . "\n"
            unless $hello_reply && $hello_reply =~ /^OK\b/;

        syswrite($sock, "$inner\n");

        # Pump reply lines. End on OK or ERR at line start — single-
        # reply verbs (STATUS, OBSERVE, POLL, TRIGGER) reply with one
        # such line; snapshot subscriptions emit ROW…ROW…EOS then
        # an OK ack we use as the stop signal.
        while (defined(my $line = _read_one_line($sock, 60))) {
            $self->_send($cli, $line);
            last if $line =~ /^\s*(OK|ERR)\b/;
        }
    };
    if ($@) {
        my $err = $@; chomp $err;
        $self->_send($cli, format_err("FORWARD_TO: $err"));
    }
    eval { close $sock };
    return;
}

# Small synchronous line reader for FORWARD_TO. Returns the next \n-
# terminated line (without the newline) or undef on timeout/eof.
# Uses a per-socket buffer attached to the file handle via Perl's
# fileno-keyed hash so a multi-line reply isn't chopped between
# reads.
my %_fwd_bufs;
sub _read_one_line {
    my ($sock, $timeout) = @_;
    my $fd = fileno($sock);
    $_fwd_bufs{$fd} //= '';
    while (1) {
        if ($_fwd_bufs{$fd} =~ s/^([^\n]*)\n//) {
            my $line = $1;
            return $line;
        }
        my $vec = ''; vec($vec, $fd, 1) = 1;
        my $rv = select(my $r = $vec, undef, undef, $timeout);
        if ($rv <= 0) {
            delete $_fwd_bufs{$fd};
            return undef;
        }
        my $n = sysread($sock, my $chunk, 4096);
        if (!defined $n || $n == 0) {
            delete $_fwd_bufs{$fd};
            return undef;
        }
        $_fwd_bufs{$fd} .= $chunk;
    }
}

# Inbound HEARTBEAT from a peer over its outbound mesh socket — the
# *receiving* daemon's side. We trust the `member=` field as the
# sender's self-identification (cluster member names are how the
# roster is keyed; spoofing requires presence on the bound iface,
# which is a separate threat model). Updates the local mesh state
# table so STATUS can surface "what does X think they are".
#
# No OK reply — heartbeats are fire-and-forget so neither side
# blocks on the other's processing latency. The mesh's own retry
# logic handles drops.
sub _handle_heartbeat {
    my ($self, $cli, $cmd) = @_;
    return unless $self->{mesh};
    my $kv = $cmd->{kv} || {};
    my $member = $kv->{member};
    return unless defined $member && length $member;
    $self->{mesh}->record($member, $kv);
}

# Loopback-only control verb. net-mgr-relay calls this after its
# election picks a winner so STATUS starts reporting cluster_role
# accurately to the rest of the cluster.
#
#   CLUSTER_ROLE role=master|follower|auto member=NAME [master=NAME]
#
# 'member' is the role-bearer's own member name (sanity-checked
# against cluster.self_name). 'master' is the elected master's name
# — required on role=follower, ignored on role=master (the role
# bearer is the master), cleared on role=auto.
#
# Restricted to loopback peers; the relay always runs on the same
# host as the daemon. Any other peer trying to assert cluster role
# is ignored.
sub _handle_cluster_role {
    my ($self, $cli, $cmd) = @_;
    unless (_peer_is_loopback($cli)) {
        return $self->_send($cli,
            format_err("CLUSTER_ROLE restricted to loopback peers"));
    }
    my $kv = $cmd->{kv} || {};
    my $role = lc($kv->{role} // '');
    unless ($role =~ /^(master|follower|auto)$/) {
        return $self->_send($cli,
            format_err("CLUSTER_ROLE: role must be master|follower|auto"));
    }
    my $cs = $self->{cluster} // {};
    if (defined $kv->{member} && length $kv->{member}
        && defined $cs->{self_name} && $kv->{member} ne $cs->{self_name}) {
        return $self->_send($cli, format_err(
            "CLUSTER_ROLE: member='$kv->{member}' != self_name='$cs->{self_name}'"));
    }
    my $master = $kv->{master};
    if ($role eq 'master') {
        $master = $cs->{self_name};
    } elsif ($role eq 'auto') {
        $master = '';
    } else {
        return $self->_send($cli,
            format_err("CLUSTER_ROLE role=follower needs master=NAME"))
            unless defined $master && length $master;
    }
    $self->{cluster_runtime} = {
        role          => $role,
        master_member => $master,
        since         => time(),
    };
    $self->_log("cluster_role=$role"
              . ($master ? " master=$master" : '')
              . " (set by $cli->{peer})");
    return $self->_send($cli, format_ok(
        role   => $role,
        master => ($master // ''),
        since  => $self->{cluster_runtime}{since},
    ));
}

# Heuristic: this host has an "internet-facing" default route if any
# default route's egress iface name looks like a USB/PCIe NIC the
# operator typically wires to a modem (enxXXXX, enpXsY, eth-USB-ish).
# Returns 1 if internet-facing detected, 0 if not. Operator can
# override via [cluster] internet_facing = 0|1.
sub _detect_internet_facing {
    open my $fh, '-|', 'ip', '-o', '-4', 'route', 'show', 'default'
        or return 0;
    my $internet = 0;
    while (my $line = <$fh>) {
        # default via X.X.X.X dev IFACE ...
        if ($line =~ /\bdev\s+(\S+)/) {
            my $iface = $1;
            # Common patterns for USB-ethernet / NIC-on-PCIe / generic
            # ethernet that operators use to connect to a modem.
            $internet = 1 if $iface =~ /^(enx|enp\d+s|eth\d|wlp)/;
        }
    }
    close $fh;
    return $internet;
}

sub _handle_hello {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    if ($kv->{source}) {
        $cli->{kind} = 'producer'; $cli->{ident} = $kv->{source};
    } elsif ($kv->{consumer}) {
        $cli->{kind} = 'consumer'; $cli->{ident} = $kv->{consumer};
    } else {
        return $self->_send($cli, format_err("HELLO needs source= or consumer="));
    }
    # hop=N marks a forwarded request — block transitive FORWARD_TO.
    # Mesh is single-hop by design.
    $cli->{hop} = ($kv->{hop} // 0) + 0;
    $self->_log("hello $cli->{peer} $cli->{kind}=$cli->{ident}"
              . ($cli->{hop} ? " hop=$cli->{hop}" : ''));
    $self->_send($cli, format_ok());
}

# ---- SUBSCRIBE / UNSUB ------------------------------------------------

sub _handle_subscribe {
    my ($self, $cli, $cmd) = @_;
    my $sub   = $cmd->{sub};
    my $mode  = $cmd->{mode};
    my $table = $cmd->{table};
    my $where = $cmd->{where};
    return $self->_send($cli, format_err("unknown table '$table'"))
        unless $SUBSCRIBABLE{$table} || $SUBSCRIBABLE_AUTH{$table};
    if ($SUBSCRIBABLE_AUTH{$table} && !$self->_auth_is_full($cli)) {
        return $self->_send($cli,
            format_err("table '$table' requires full-scope AUTH (or loopback peer)"));
    }

    my $where_ast = eval { NetMgr::Where::parse($where) };
    if ($@) {
        my $err = $@; chomp $err;
        return $self->_send($cli, format_err("WHERE: $err"));
    }

    $cli->{subs}{$sub} = {
        table     => $table,
        mode      => $mode,
        where_ast => $where_ast,
    };
    $self->_log("subscribe $cli->{ident} sub=$sub mode=$mode FROM $table"
              . (defined $where ? " WHERE $where" : ''));

    # Snapshot phase. For tables with a `ts` column (events) we look
    # for a `ts > ago(N)` lower bound in the WHERE clause and push it
    # to SQL, so a windowed snapshot doesn't have to load the entire
    # ping history into Perl just to filter it out.
    if ($mode eq 'snapshot' || $mode eq 'snapshot+stream') {
        my %qopts;
        if (my $bound = _extract_ts_lower_bound($where_ast)) {
            $qopts{since_epoch} = $bound;
        }
        # Guard the DB call so a bug in query_table (missed allowlist
        # entry, etc.) doesn't unwind out of the main loop and kill
        # the daemon. Report as an ERR and drop the subscription;
        # next connection isn't affected.
        my $rows = eval { $self->{db}->query_table($table, %qopts) };
        if ($@) {
            my $e = $@; chomp $e;
            $self->_log("err snapshot $table from $cli->{ident}: $e");
            delete $cli->{subs}{$sub};
            return $self->_send($cli, format_err("snapshot $table: $e"));
        }
        for my $row (@$rows) {
            next if $where_ast && !eval_ast($where_ast, _row_for_match($row));
            $self->_send($cli, format_row($sub, $table, 'snapshot', %$row));
        }
        $self->_send($cli, format_eos($sub));
    }

    # If snapshot-only, drop the subscription so we don't stream.
    if ($mode eq 'snapshot') {
        delete $cli->{subs}{$sub};
    }

    $self->_send($cli, format_ok(sub => $sub));
}

sub _handle_unsub {
    my ($self, $cli, $cmd) = @_;
    my $sub = $cmd->{sub};
    if (delete $cli->{subs}{$sub}) {
        $self->_log("unsub $cli->{ident} sub=$sub");
        $self->_send($cli, format_ok(sub => $sub));
    } else {
        $self->_send($cli, format_err("no such subscription sub=$sub"));
    }
}

# ---- FORWARD / UNFORWARD --------------------------------------------
#
# Wires a local-loopback port (the laptop end of an ssh -L tunnel)
# to a LAN target by installing an iptables OUTPUT-chain DNAT rule
# (or a socat process if iptables is unavailable). Forwards live for
# the duration of the connection that requested them; on disconnect,
# every still-installed forward is torn down.
#
# Authorisation: by default, only loopback peers (127.0.0.1) may
# FORWARD. The laptop usually reaches the daemon by tunnelling an
# extra -L through ssh terminating at the daemon host, so its source
# from sshd's POV is 127.0.0.1.
#
# When the daemon host is NOT the ssh entry-point — e.g., the laptop
# logs into zmc1 but the daemon is on nas3, with the laptop's tunnel
# `-L 7531:nas3.grfx.com:7531` — connections from the daemon's POV
# come from zmc1's LAN IP, not loopback. Set
#   [forward]
#   allow_peers = 192.168.15.0/24, 192.168.223.0/24
# in the daemon config to permit those peers. Loopback is always
# allowed regardless of config.

sub _handle_forward {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};

    return $self->_send($cli, format_err("FORWARD requires HELLO first"))
        unless defined $cli->{kind};
    return $self->_send($cli,
        format_err("FORWARD peer not permitted (need AUTH or loopback; "
                 . "see [forward] allow_peers for IP-based legacy access)"))
        unless $self->_peer_may_mutate($cli);

    my $slot = $kv->{slot};
    my $tgt  = $kv->{target};
    return $self->_send($cli, format_err("FORWARD requires slot=PORT"))
        unless defined $slot && $slot =~ /^\d+$/ && $slot >= 1 && $slot <= 65535;
    return $self->_send($cli, format_err("FORWARD requires target=IP:PORT"))
        unless defined $tgt && $tgt =~ /^(\d+\.\d+\.\d+\.\d+):(\d+)$/;
    my ($tip, $tport) = ($1, $2);
    return $self->_send($cli, format_err("bad target port $tport"))
        unless $tport >= 1 && $tport <= 65535;

    # Replace any existing forward on the same slot for this connection.
    if (my $old = delete $cli->{forwards}{$slot}) {
        eval { $self->_remove_forward($old) };
        $self->_log("warn: replacing slot=$slot remove-old failed: $@") if $@;
    }

    my $f = eval {
        $self->_install_forward(
            slot   => $slot + 0,
            target => "$tip:$tport",
            owner  => $cli->{ident} // 'anon',
            fd     => fileno($cli->{sock}),
        );
    };
    if ($@ || !$f) {
        my $msg = $@ // 'install failed';
        $msg =~ s/\s+at\s+\S+\s+line\s+\d+\.?$//;
        return $self->_send($cli, format_err("FORWARD failed: $msg"));
    }

    $cli->{forwards}{$slot} = $f;
    $self->_log("forward $cli->{ident} slot=$slot → $tip:$tport via $f->{method}");
    $self->_send($cli, format_ok(slot => $slot, method => $f->{method}));
}

sub _handle_unforward {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my $slot = $kv->{slot};
    return $self->_send($cli, format_err("UNFORWARD requires slot=PORT"))
        unless defined $slot && $slot =~ /^\d+$/;
    my $f = delete $cli->{forwards}{$slot}
        or return $self->_send($cli, format_err("no such forward slot=$slot"));
    eval { $self->_remove_forward($f) };
    if ($@) {
        my $msg = $@; $msg =~ s/\s+at\s+\S+\s+line\s+\d+\.?$//;
        return $self->_send($cli, format_err("UNFORWARD: $msg"));
    }
    $self->_log("unforward $cli->{ident} slot=$slot");
    $self->_send($cli, format_ok(slot => $slot));
}

# ---- NAT_MASQUERADE -------------------------------------------------
#
# Install or remove an iptables MASQUERADE rule on the daemon host's
# nat POSTROUTING chain, scoped to the named egress interface. Used
# by net-set to make a candidate gateway routing-ready before we flip
# clients onto it.
#
#   NAT_MASQUERADE iface=enp4s0 state=on  [boot=1]
#   NAT_MASQUERADE iface=enp4s0 state=off
#
# Idempotent: state=on with the rule already present is a no-op
# (returns OK). state=off with no marked rule for that iface is also
# a no-op. boot=1 also writes through to /etc/iptables/rules.v4 (or
# netfilter-persistent save) so the rule survives reboot; OK reply
# notes which mechanism was used.
#
# Authorisation: same as FORWARD (loopback always allowed; off-host
# peers gated by [forward] allow_peers). MASQUERADE on an outbound
# interface doesn't expose anything inbound, so persistence is the
# default (no per-connection cleanup).

sub _handle_nat_masquerade {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};

    return $self->_send($cli, format_err("NAT_MASQUERADE requires HELLO first"))
        unless defined $cli->{kind};
    return $self->_send($cli,
        format_err("NAT_MASQUERADE peer not permitted (need AUTH or loopback; "
                 . "see [forward] allow_peers for IP-based legacy access)"))
        unless $self->_peer_may_mutate($cli);

    my $iface = $kv->{iface};
    my $state = lc($kv->{state} // '');
    my $boot  = $kv->{boot} ? 1 : 0;
    return $self->_send($cli, format_err("NAT_MASQUERADE requires iface=NAME"))
        unless defined $iface && $iface =~ /^[A-Za-z0-9._-]+$/;
    return $self->_send($cli, format_err("NAT_MASQUERADE state must be 'on' or 'off'"))
        unless $state eq 'on' || $state eq 'off';

    return $self->_send($cli, format_err("iptables not available on this host"))
        unless _have_cmd('iptables');

    my $cookie = "net-mgr:masq:$iface";
    my $present = _masq_rule_present($iface, $cookie);

    my $boot_msg;
    if ($state eq 'on') {
        unless ($present) {
            my @cmd = ('iptables', '-t', 'nat', '-A', 'POSTROUTING',
                       '-o', $iface,
                       '-m', 'comment', '--comment', $cookie,
                       '-j', 'MASQUERADE');
            my $rc = system(@cmd);
            if ($rc != 0) {
                return $self->_send($cli,
                    format_err("iptables install rc=" . ($rc >> 8)));
            }
            $self->_log("nat_masquerade $cli->{ident} iface=$iface ON");
        }
        $boot_msg = $self->_persist_iptables if $boot;
    } else {
        # state=off — remove every rule with our marker for this iface.
        my $removed = 0;
        while (_masq_rule_present($iface, $cookie)) {
            my @cmd = ('iptables', '-t', 'nat', '-D', 'POSTROUTING',
                       '-o', $iface,
                       '-m', 'comment', '--comment', $cookie,
                       '-j', 'MASQUERADE');
            my $rc = system(@cmd);
            last if $rc != 0;
            $removed++;
        }
        $self->_log("nat_masquerade $cli->{ident} iface=$iface OFF removed=$removed")
            if $removed;
        $boot_msg = $self->_persist_iptables if $boot;
    }

    my %ok = (iface => $iface, state => $state);
    $ok{boot} = $boot_msg if defined $boot_msg;
    $self->_send($cli, format_ok(%ok));
}

# Returns 1 if a POSTROUTING rule with our marker for $iface exists.
sub _masq_rule_present {
    my ($iface, $cookie) = @_;
    open my $fh, '-|', 'iptables', '-t', 'nat', '-S', 'POSTROUTING'
        or return 0;
    my $hit = 0;
    while (my $line = <$fh>) {
        if ($line =~ /-o \Q$iface\E\b/
         && $line =~ /\Q$cookie\E/
         && $line =~ /-j MASQUERADE/) {
            $hit = 1; last;
        }
    }
    close $fh;
    return $hit;
}

# Try the common Debian/Ubuntu persistence mechanisms in order.
# Returns a short string describing what was used, suitable for the
# OK reply's boot=... field.
sub _persist_iptables {
    my ($self) = @_;
    if (_have_cmd('netfilter-persistent')) {
        my $rc = system('netfilter-persistent', 'save');
        return $rc == 0 ? 'netfilter-persistent'
                        : 'netfilter-persistent-failed';
    }
    if (-d '/etc/iptables' && _have_cmd('iptables-save')) {
        my $tmp = '/etc/iptables/rules.v4.tmp';
        my $rc  = system("iptables-save > $tmp && mv $tmp /etc/iptables/rules.v4");
        return $rc == 0 ? 'iptables-save->/etc/iptables/rules.v4'
                        : 'iptables-save-failed';
    }
    return 'no-mechanism';
}

# ---- SET_GATEWAY ----------------------------------------------------
#
# Install (or remove) a low-metric default route on the daemon host.
# The strategy is to leave whatever default route DHCP gave us in
# place and add a competing one at metric=1; the kernel always picks
# the lowest-metric default, so traffic switches to ours immediately.
# To revert, remove the metric=1 entry — DHCP's default takes back
# over with no need to touch dhclient/networkd state.
#
#   SET_GATEWAY action=set via=IP [dev=NAME] [metric=1]
#   SET_GATEWAY action=clear         [metric=1]
#
# Idempotent. action=set replaces any prior route at the same metric
# (we own that metric for this purpose). Authorisation is the same
# as FORWARD: loopback always allowed; off-host gated by
# [forward] allow_peers.

sub _handle_set_gateway {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};

    return $self->_send($cli, format_err("SET_GATEWAY requires HELLO first"))
        unless defined $cli->{kind};
    return $self->_send($cli,
        format_err("SET_GATEWAY peer not permitted (need AUTH or loopback; "
                 . "see [forward] allow_peers for IP-based legacy access)"))
        unless $self->_peer_may_mutate($cli);

    return $self->_send($cli, format_err("ip(8) not available on this host"))
        unless _have_cmd('ip');

    my $action = lc($kv->{action} // 'set');
    my $metric = $kv->{metric} // 1;
    return $self->_send($cli, format_err("metric must be 0..4294967295"))
        unless $metric =~ /^\d+$/ && $metric <= 4294967295;

    if ($action eq 'clear') {
        # Remove every default route at this metric (typically just one).
        # Loop because successive `ip route del` may match siblings.
        my $removed = 0;
        for (1..8) {
            my $rc = system('ip', 'route', 'del', 'default',
                            'metric', $metric);
            last if $rc != 0;       # nothing left to delete
            $removed++;
        }
        $self->_log("set_gateway $cli->{ident} CLEAR metric=$metric removed=$removed");
        return $self->_send($cli, format_ok(action => 'clear',
                                            metric => $metric,
                                            removed => $removed));
    }

    if ($action ne 'set') {
        return $self->_send($cli,
            format_err("SET_GATEWAY action must be 'set' or 'clear'"));
    }

    my $via = $kv->{via};
    return $self->_send($cli, format_err("SET_GATEWAY action=set requires via=IP"))
        unless defined $via && $via =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
    my $dev = $kv->{dev};
    return $self->_send($cli, format_err("dev must be A-Za-z0-9._-"))
        if defined $dev && $dev !~ /^[A-Za-z0-9._-]+$/;

    # Replace any existing route we own at this metric (idempotent).
    system('ip', 'route', 'del', 'default', 'metric', $metric);   # may fail; OK

    my @cmd = ('ip', 'route', 'add', 'default', 'via', $via,
               'metric', $metric);
    push @cmd, 'dev', $dev if defined $dev;
    my $rc = system(@cmd);
    if ($rc != 0) {
        return $self->_send($cli,
            format_err("ip route add rc=" . ($rc >> 8)));
    }
    $self->_log("set_gateway $cli->{ident} SET via=$via dev="
              . ($dev // 'auto') . " metric=$metric");
    $self->_send($cli, format_ok(
        action => 'set', via => $via,
        dev    => ($dev // 'auto'),
        metric => $metric,
    ));
}

# ---- AUTH / AUTH_RESPONSE -------------------------------------------
#
# SSH-key client authentication via OpenSSH's SSHSIG scheme. See
# NetMgr::Auth for the verification mechanics. Workflow:
#
#   client → AUTH key-id=ID
#   server → READY nonce=base64
#   client → AUTH_RESPONSE sig=base64(armored sshsig)
#   server → OK key-id=ID  (or ERR ...)
#
# After OK, $cli->{auth} = { key_id => ID, verified => 1 } and
# privileged verbs (FORWARD, NAT_MASQUERADE, SET_GATEWAY) accept the
# connection regardless of source IP. Without auth, the legacy
# loopback-or-allow_peers IP check still applies.
#
# The nonce is per-connection and one-shot — once consumed by an
# AUTH_RESPONSE (success or failure), it's cleared. The client must
# AUTH again to retry.

sub _handle_auth {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my $key_id = $kv->{key_id};
    return $self->_send($cli, format_err("AUTH requires key_id="))
        unless defined $key_id && length $key_id;
    return $self->_send($cli, format_err("AUTH requires HELLO first"))
        unless defined $cli->{kind};
    my $nonce = NetMgr::Auth::fresh_nonce();
    $cli->{auth} = { key_id => $key_id, nonce => $nonce, verified => 0 };
    $self->_send($cli, format_ready(nonce => $nonce, key_id => $key_id));
}

sub _handle_auth_response {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my $sig = $kv->{sig};
    my $auth = $cli->{auth};
    unless (defined $auth && defined $auth->{nonce} && !$auth->{verified}) {
        return $self->_send($cli,
            format_err("AUTH_RESPONSE without prior AUTH"));
    }
    return $self->_send($cli, format_err("AUTH_RESPONSE requires sig="))
        unless defined $sig && length $sig;

    # Tier 1: the full allowlist (allowed_signers + authorized_keys) grants
    # scope='full' — mesh mutation + chat + auth-gated reads. Tier 2: the
    # chat-only allowlist (allowed_chat) grants scope='chat'. Tier 3: the
    # updater allowlist (allowed_updaters) grants scope='update' (self_update
    # only). verify() is stateless w.r.t. the nonce, so trying each with the
    # same nonce is safe.
    my ($ok, $err) = NetMgr::Auth::verify(
        $self->{auth_state}, $auth->{key_id}, $auth->{nonce}, $sig);
    my $scope = 'full';
    if (!$ok) {
        my ($cok, $cerr) = NetMgr::Auth::verify(
            $self->{chat_auth_state}, $auth->{key_id}, $auth->{nonce}, $sig);
        if ($cok) { $ok = 1; $scope = 'chat'; }
        else      { $err = $cerr // $err; }
    }
    if (!$ok) {
        my ($uok, $uerr) = NetMgr::Auth::verify(
            $self->{update_auth_state}, $auth->{key_id}, $auth->{nonce}, $sig);
        if ($uok) { $ok = 1; $scope = 'update'; }
        else      { $err = $uerr // $err; }
    }
    if (!$ok) {
        my ($iok, $ierr) = NetMgr::Auth::verify(
            $self->{internet_auth_state}, $auth->{key_id}, $auth->{nonce}, $sig);
        if ($iok) { $ok = 1; $scope = 'internet'; }
        else      { $err = $ierr // $err; }
    }
    if (!$ok) {
        my ($dok, $derr) = NetMgr::Auth::verify(
            $self->{debug_auth_state}, $auth->{key_id}, $auth->{nonce}, $sig);
        if ($dok) { $ok = 1; $scope = 'debug'; }
        else      { $err = $derr // $err; }
    }
    # Tier 6 — chat-key: keys persisted in chat_authorized_keys from prior
    # see-and-request approvals. The DB is the source of truth here (no static
    # /etc/net-mgr/allowed_* file), so we build a temp signers file from the
    # rows whose pubkey is non-null and verify against it. On success the
    # connection is scope='chat-key', flagged with the chat sessions this key
    # is authorized for; _chat_identity then treats the connection as authed
    # (returns the fingerprint as principal), and _handle_chat_join's
    # chat_authorized_keys lookup auto-admits.
    my $chat_sessions;
    if (!$ok) {
        my ($ckok, $ckerr, $sessions)
            = $self->_chatkey_verify($auth->{key_id}, $auth->{nonce}, $sig);
        if ($ckok) { $ok = 1; $scope = 'chat-key'; $chat_sessions = $sessions }
        else       { $err = $ckerr // $err; }
    }
    # Always invalidate the nonce — one-shot regardless of outcome.
    delete $auth->{nonce};
    if (!$ok) {
        $cli->{auth} = undef;
        $self->_log("auth FAIL $cli->{peer} key-id=$auth->{key_id}: $err");
        return $self->_send($cli, format_err("AUTH failed: $err"));
    }
    # may_* capabilities are orthogonal to scope: a full-scope operator key
    # listed in allowed_updaters/allowed_internet also gets them.
    my $may_update   = $self->_is_allowed_updater($auth->{key_id});
    my $may_internet = $self->_is_allowed_internet($auth->{key_id});
    my $may_debug    = $self->_is_allowed_debug($auth->{key_id});
    $cli->{auth} = { key_id => $auth->{key_id}, verified => 1, scope => $scope,
                     may_update => $may_update, may_internet => $may_internet,
                     may_debug => $may_debug,
                     ($chat_sessions ? (chat_sessions => $chat_sessions) : ()) };
    $self->_log("auth OK $cli->{peer} key_id=$auth->{key_id} scope=$scope"
              . ($may_update ? " +update" : "") . ($may_internet ? " +internet" : "")
              . ($may_debug ? " +debug" : "")
              . ($chat_sessions
                 ? " +chats=" . join(',', sort keys %$chat_sessions) : ""));
    $self->_send($cli, format_ok(key_id => $auth->{key_id}, scope => $scope));
}

# True if this connection is allowed to mutate (FORWARD,
# NAT_MASQUERADE, SET_GATEWAY). Loopback peers always allowed;
# verified-auth connections always allowed regardless of source IP;
# otherwise fall through to the legacy allow_peers IP check.
# True iff the connection holds FULL-scope authority — a loopback peer, or
# an auth'd connection whose key is on allowed_signers/authorized_keys
# (scope='full'). Required for mesh mutation, ISP secrets, and peer-authority
# changes. A chat-only connection (scope='chat', from allowed_chat) is
# verified but NOT full, so it is excluded from every privileged op below.
sub _auth_is_full {
    my ($self, $cli) = @_;
    return 1 if _peer_is_loopback($cli);
    return 1 if $cli->{auth} && $cli->{auth}{verified}
             && ($cli->{auth}{scope} // 'full') eq 'full';
    return 0;
}

sub _peer_may_mutate {
    my ($self, $cli) = @_;
    return 1 if $self->_auth_is_full($cli);
    return $self->_peer_may_forward($cli);
}

# True if $key_id is named in /etc/net-mgr/allowed_updaters — the allowlist of
# keys permitted to fire self_update over the mesh.
sub _is_allowed_updater {
    my ($self, $key_id) = @_;
    return 0 unless defined $key_id && length $key_id;
    return scalar grep { $_ eq $key_id }
        NetMgr::Auth::principals('/etc/net-mgr/allowed_updaters');
}

# True if $key_id is named in /etc/net-mgr/allowed_internet — the allowlist of
# keys permitted to drive the he_net uplink over the mesh.
sub _is_allowed_internet {
    my ($self, $key_id) = @_;
    return 0 unless defined $key_id && length $key_id;
    return scalar grep { $_ eq $key_id }
        NetMgr::Auth::principals('/etc/net-mgr/allowed_internet');
}

# True if $key_id is named in /etc/net-mgr/allowed_debug — the allowlist of keys
# permitted to run POLL probes over the mesh when [debug] enabled is on and the
# allowlist exists (an empty/absent allowlist leaves POLL open, per _handle_poll).
# Chat-key auth (Tier 6): a key persisted via the see-and-request approval
# path can re-authenticate without being in any of the static allowed_*
# files. We pull every chat_authorized_keys row with a stored pubkey,
# write them to a temp allowed_signers file (one line per session-key pair),
# then call NetMgr::Auth::verify with a state pointing at it. Returns
# ($ok, $err, \%sessions) where %sessions maps session name -> 1 for every
# row whose pubkey matched $key_id (the rows the user is authorized for).
sub _chatkey_verify {
    my ($self, $key_id, $nonce, $sig) = @_;
    return (0, 'no key_id', undef)
        unless defined $key_id && length $key_id;
    my $matches = $self->{db}->list_chat_authorized_pubkeys($key_id);
    return (0, 'no chat-key match', undef) unless $matches && @$matches;
    my @matches = @$matches;
    require File::Temp;
    my $tmp = File::Temp->new(TEMPLATE => 'netmgr-chatkey-XXXXXX',
                              TMPDIR => 1, UNLINK => 1);
    binmode $tmp;
    # allowed_signers format: "<principals> <pubkey>". We use the fingerprint
    # itself as the principal so ssh-keygen -Y verify -I $key_id matches it.
    for my $r (@matches) {
        my $pk = $r->{pubkey} // ''; next unless length $pk;
        # pubkey may include a comment we don't need — just key_type + blob.
        print $tmp "$key_id $pk\n";
    }
    $tmp->flush;
    my $state = NetMgr::Auth::new_state(
        signers_path    => $tmp->filename,
        authorized_keys => undef,
    );
    my ($ok, $err) = NetMgr::Auth::verify($state, $key_id, $nonce, $sig);
    return ($ok, $err, undef) unless $ok;
    my %sessions = map { $_->{session} => 1 } @matches;
    return (1, undef, \%sessions);
}

sub _is_allowed_debug {
    my ($self, $key_id) = @_;
    return 0 unless defined $key_id && length $key_id;
    return scalar grep { $_ eq $key_id }
        NetMgr::Auth::principals('/etc/net-mgr/allowed_debug');
}

sub _peer_is_loopback {
    my ($cli) = @_;
    my $sock = $cli->{sock} or return 0;
    my $h = eval { $sock->peerhost } // '';
    return $h eq '127.0.0.1' || $h eq '::1';
}

# Loopback always allowed; otherwise the peer's IPv4 must fall in one
# of the CIDRs listed in [forward] allow_peers (comma- or whitespace-
# separated). Parsed once and cached.
sub _peer_may_forward {
    my ($self, $cli) = @_;
    return 1 if _peer_is_loopback($cli);
    my $sock = $cli->{sock} or return 0;
    my $h = eval { $sock->peerhost } // '';
    return 0 unless $h =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
    my $peer = ($1 << 24) | ($2 << 16) | ($3 << 8) | $4;
    my $cidrs = $self->{_fwd_allow_cidrs} //= _parse_cidrs(
        eval { $self->{cfg}{forward}{allow_peers} } // ''
    );
    for my $c (@$cidrs) {
        return 1 if ($peer & $c->[1]) == $c->[0];
    }
    return 0;
}

sub _parse_cidrs {
    my ($s) = @_;
    my @out;
    for my $tok (split /[\s,]+/, $s) {
        next unless length $tok;
        if ($tok =~ m{^(\d+)\.(\d+)\.(\d+)\.(\d+)(?:/(\d+))?$}) {
            my ($a,$b,$c,$d,$pl) = ($1,$2,$3,$4,$5);
            $pl //= 32;
            next unless $pl >= 0 && $pl <= 32;
            my $ipi  = ($a << 24) | ($b << 16) | ($c << 8) | $d;
            my $mask = $pl == 0 ? 0 : ((0xffffffff << (32 - $pl)) & 0xffffffff);
            push @out, [ $ipi & $mask, $mask ];
        }
    }
    return \@out;
}

# Walks every consumer's subscriptions; for each that matches table+WHERE,
# pushes a ROW line. Called after every UPSERT/insert/event.
sub _emit_change {
    my ($self, %args) = @_;
    my $table = $args{table};
    my $op    = $args{op};
    my $row   = $args{row} or return;
    my $match_row = _row_for_match($row);

    for my $cli (values %{ $self->{clients} }) {
        my $subs = $cli->{subs} or next;
        for my $sub_id (keys %$subs) {
            my $sub = $subs->{$sub_id};
            next unless $sub->{table} eq $table;
            next unless $sub->{mode} eq 'stream' || $sub->{mode} eq 'snapshot+stream';
            if ($sub->{where_ast}) {
                next unless eval_ast($sub->{where_ast}, $match_row);
            }
            $self->_send($cli, format_row($sub_id, $table, $op, %$row));
        }
    }
}

# Convert a DB row (DATETIME strings) to a hash with epoch seconds for
# date-shaped values, so WHERE-eval's now()/interval comparisons work.
sub _row_for_match {
    my ($row) = @_;
    my %out;
    for my $k (keys %$row) {
        my $v = $row->{$k};
        if (defined $v && $v =~ /^(\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)/) {
            require Time::Local;
            $out{$k} = eval { Time::Local::timelocal($6, $5, $4, $3, $2-1, $1) }
                       // $v;
        } else {
            $out{$k} = $v;
        }
    }
    return \%out;
}

# ---- TRIGGER ---------------------------------------------------------

sub _handle_trigger {
    my ($self, $cli, $cmd) = @_;
    my $name = $cmd->{name};
    my $wait = $cmd->{wait};

    if ($name eq 'scan-ap') {
        my @ips = $self->_known_ap_ips;
        return $self->_send($cli, format_err("no APs known"))
            unless @ips;
        my $bin = $self->_producer_path('net-poll-ap');
        return $self->_send($cli, format_err("net-poll-ap not found at $bin"))
            unless -x $bin;

        my $pid = fork();
        return $self->_send($cli, format_err("fork: $!"))
            unless defined $pid;
        if ($pid == 0) {
            # Child: close inherited sockets, exec the producer.
            for my $c (values %{ $self->{clients} }) {
                close $c->{sock} if $c->{sock};
            }
            for my $l (values %{ $self->{listeners} }) {
                close $l->{sock} if $l->{sock};
            }
            $ENV{NET_MGR_LISTEN} = $self->_child_connect_addr;
            exec $bin, @ips;
            exit 127;
        }
        $self->_log("trigger scan-ap pid=$pid ips=" . scalar(@ips)
                  . ($wait ? ' (WAIT)' : ''));

        # Don't block in waitpid — the child needs to connect back here
        # to push observations, which we can't accept while blocked.
        # Record the pending trigger; the main loop reaps it.
        $self->{triggers}{$pid} = {
            cli_fd     => ($wait ? fileno($cli->{sock}) : undef),
            name       => $name,
            started_at => time(),
        };
        $self->_send($cli, format_ok(name => $name, pid => $pid))
            unless $wait;
        return;
    }

    if ($name eq 'wifi-survey') {
        # net-wifi-survey ssh's to every AP and runs the channel scan.
        # The web CGI runs as www-data and has no ssh keys, so it
        # delegates here — the daemon runs as root with keys available.
        my $bin = $self->_producer_path('net-wifi-survey');
        return $self->_send($cli, format_err("net-wifi-survey not found at $bin"))
            unless -x $bin;
        my $pid = fork();
        return $self->_send($cli, format_err("fork: $!"))
            unless defined $pid;
        if ($pid == 0) {
            for my $c (values %{ $self->{clients} }) {
                close $c->{sock} if $c->{sock};
            }
            for my $l (values %{ $self->{listeners} }) {
                close $l->{sock} if $l->{sock};
            }
            $ENV{NET_MGR_LISTEN} = $self->_child_connect_addr;
            exec $bin;
            exit 127;
        }
        $self->_log("trigger wifi-survey pid=$pid"
                  . ($wait ? ' (WAIT)' : ''));
        $self->{triggers}{$pid} = {
            cli_fd     => ($wait ? fileno($cli->{sock}) : undef),
            name       => $name,
            started_at => time(),
        };
        $self->_send($cli, format_ok(name => $name, pid => $pid))
            unless $wait;
        return;
    }

    if ($name eq 'discover') {
        my $bin = $self->_producer_path('net-discover');
        return $self->_send($cli, format_err("net-discover not found at $bin"))
            unless -x $bin;
        my @args = ('--discover');
        if ($cmd->{kv}{network}) {
            push @args, '--network', $cmd->{kv}{network};
        }
        my $pid = fork();
        return $self->_send($cli, format_err("fork: $!"))
            unless defined $pid;
        if ($pid == 0) {
            for my $c (values %{ $self->{clients} }) {
                close $c->{sock} if $c->{sock};
            }
            for my $l (values %{ $self->{listeners} }) {
                close $l->{sock} if $l->{sock};
            }
            $ENV{NET_MGR_LISTEN} = $self->_child_connect_addr;
            exec $bin, @args;
            exit 127;
        }
        $self->_log("trigger discover pid=$pid args=@args"
                  . ($wait ? ' (WAIT)' : ''));
        $self->{triggers}{$pid} = {
            cli_fd     => ($wait ? fileno($cli->{sock}) : undef),
            name       => $name,
            started_at => time(),
        };
        $self->_send($cli, format_ok(name => $name, pid => $pid))
            unless $wait;
        return;
    }

    if ($name eq 'presence') {
        my $bin = $self->_producer_path('net-discover');
        return $self->_send($cli, format_err("net-discover not found at $bin"))
            unless -x $bin;
        my $pid = fork();
        return $self->_send($cli, format_err("fork: $!")) unless defined $pid;
        if ($pid == 0) {
            for my $c (values %{ $self->{clients} }) { close $c->{sock} if $c->{sock} }
            for my $l (values %{ $self->{listeners} }) {
                close $l->{sock} if $l->{sock};
            }
            $ENV{NET_MGR_LISTEN} = $self->_child_connect_addr;
            exec $bin, '--presence';
            exit 127;
        }
        $self->_log("trigger presence pid=$pid" . ($wait ? ' (WAIT)' : ''));
        $self->{triggers}{$pid} = {
            cli_fd     => ($wait ? fileno($cli->{sock}) : undef),
            name       => $name,
            started_at => time(),
        };
        $self->_send($cli, format_ok(name => $name, pid => $pid))
            unless $wait;
        return;
    }

    if ($name eq 'probe-host') {
        return $self->_send($cli, format_err("trigger '$name' not yet implemented"));
    }

    if ($name eq 'reset-rtt') {
        # In-process: no fork, just clear the RTT fields. addr= picks
        # one IP; addr= absent + all=1 clears every row.
        my $kv   = $cmd->{kv} || {};
        my $addr = $kv->{addr};
        my $all  = $kv->{all};
        my $n;
        if ($addr) {
            $n = $self->{db}->reset_rtt(addr => $addr);
        } elsif ($all) {
            $n = $self->{db}->reset_rtt;
        } else {
            return $self->_send($cli,
                format_err("reset-rtt needs addr=<ip> or all=1"));
        }
        $self->_log("trigger reset-rtt rows=$n addr=" . ($addr // '*'));
        return $self->_send($cli, format_ok(name => $name, rows => $n));
    }

    $self->_send($cli, format_err("unknown trigger '$name'"));
}

# Flip currently-online interfaces back to offline if their last_seen
# is older than the grace period. Cheap query; runs at most every 30s.
# Walk a parsed WHERE AST looking for a `ts > ago(N)` (or AND-chain
# containing one), return the absolute epoch threshold. Used to push a
# windowed snapshot down into SQL when the events table is queried.
# Conservative — only matches a few common shapes; falls through (=
# no SQL filter) for anything fancier and the in-Perl WHERE eval still
# applies.
sub _extract_ts_lower_bound {
    my ($ast) = @_;
    return undef unless ref $ast eq 'ARRAY' && @$ast;
    my $op = $ast->[0];
    if ($op eq 'and') {
        for my $branch (@{$ast}[1 .. $#$ast]) {
            my $b = _extract_ts_lower_bound($branch);
            return $b if $b;
        }
        return undef;
    }
    if ($op eq '>' || $op eq '>=') {
        my ($lhs, $rhs) = @{$ast}[1, 2];
        return undef unless ref $lhs eq 'ARRAY' && $lhs->[0] eq 'col'
                         && $lhs->[1] eq 'ts';
        return undef unless ref $rhs eq 'ARRAY' && $rhs->[0] eq 'fn_ago';
        my $secs = $rhs->[1];
        return undef unless ref $secs eq 'ARRAY' && $secs->[0] eq 'num';
        return time() - $secs->[1];
    }
    return undef;
}

# Run periodically: drop events older than retention. Bounded by an
# hourly cap so the daemon doesn't keep slamming DELETE on a tiny table.
sub _purge_old_events {
    my ($self) = @_;
    my $now = time();
    return if ($now - ($self->{_last_purge} // 0)) < 3600;
    $self->{_last_purge} = $now;
    my $days = $self->{config}{manager}{event_retention_days} // 7;
    return unless $days > 0;
    my $n = $self->{db}->purge_events(days => $days);
    $self->_log("purged $n event row(s) older than ${days}d") if $n && $n > 0;
}

sub _age_out_offline {
    my ($self) = @_;
    my $grace = $self->{config}{manager}{offline_after} // 300;
    return unless $grace && $grace > 0;
    my $now = time();
    return if ($now - ($self->{_last_age_check} // 0)) < 30;
    $self->{_last_age_check} = $now;

    my $rows = $self->{db}->dbh->selectall_arrayref(
        "SELECT mac FROM interfaces
          WHERE online = 1
            AND last_seen < DATE_SUB(NOW(), INTERVAL ? SECOND)",
        { Slice => {} }, $grace
    );
    return unless @$rows;
    for my $r (@$rows) {
        my $upd = $self->_upsert('interfaces', 'upsert_interface',
            mac => $r->{mac}, online => 0);
        if ($upd->{op} eq 'update'
            && grep { $_ eq 'online' } @{ $upd->{changed_fields} })
        {
            $self->_log_event(type => 'interface_offline', mac => $r->{mac});
        }
    }
}

# Periodic, daemon-initiated TRIGGERs. Reads intervals from
# $cfg->{scheduling} and fires the matching producer when due.
# Skips if a previous run of the same name is still pending.
sub _check_periodic_triggers {
    my ($self) = @_;
    my $sched = $self->{config}{scheduling} || {};
    my $now   = time();
    $self->{periodic_last} //= {};

    for my $name (qw(scan-ap presence discover find-peers import-leases push-dnsmasq ddns ipv6_vlan netif)) {
        my $interval = $sched->{$name} // 0;
        # netif: track interface changes (WiFi/USB up/down) and rebind the
        # 'all'/'auto' listeners. Auto-enable at 30s for those specs (an explicit
        # address list is static, so it stays off). SIGHUP gives an instant nudge.
        if ($name eq 'netif' && !$interval) {
            my $spec = $self->{config}{manager}{listen} || 'all';
            $interval = 30 if grep { lc($_) eq 'all' || lc($_) eq 'auto' }
                              map { s/^\s+|\s+$//gr } split /,/, $spec;
        }
        # ipv6_vlan keep-up: re-establish a managed IPv6 net that's down. Auto-
        # enable at 60s when there's one to keep up (the control VLAN has an id,
        # or an he6in4 network is mode=on).
        if ($name eq 'ipv6_vlan' && !$interval) {
            my $vl = $self->{config}{ipv6_vlan} || {};
            my $cl = $self->{config}{cluster}   || {};
            my $want = length($vl->{network_management}{id} // $cl->{control_vlan_id} // '');
            unless ($want) {
                for my $e (values %$vl) {
                    next unless ref $e eq 'HASH';
                    $want = 1, last
                        if lc($e->{mode} // 'off') eq 'on'
                        || lc($e->{type} // '') eq 'relay';
                }
            }
            $interval = 60 if $want;
        }
        # ddns: watch the WAN IP and run /etc/net-mgr/ddns hooks on change. Cadence
        # from [ddns] interval; auto-enable at 120s when that dir has hooks, so
        # dropping a script in activates it without extra config.
        if ($name eq 'ddns') {
            $interval = $self->{config}{ddns}{interval} // 0;
            $interval ||= 120 if NetMgr::Ddns::hooks($self->{config}{ddns}{dir}
                                                     || '/etc/net-mgr/ddns');
        }
        # find-peers powers cluster auto-discovery: default it to 5 min when this
        # node auto-discovers and the operator hasn't set a [scheduling] cadence,
        # so a fresh follower bootstraps the mesh without any extra config.
        $interval ||= 300 if $name eq 'find-peers' && $self->{cluster}{auto_spec};
        # push-dnsmasq polls dhcp_reservations for changes and regenerates/pushes
        # when this node opts in ([dhcp] gen_local / push_aps). Default 30s when
        # opted in; otherwise interval 0 = inert (never runs).
        $interval ||= 30 if $name eq 'push-dnsmasq'
            && ((($self->{config}{dnsmasq}{mode} // 'off') eq 'auto')
                 || $self->{config}{dnsmasq}{push_aps});
        next unless $interval && $interval > 0;
        my $last = $self->{periodic_last}{$name} // 0;
        next if ($now - $last) < $interval;

        # Don't pile up if the previous run is still going
        if (grep { $_->{name} eq $name } values %{ $self->{triggers} }) {
            next;
        }
        $self->{periodic_last}{$name} = $now;
        $self->_fire_periodic($name);
    }
}

sub _fire_periodic {
    my ($self, $name) = @_;
    if ($name eq 'push-dnsmasq') { $self->_sync_dnsmasq; return }
    if ($name eq 'ddns')         { $self->_check_ddns;   return }
    if ($name eq 'ipv6_vlan')    { $self->_check_ipv6_vlans; return }
    if ($name eq 'netif')        { $self->_recheck_listeners; return }
    my ($bin, @args);
    if ($name eq 'scan-ap') {
        my @ips = $self->_known_ap_ips;
        return unless @ips;
        $bin  = $self->_producer_path('net-poll-ap');
        @args = @ips;
    } elsif ($name eq 'presence') {
        $bin  = $self->_producer_path('net-discover');
        @args = ('--presence');
    } elsif ($name eq 'discover') {
        $bin  = $self->_producer_path('net-discover');
        @args = ('--discover');
    } elsif ($name eq 'find-peers') {
        # Auto-discover other net-mgr daemons on the LAN. The tool
        # writes its findings to the local `peers` table; the new
        # 'unconfigured peer found' event-emit path lives in
        # net-find-peers itself (sees a peer whose primary_name
        # isn't in [cluster] members, emits an event). Keeping the
        # logic there avoids duplicating it in this dispatcher.
        $bin  = $self->_producer_path('net-find-peers');
        @args = ('--quiet');
        # Cold start: when auto-discovering, let net-find-peers fall back to a
        # direct local-/24 sweep if the peers table is still empty (the normal
        # scan only probes already-known addresses, which a fresh follower lacks).
        push @args, '--bootstrap' if $self->{cluster}{auto_spec};
    } elsif ($name eq 'import-leases') {
        # Pull the APs'/gateways' current DHCP leases — catches devices that
        # never answer an active scan (sleepy sensors, smart plugs). Opt-in via
        # [scheduling] import-leases (it ssh's out to every AP/gateway).
        $bin  = $self->_producer_path('net-import-dnsmasq');
        @args = ('--auto', '--leases');
    } else {
        return;
    }
    return unless $bin && -x $bin;

    my $pid = fork();
    return unless defined $pid;
    if ($pid == 0) {
        for my $c (values %{ $self->{clients} }) { close $c->{sock} if $c->{sock} }
        close $self->{listen} if $self->{listen};
        # A connectable address for the child to reach US — NOT the raw config
        # 'listen' value, which may be a bind spec like 'auto' or '0.0.0.0:7531'
        # that you can't connect() to ("connect auto:7531: Invalid argument").
        # That silently broke net-find-peers (and every forked producer) on any
        # node configured `listen = auto`: the child died before populating the
        # peers table, so auto-discovery never found a master.
        $ENV{NET_MGR_LISTEN} = $self->_self_connect_addr;
        exec $bin, @args;
        exit 127;
    }
    my $next = $self->{config}{scheduling}{$name} // '?';
    $self->_log("periodic $name pid=$pid (next in ${next}s)");
    $self->{triggers}{$pid} = {
        cli_fd     => undef,
        name       => $name,
        started_at => time(),
    };
}

# Regenerate / push dnsmasq config when dhcp_reservations has changed. Gated by
# [dnsmasq] mode = auto (this node regenerates its OWN dnsmasq from the local DB
# replica + reload — the gateway "do it automatically on reservation updates"
# path) and, on the master, [dnsmasq] push_aps (push DD-WRT AP static_leases).
# Default OFF, so this is inert until a node opts in. Change is detected by a
# (count | max updated_at) signature so rapid edits coalesce into one
# regen/push; the first observation after startup only primes the signature (no
# push on restart). Work runs in forked children, reaped like any other trigger.
# (An operator/master can also force a regen out-of-band via OBSERVE
# kind=regen_dnsmasq -> _obs_regen_dnsmasq, independent of the auto poll.)
sub _sync_dnsmasq {
    my ($self) = @_;
    my $cfg       = $self->{config}{dnsmasq} || {};
    my $is_master = (($self->{cluster_runtime}{role} // $self->{cluster}{role} // '') eq 'master');
    my $want_gen  = (($cfg->{mode} // 'off') eq 'auto') ? 1 : 0;   # gateway: self-regen on change
    my $want_aps  = ($is_master && $cfg->{push_aps})    ? 1 : 0;   # master: push DD-WRT APs
    return unless $want_gen || $want_aps;

    my $sig = eval {
        my $r = $self->{db}->dbh->selectrow_arrayref(
            "SELECT COUNT(*), COALESCE(MAX(updated_at), '') FROM dhcp_reservations");
        $r ? ($r->[0] . '|' . $r->[1]) : '';
    };
    $sig //= '';
    my $primed = exists $self->{dnsmasq_sig};
    return if $primed && $self->{dnsmasq_sig} eq $sig;
    $self->{dnsmasq_sig} = $sig;
    return unless $primed;          # first run after start: prime only, don't push

    $self->_log("dnsmasq sync: reservations changed (sig=$sig) gen=$want_gen aps=$want_aps");
    my @jobs;
    push @jobs, [ $self->_producer_path('net-gen-dnsmasq'), '--from-db', '--reload' ] if $want_gen;
    push @jobs, [ $self->_producer_path('net-push-ap'),     '--apply', '--auto'     ] if $want_aps;
    for my $j (@jobs) {
        my ($bin, @args) = @$j;
        unless ($bin && -x $bin) {
            $self->_log("dnsmasq sync: skip — not executable: " . ($bin // '?'));
            next;
        }
        my $pid = fork();
        next unless defined $pid;
        if ($pid == 0) {
            for my $c (values %{ $self->{clients} }) { close $c->{sock} if $c->{sock} }
            close $self->{listen} if $self->{listen};
            $ENV{NET_MGR_LISTEN} = $self->_self_connect_addr;
            exec $bin, @args;
            exit 127;
        }
        $self->_log("dnsmasq sync: $bin @args pid=$pid");
        $self->{triggers}{$pid} = { cli_fd => undef, name => 'push-dnsmasq', started_at => time() };
    }
}

# Non-blocking reap of any TRIGGER children that have exited.
# For WAIT triggers, sends READY to the waiting client (if still connected).
sub _reap_triggers {
    my ($self) = @_;
    while ((my $pid = waitpid(-1, POSIX::WNOHANG())) > 0) {
        my $exit = $? >> 8;
        my $t = delete $self->{triggers}{$pid};
        next unless $t;
        $self->_log("trigger $t->{name} pid=$pid done exit=$exit"
                  . " elapsed=" . (time() - $t->{started_at}) . "s");
        if ($t->{name} eq 'self-update') {
            if ($exit == 0) {
                $self->_log("self-update OK — re-execing into the new code");
                $self->_reexec;            # does not return on success
            } else {
                $self->_log("self-update FAILED (exit=$exit) — keeping current version");
            }
            next;
        }
        next unless defined $t->{cli_fd};
        my $cli = $self->{clients}{ $t->{cli_fd} };
        next unless $cli;
        $self->_send($cli, format_ready(name => $t->{name}, pid => $pid,
                                        exit => $exit));
    }
}

# OBSERVE kind=self_update — run the configured update script (pull + reinstall
# the [manager] repo) and, on success, re-exec into the new code. Auth-gated.
# Lets `net-cluster update` redeploy the whole cluster in one shot instead of
# hand-running git pull / make install / restart on every node. The actual steps
# live in a versioned, overridable script (sbin/net-mgr-self-update), not here,
# so an operator can adapt them without touching the daemon. The work runs in a
# forked child so the run loop keeps serving; on success _reap_triggers re-execs.
sub _obs_self_update {
    my ($self, $cli, $kv) = @_;
    my ($who) = $self->_chat_identity($cli, $kv);
    die "self_update: not authorized\n" unless defined $who;
    # A remote caller must be on /etc/net-mgr/allowed_updaters; loopback/local
    # root is implicitly trusted (it can already run the script directly).
    unless (_peer_is_loopback($cli) || ($cli->{auth} && $cli->{auth}{may_update})) {
        die "self_update: '$who' is not an allowed updater "
          . "(add the key to /etc/net-mgr/allowed_updaters)\n";
    }
    my $repo = $self->{config}{manager}{repo};
    die "self_update: no repo configured (set [manager] repo = /path/to/checkout)\n"
        unless defined $repo && length $repo;
    $repo =~ m{^[\w./-]+$}
        or die "self_update: refusing suspicious repo path '$repo'\n";
    -d "$repo/.git" or die "self_update: '$repo' is not a git checkout\n";
    # Default to the INSTALLED script: a `git pull` of the repo copy can't rewrite
    # it out from under us mid-run. [manager] update_script overrides it.
    my $script = $self->{config}{manager}{update_script}
              // '/usr/local/sbin/net-mgr-self-update';
    -x $script or die "self_update: update script '$script' is not executable\n";
    die "self_update: already in progress\n"
        if grep { $_->{name} eq 'self-update' } values %{ $self->{triggers} };

    my $pid = fork();
    die "self_update: fork failed: $!\n" unless defined $pid;
    if ($pid == 0) {
        for my $c (values %{ $self->{clients}   }) { close $c->{sock} if $c->{sock} }
        for my $l (values %{ $self->{listeners} }) { close $l->{sock} if $l->{sock} }
        $ENV{NET_MGR_REPO} = $repo;     # the script pulls/installs this checkout
        # A deploy hub ([deploy] hosts set) also pushes the new code to its leaf
        # nodes after installing (the script runs net-mgr-deploy, best-effort).
        if (($self->{config}{deploy}{hosts} // '') =~ /\S/) {
            $ENV{NET_MGR_DEPLOY} = '1';
            my $du = $self->{config}{deploy}{user};
            $ENV{NET_MGR_DEPLOY_USER} = $du if defined $du && length $du;
        }
        { no warnings; exec $script; } # exec replaces us; _exit only on failure
        POSIX::_exit(127);
    }
    $self->{triggers}{$pid} = { name => 'self-update', started_at => time(),
                                cli_fd => undef, who => $who };
    $self->_log("self-update started pid=$pid by $who (repo=$repo script=$script)");
    return ();   # OBSERVE OK now; the daemon re-execs when the child succeeds
}

# OBSERVE kind=deploy — push this checkout to the [deploy] hosts (`make deploy`),
# for a deploy HUB (e.g. nas3) feeding leaf nodes that have no repo of their own
# (the gateways). Runs the configured deploy script in a forked child so the run
# loop keeps serving; _reap_triggers just logs the result (no re-exec — this node
# isn't the one changing). Auth-gated on may_update, same as self_update.
sub _obs_deploy {
    my ($self, $cli, $kv) = @_;
    my ($who) = $self->_chat_identity($cli, $kv);
    die "deploy: not authorized\n" unless defined $who;
    unless (_peer_is_loopback($cli) || ($cli->{auth} && $cli->{auth}{may_update})) {
        die "deploy: '$who' is not an allowed updater "
          . "(add the key to /etc/net-mgr/allowed_updaters)\n";
    }
    my $repo = $self->{config}{manager}{repo};
    die "deploy: no repo configured (set [manager] repo = /path/to/checkout)\n"
        unless defined $repo && length $repo;
    $repo =~ m{^[\w./-]+$}
        or die "deploy: refusing suspicious repo path '$repo'\n";
    -d "$repo/.git" or die "deploy: '$repo' is not a git checkout\n";
    my $script = $self->{config}{manager}{deploy_script}
              // '/usr/local/sbin/net-mgr-deploy';
    -x $script or die "deploy: deploy script '$script' is not executable\n";
    die "deploy: already in progress\n"
        if grep { $_->{name} eq 'deploy' } values %{ $self->{triggers} };

    my $pid = fork();
    die "deploy: fork failed: $!\n" unless defined $pid;
    if ($pid == 0) {
        for my $c (values %{ $self->{clients}   }) { close $c->{sock} if $c->{sock} }
        for my $l (values %{ $self->{listeners} }) { close $l->{sock} if $l->{sock} }
        $ENV{NET_MGR_REPO} = $repo;
        my $du = $self->{config}{deploy}{user};
        $ENV{NET_MGR_DEPLOY_USER} = $du if defined $du && length $du;
        { no warnings; exec $script; }
        POSIX::_exit(127);
    }
    $self->{triggers}{$pid} = { name => 'deploy', started_at => time(),
                                cli_fd => undef, who => $who };
    $self->_log("deploy started pid=$pid by $who (make deploy, repo=$repo script=$script)");
    return ();
}

# Re-exec the daemon into freshly installed code (after self_update). Relaunch
# with the exact original argv via /proc/self/cmdline. Perl marks our sockets
# close-on-exec, so the replacement process rebinds cleanly.
sub _reexec {
    my ($self) = @_;
    my @argv;
    if (open my $fh, '<', '/proc/self/cmdline') {
        local $/; my $raw = <$fh> // ''; close $fh;
        @argv = grep { length } split /\0/, $raw;
    }
    @argv = ($^X, $0, @ARGV) unless @argv;
    $self->_log("self-update: re-exec @argv");
    { no warnings; exec { $argv[0] } @argv; }
    $self->_log("self-update: re-exec failed: $! — exiting for systemd to restart");
    exit 1;     # Restart=on-failure brings us back up on the new code
}

# ---- POLL ----------------------------------------------------------------
#
# Synchronous RPC: peer asks the daemon to run a whitelisted local probe
# and ship the captured stdout back in the OK reply.  Output is base64-
# encoded so newlines/quotes survive the kv wire format.  No client-
# supplied shell — the name argument indexes into %POLL_SCRIPTS only.
#
# Runs as the daemon user (typically root, which is what iptables-save
# needs).  Same trust boundary as the rest of the protocol: anyone who
# can reach :7531 can already drive producers via TRIGGER, so POLL
# isn't widening the attack surface — just exposing read-only probes
# of host state that the daemon can already see.
# Each value is either a shell-script string (run via /bin/sh -c) or
# a code-ref that returns a string. The dispatcher in _handle_poll
# picks the right path.
my %POLL_SCRIPTS = (
    fw_state => <<'SH',
echo ===KIND===
if [ -f /tmp/.rc_started ] || [ -e /jffs ]; then echo dd-wrt
elif [ -f /etc/openwrt_release ]; then echo openwrt
elif [ -e /usr/bin/cygpath ]; then echo cygwin
else echo linux; fi
echo ===HOSTNAME===
hostname 2>/dev/null
echo ===ROUTES===
ip -4 route show 2>/dev/null || route -n 2>/dev/null
echo ===NAT===
iptables-save -t nat 2>/dev/null
echo ===FILTER===
iptables-save -t filter 2>/dev/null
echo ===END===
SH
    ssh_forwards => 'pgrep -lfa ssh 2>/dev/null',
    'host-debug' => sub {
        require NetMgr::HostDebug;
        return NetMgr::HostDebug::format_report();
    },
    # IPv6 state — for debugging the ipv6_vlan model (control VLAN, he6in4 tunnel,
    # relay) on a node you can't ssh to.
    ipv6 => <<'SH',
echo "=== global v6 addresses (which iface has what) ==="
ip -6 -br addr show 2>/dev/null | grep -vE "^lo " | grep -iE "2[0-9a-f:]+|fd[0-9a-f:]+" || ip -6 addr show scope global 2>/dev/null
echo "=== default v6 route(s) ==="
ip -6 route show default 2>/dev/null
echo "=== sit tunnels (he6in4) ==="
ip -d link show type sit 2>/dev/null | grep -E ":|link/sit"
echo "=== forwarding ==="
sysctl net.ipv6.conf.all.forwarding 2>/dev/null
echo "=== disable_ipv6 per iface (1 = v6 off; ip -6 addr add -> EPERM even as root) ==="
grep -H . /proc/sys/net/ipv6/conf/*/disable_ipv6 2>/dev/null | sed 's|/proc/sys/net/ipv6/conf/||; s|/disable_ipv6:|: |'
echo "=== v6 neighbors ==="
ip -6 neigh show 2>/dev/null | grep -vi fe80 | head -10
SH
    ifaces => 'ip -br addr show 2>/dev/null',
    routes => 'echo "== v4 =="; ip -4 route show 2>/dev/null; echo "== v6 =="; ip -6 route show 2>/dev/null',
    # The active /etc/net-mgr/config. Plain text, no creds (creds live in
    # /etc/net-mgr/secrets/ and /etc/net-mgr/root.conf — neither is exposed by
    # any probe). Lets an operator audit a remote node's config without ssh,
    # and pairs with `net-cluster put` (round-trip: poll, edit, put).
    config => 'cat /etc/net-mgr/config 2>/dev/null',
    # IPv6 reachability FROM this node — forwarding, the v6 firewall (a FORWARD
    # DROP silently eats relayed traffic), and ping to public v6. Run on the
    # uplink (gateway3) to test its own tunnel; on a relay client to test the
    # whole path. ~6s (pings).
    'ipv6-ping' => <<'SH',
echo "=== forwarding (all/default) ==="
sysctl net.ipv6.conf.all.forwarding net.ipv6.conf.default.forwarding 2>/dev/null
echo "=== ip6tables policy + FORWARD chain ==="
ip6tables -S 2>/dev/null | grep -E "^-P|FORWARD" | head -20 || echo "(no ip6tables / not permitted)"
echo "=== ping6 Cloudflare 2606:4700:4700::1111 ==="
ping6 -c2 -W2 2606:4700:4700::1111 2>&1 | tail -3
echo "=== ping6 Google 2001:4860:4860::8888 ==="
ping6 -c2 -W2 2001:4860:4860::8888 2>&1 | tail -3
SH
);

# Coderef POLLs that need access to the daemon object (for in-memory
# state, e.g. the cluster's peer_caps table). Keyed identically to
# %POLL_SCRIPTS; checked first.
my %POLL_METHODS = (
    'peer-caps' => sub {
        my ($self) = @_;
        my $caps = $self->{cluster}{peer_caps} || {};
        my @lines;
        for my $name (sort keys %$caps) {
            my $list = join(',', @{ $caps->{$name} || [] });
            push @lines, "$name\t$list";
        }
        return join("\n", @lines) . "\n";
    },
    # Recent daemon log — the tail of [manager] log, or journald if the daemon
    # logs to stderr under systemd. Read-only window into what the daemon just
    # did (ipv6_vlan attach decisions, election, errors) on a node you can't ssh
    # to. Gated like every POLL probe (see _handle_poll).
    'netmgr-log' => sub {
        my ($self) = @_;
        # Prefer journald: net-mgr.service logs StandardOutput=journal, so the
        # [manager] log FILE is usually a stale relic. Fall back to the file only
        # when journald has nothing for us (non-systemd host, older build).
        my $unit = $self->{config}{manager}{unit} || 'net-mgr';
        my $j = `journalctl -u "$unit.service" -n 120 --no-pager 2>/dev/null`;
        $j = `journalctl -t "$unit" -n 120 --no-pager 2>/dev/null` if $j !~ /\S/;
        return "== journalctl $unit -n 120 ==\n$j" if $j =~ /\S/;
        my $log = $self->{config}{manager}{log} || '/var/log/net-mgr.log';
        return "== tail -120 $log ==\n" . `tail -n 120 "$log" 2>/dev/null` if -r $log;
        return "(no journald entries for $unit and no readable $log)\n";
    },
    # One-shot net-find-peers --bootstrap --print run, for diagnosing
    # cluster-discovery problems on a node you can't ssh to. The --print mode
    # never writes to the DB, so this is read-only.
    'find-peers' => sub {
        my $bin = '/usr/local/bin/net-find-peers';
        return "(net-find-peers not found at $bin)\n" unless -x $bin;
        return "== $bin --bootstrap --print ==\n"
             . `$bin --bootstrap --print --timeout 1 2>&1`;
    },
    # Tail of net-mgr-relay.service — separate unit, separate journal. Needed
    # to diagnose replication problems (relay can't reach master, is subscribed
    # to too few tables, is connecting but the snapshot fails, etc.) on a node
    # where ssh isn't an option.
    'relay-log' => sub {
        my $unit = 'net-mgr-relay';
        my $j = `journalctl -u "$unit.service" -n 120 --no-pager 2>/dev/null`;
        return "== journalctl $unit -n 120 ==\n$j" if $j =~ /\S/;
        return "(no journald entries for $unit)\n";
    },
);

sub _handle_poll {
    my ($self, $cli, $cmd) = @_;
    # Debug/query gate. [debug] enabled (default on) is the master switch; turn it
    # off to refuse all POLL. When /etc/net-mgr/allowed_debug exists, restrict POLL
    # to loopback or keys flagged may_debug; with no allowlist POLL stays open
    # (read-only probes, same trust boundary as TRIGGER — back-compat).
    my $en = lc($self->{config}{debug}{enabled} // 'on');
    if ($en =~ /^(off|no|0|false|disabled)$/) {
        return $self->_send($cli, format_err("POLL disabled ([debug] enabled=off)"));
    }
    if (NetMgr::Auth::principals('/etc/net-mgr/allowed_debug')) {
        unless (_peer_is_loopback($cli) || ($cli->{auth} && $cli->{auth}{may_debug})) {
            return $self->_send($cli,
                format_err("POLL: not authorized (add the key to /etc/net-mgr/allowed_debug)"));
        }
    }
    my $name = $cmd->{name} // '';
    my $method = $POLL_METHODS{$name};
    my $handler = $POLL_SCRIPTS{$name};
    if (!defined $method && !defined $handler) {
        my @ok = sort(keys %POLL_SCRIPTS, keys %POLL_METHODS);
        return $self->_send($cli,
            format_err("unknown POLL '$name' (allowed: @ok)"));
    }
    my $output = '';
    eval {
        if ($method) {
            $output = $method->($self) // '';
        } elsif (ref($handler) eq 'CODE') {
            $output = $handler->() // '';
        } else {
            open(my $fh, '-|', '/bin/sh', '-c', $handler)
                or die "fork /bin/sh: $!\n";
            local $/;
            $output = <$fh> // '';
            close $fh;
        }
    };
    if ($@) {
        my $e = $@; chomp $e;
        return $self->_send($cli, format_err("POLL $name: $e"));
    }
    require MIME::Base64;
    my $b64 = MIME::Base64::encode_base64($output, '');   # no newlines
    $self->_send($cli, format_ok(name => $name, output => $b64));
    $self->_log("poll $name from $cli->{ident} ("
              . length($output) . " bytes)");
}

# Returns sorted unique v4 addresses for known APs.
sub _known_ap_ips {
    my ($self) = @_;
    my $rows = $self->{db}->dbh->selectall_arrayref(
        "SELECT DISTINCT ad.addr
           FROM aps a JOIN addresses ad ON ad.mac = a.mac
          WHERE ad.family = 'v4'
          ORDER BY ad.addr",
        { Slice => {} }
    );
    return map { $_->{addr} } @$rows;
}

# Locate a sibling producer binary. Looks at config[paths] first, then
# alongside the daemon under sbin/../bin/.
sub _producer_path {
    my ($self, $name) = @_;
    my $cfg_path = $self->{config}{paths}{$name};
    return $cfg_path if $cfg_path;
    # Source-tree layout: lib/NetMgr/Manager.pm → ../../bin/<name>
    require File::Basename;
    my $here = File::Basename::dirname(__FILE__);
    for my $cand ("$here/../../bin/$name",
                  "$FindBin::Bin/../bin/$name",
                  "/usr/local/bin/$name") {
        return $cand if -x $cand;
    }
    return "$here/../../bin/$name";   # report this in the error
}

# ---- upsert + emit wrappers ------------------------------------------
# Keeps the OBSERVE handlers tidy and ensures every change reaches
# subscribers. $table is the logical table name; $method is the DB
# method (e.g. 'upsert_interface').

sub _upsert {
    my ($self, $table, $method, %args) = @_;
    my $r = $self->{db}->$method(%args);
    if ($r->{op} && $r->{op} ne 'noop' && $r->{now}) {
        $self->_emit_change(table => $table, op => $r->{op}, row => $r->{now});
    }
    return $r;
}

sub _log_event {
    my ($self, %ev) = @_;
    my $id = $self->{db}->log_event(%ev);
    $self->_log("event $ev{type} mac=" . ($ev{mac} // '-')
                                . " addr=" . ($ev{addr} // '-'));
    # Re-fetch the row so subscribers see exactly what's persisted.
    my $row = $self->{db}->dbh->selectrow_hashref(
        "SELECT * FROM events WHERE id = ?", undef, $id);
    $self->_emit_change(table => 'events', op => 'insert', row => $row) if $row;
    return $id;
}


# ---- net-chat --------------------------------------------------------
#
# Named chat sessions hosted by the daemon. Control verbs (CHAT_OPEN /
# SET / CLOSE / JOIN / LEAVE / ALLOW / DENY / APPROVE / REJECT) flow
# through the handlers below; message posting rides OBSERVE
# kind=chat_msg (_obs_chat_msg). Reading history / listing sessions /
# streaming a roster all use the generic SUBSCRIBE machinery against
# the chat_* tables (registered in %SUBSCRIBABLE).

# Resolve the caller's chat identity. A verified-AUTH connection is its
# key_id (an 'agent'); a loopback connection is trusted to self-declare
# `as=NAME` (a 'human', used by the web GUI passing REMOTE_USER) and
# falls back to 'local'. Anyone else is unauthenticated → (undef,undef).
sub _chat_identity {
    my ($self, $cli, $kv) = @_;
    if ($cli->{auth} && $cli->{auth}{verified}) {
        return ($cli->{auth}{key_id}, 'agent');
    }
    if (_peer_is_loopback($cli)) {
        my $as = (defined $kv && length($kv->{as} // '')) ? $kv->{as} : 'local';
        return ($as, 'human');
    }
    # Unverified remote: an unauthed connection that supplies a self-asserted
    # name (as=NAME). The name carries the 'unverified:' prefix so it's blatant
    # in every UI surface — owners are explicitly accepting that the name is
    # not cryptographically tied to a key. Used by the see-and-request flow:
    # the user can browse open sessions and ask active members to admit them.
    # CHAT_JOIN routes unverified principals through the request flow even for
    # mode=open (no auto-admit); other write verbs treat them as non-members
    # until/unless a member approves.
    if (defined $kv && length($kv->{as} // '')) {
        my $as = $kv->{as};
        # Strip any leading 'unverified:' the client might have prepended, then
        # add it ourselves — the prefix belongs to the daemon, not the client.
        $as =~ s/^\s*unverified:\s*//i;
        return ("unverified:$as", 'unverified') if length $as;
    }
    return (undef, undef);
}

# Sanity-normalise an OpenSSH-format public key arriving in a kv field. Strips
# stray whitespace, collapses internal runs to single spaces, refuses anything
# that doesn't look like a real pubkey ("ssh-*", "ecdsa-*", "sk-*", followed by
# a base64 blob). 4 KiB length cap. Returns undef on rejection so callers can
# treat that as "no pubkey supplied" (the request still goes through, just
# without durable-key auth on approval).
sub _normalize_pubkey {
    my ($v) = @_;
    return undef unless defined $v && length $v;
    return undef if length($v) > 4096;
    $v =~ s/\A\s+|\s+\z//g;
    $v =~ s/\s+/ /g;
    return undef unless $v =~ m{\A(?:ssh-(?:rsa|dss|ed25519|ed25519-sk)
                                       |ecdsa-sha2-[A-Za-z0-9-]+
                                       |sk-(?:ssh-ed25519|ecdsa-sha2-[A-Za-z0-9-]+))
                                 \s+[A-Za-z0-9+/=]{40,}
                                 (?:\s+\S.*)?\z}x;
    return $v;
}

# Compute the SHA256 fingerprint + key_type of an OpenSSH-format public key by
# shelling out to ssh-keygen -lf. Returns (key_id, key_type) — "SHA256:...",
# "ed25519"/"rsa"/etc — or (undef, undef) on failure. Used when persisting an
# unverified user's pubkey to chat_authorized_keys on approval; the resulting
# key_id is what the future AUTH dance will present as its principal.
sub _pubkey_fingerprint {
    my ($pubkey) = @_;
    return (undef, undef) unless defined $pubkey && length $pubkey;
    require File::Temp;
    my $tmp = File::Temp->new(TEMPLATE => 'netmgr-pk-XXXXXX',
                              TMPDIR => 1, SUFFIX => '.pub', UNLINK => 1);
    binmode $tmp;
    print $tmp $pubkey;
    $tmp->flush;
    # `ssh-keygen -l -E sha256 -f <file>` ⇒ "256 SHA256:... user@host (ED25519)"
    my $out = `ssh-keygen -l -E sha256 -f '@{[ $tmp->filename ]}' 2>/dev/null`;
    return (undef, undef) unless defined $out && $out =~ /SHA256:/;
    chomp $out;
    my ($fp)  = $out =~ /(SHA256:\S+)/;
    my ($typ) = $out =~ /\(([A-Za-z0-9_-]+)\)\s*\z/;
    return (undef, undef) unless defined $fp && length $fp;
    return ($fp, lc($typ // ''));
}

# Active member: principal currently present in the session (chat_presence row).
# An active member can admit (allow/approve) other principals — that's the
# see-and-request flow: not only the owner, but anyone currently in the chat
# can let a requester in.
sub _chat_is_active_member {
    my ($self, $session, $principal) = @_;
    return 0 unless defined $session && defined $principal;
    my $rows = $self->{db}->dbh->selectall_arrayref(
        "SELECT 1 FROM chat_presence WHERE session = ? AND principal = ? LIMIT 1",
        { Slice => {} }, $session, $principal);
    return scalar(@$rows) ? 1 : 0;
}

# Session names: a short safe token usable bare in WHERE clauses and URLs.
sub _chat_valid_name {
    my ($n) = @_;
    return defined $n && $n =~ /\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z/;
}

# May $principal administer $session_row (edit/close/manage membership)?
# Loopback is trusted as an admin (matches net-mgr's loopback model);
# otherwise only the creator or an 'owner'-role member qualifies.
sub _chat_may_admin {
    my ($self, $cli, $session_row, $principal) = @_;
    return 1 if _peer_is_loopback($cli);
    return 0 unless defined $principal;
    return 1 if $session_row->{created_by} eq $principal;
    my $m = $self->{db}->get_chat_member($session_row->{name}, $principal);
    return $m && $m->{role} eq 'owner';
}

# Add this connection to a session's live roster + emit to subscribers.
sub _chat_presence_add {
    my ($self, $cli, $session, $principal) = @_;
    my $conn_id = fileno($cli->{sock});
    return unless defined $conn_id;
    my $r = $self->{db}->upsert_chat_presence(
        session => $session, conn_id => $conn_id, principal => $principal);
    $self->_emit_change(table => 'chat_presence', op => $r->{op}, row => $r->{now})
        if $r->{op} ne 'noop' && $r->{now};
}

sub _handle_chat_open {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my ($who) = $self->_chat_identity($cli, $kv);
    return $self->_send($cli, format_err("CHAT_OPEN: not authorized"))
        unless defined $who;
    my $name = $kv->{name};
    return $self->_send($cli, format_err("CHAT_OPEN: bad/missing name="))
        unless _chat_valid_name($name);
    my $mode = $kv->{mode} // 'open';
    return $self->_send($cli, format_err("CHAT_OPEN: bad mode '$mode'"))
        unless $mode =~ /\A(open|list|request)\z/;

    # A previously-closed session is reopened (not rejected as 'exists') by an
    # owner/admin — otherwise CHAT_CLOSE is irreversible and follow/post stay
    # blocked forever. mode/topic are updated only if explicitly supplied.
    if (my $existing = $self->{db}->get_chat_session($name)) {
        if ($existing->{status} eq 'closed') {
            return $self->_send($cli,
                format_err("CHAT_OPEN: not authorized to reopen '$name'"))
                unless $self->_chat_may_admin($cli, $existing, $who);
            # Resurrect archived messages back into the DB before reopening.
            eval { $self->_chat_restore($name) };
            $self->_log("chat resurrect $name failed: $@") if $@;
            my $rr = $self->{db}->reopen_chat_session($name,
                (defined $kv->{mode}  ? (access_mode => $mode)        : ()),
                (defined $kv->{topic} ? (topic       => $kv->{topic}) : ()));
            $self->_emit_change(table => 'chat_sessions', op => 'update',
                                row => $rr->{now}) if $rr->{now};
            $self->_log("chat reopen $name by $who");
            return $self->_send($cli, format_ok(name => $name,
                mode => ($rr->{now}{access_mode} // $mode),
                status => 'open', reopened => 1));
        }
        return $self->_send($cli, format_err("CHAT_OPEN: session '$name' exists"));
    }

    my $r = eval {
        $self->{db}->open_chat_session(
            name => $name, created_by => $who,
            access_mode => $mode, topic => $kv->{topic});
    };
    return $self->_send($cli, format_err("CHAT_OPEN: $@")) if $@;
    return $self->_send($cli, format_err("CHAT_OPEN: session '$name' exists"))
        if $r->{op} eq 'exists';

    # Creator becomes owner-member, then stream both new rows.
    my $m = $self->{db}->set_chat_member(
        session => $name, principal => $who, role => 'owner',
        state => 'member', added_by => $who);
    $self->_emit_change(table => 'chat_sessions', op => 'insert', row => $r->{now});
    $self->_emit_change(table => 'chat_members',  op => 'insert', row => $m->{now})
        if $m->{now};
    $self->_log("chat open $name by $who mode=$mode");
    $self->_send($cli, format_ok(name => $name, mode => $mode));
}

sub _handle_chat_set {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my ($who) = $self->_chat_identity($cli, $kv);
    my $name = $kv->{name};
    my $s = $self->{db}->get_chat_session($name)
        or return $self->_send($cli, format_err("CHAT_SET: no such session '".($name//'')."'"));
    return $self->_send($cli, format_err("CHAT_SET: not authorized"))
        unless $self->_chat_may_admin($cli, $s, $who);
    if (defined $kv->{mode} && $kv->{mode} !~ /\A(open|list|request)\z/) {
        return $self->_send($cli, format_err("CHAT_SET: bad mode '$kv->{mode}'"));
    }
    my $r = eval {
        $self->{db}->set_chat_session(
            name => $name,
            (defined $kv->{mode}  ? (access_mode => $kv->{mode})  : ()),
            (exists  $kv->{topic} ? (topic       => $kv->{topic}) : ()));
    };
    return $self->_send($cli, format_err("CHAT_SET: $@")) if $@;
    $self->_emit_change(table => 'chat_sessions', op => 'update', row => $r->{now})
        if $r->{now};
    $self->_send($cli, format_ok(name => $name));
}

sub _handle_chat_close {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my ($who) = $self->_chat_identity($cli, $kv);
    my $name = $kv->{name};
    my $s = $self->{db}->get_chat_session($name)
        or return $self->_send($cli, format_err("CHAT_CLOSE: no such session '".($name//'')."'"));
    return $self->_send($cli, format_err("CHAT_CLOSE: not authorized"))
        unless $self->_chat_may_admin($cli, $s, $who);

    # Move the messages out of the DB into the on-disk archive (kept until
    # explicitly deleted). The chat_sessions row stays so owners can find and
    # resurrect it. If archiving fails, abort the close — don't lose messages.
    my $dir = eval { $self->_chat_archive($name, $s) };
    if ($@) {
        my $e = $@; $e =~ s/\s+\z//;
        $self->_log("chat close $name: archive FAILED: $e");
        return $self->_send($cli, format_err("CHAT_CLOSE: archive failed: $e"));
    }

    my $r = $self->{db}->close_chat_session($name);
    $self->_emit_change(table => 'chat_sessions', op => 'update', row => $r->{now})
        if $r->{now};
    $self->_log("chat close $name by ".($who//'?')." -> $dir");
    $self->_send($cli, format_ok(name => $name, status => 'closed', archive => $dir));
}

sub _chat_archive_base {
    my ($self) = @_;
    return $self->{config}{chat}{archive_dir} // '/var/lib/net-mgr/chat';
}

# Serialize a session's messages (+ metadata + members) to its archive
# directory, then delete the message rows from the DB. Returns the directory.
sub _chat_archive {
    my ($self, $name, $s) = @_;
    my $base     = $self->_chat_archive_base;
    my $messages = $self->{db}->get_chat_messages($name);
    # Guard: never overwrite a non-empty archive with an empty one (e.g. a
    # chat closed again with 0 live messages). Keep the existing archive.
    if (!@$messages && NetMgr::ChatArchive::has_archive($base, $name)) {
        $self->_log("chat close $name: 0 live messages, keeping existing archive");
        return NetMgr::ChatArchive::dir($base, $name);
    }
    my $members  = $self->{db}->dbh->selectall_arrayref(
        "SELECT * FROM chat_members WHERE session = ?", { Slice => {} }, $name);
    my $dir = NetMgr::ChatArchive::write_archive($base, $s, $members, $messages);
    $self->{db}->delete_chat_messages($name);
    return $dir;
}

# CHAT_DELETE name=N — owner-only, destructive: remove the chat's whole archive
# directory and its DB rows (members/messages/presence cascade off the session).
sub _handle_chat_delete {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my ($who) = $self->_chat_identity($cli, $kv);
    my $name = $kv->{name};
    my $s = $self->{db}->get_chat_session($name)
        or return $self->_send($cli,
            format_err("CHAT_DELETE: no such session '" . ($name // '') . "'"));
    return $self->_send($cli, format_err("CHAT_DELETE: not authorized"))
        unless $self->_chat_may_admin($cli, $s, $who);

    eval { NetMgr::ChatArchive::delete_archive($self->_chat_archive_base, $name) };
    $self->_log("chat delete $name: archive rm failed: $@") if $@;
    $self->{db}->delete_chat_session($name);
    $self->_emit_change(table => 'chat_sessions', op => 'delete', row => $s);
    $self->_log("chat delete $name by " . ($who // '?'));
    $self->_send($cli, format_ok(name => $name, deleted => 1));
}

# Resurrect: pull archived messages back into the DB (only when the session has
# none live, so a reopen can't duplicate them). Ids/ts are preserved.
sub _chat_restore {
    my ($self, $name) = @_;
    my $base = $self->_chat_archive_base;
    return unless NetMgr::ChatArchive::has_archive($base, $name);
    my ($have) = $self->{db}->dbh->selectrow_array(
        "SELECT COUNT(*) FROM chat_messages WHERE session = ?", undef, $name);
    return if $have;
    my $msgs = NetMgr::ChatArchive::read_messages($base, $name);
    # session isn't stored per-message (it's the archive dir); supply it here.
    $self->{db}->restore_chat_message(%$_, session => $name) for @$msgs;
    $self->_log("chat resurrect $name: restored " . scalar(@$msgs) . " message(s)");
}

# May $who post to / upload to / read files of session $s? Open sessions are
# public for AUTHED principals; unverified principals (self-asserted names with
# no cryptographic backing) must be explicit members regardless of access_mode,
# so an unauthed visitor can browse + request but can't speak in 'open' chats
# until a member admits them. Loopback bypasses (local human / local agent).
sub _chat_may_post {
    my ($self, $cli, $s, $who) = @_;
    return 1 if _peer_is_loopback($cli);
    return 0 unless defined $who;
    my $is_unverified = ($who =~ /^unverified:/);
    return 1 if $s->{access_mode} eq 'open' && !$is_unverified;
    my $m = $self->{db}->get_chat_member($s->{name}, $who);
    return $m && $m->{state} eq 'member';
}

sub _human_size {
    my ($n) = @_;
    return "$n B" if $n < 1024;
    my @u = ('KB', 'MB', 'GB', 'TB');
    my ($v, $i) = ($n, -1);
    do { $v /= 1024; $i++ } while ($v >= 1024 && $i < $#u);
    return sprintf("%.1f %s", $v, $u[$i]);
}

# Resolve session + authorize for a file op; returns ($session_row, $who) or
# sends an ERR and returns () on failure.
sub _chat_file_auth {
    my ($self, $cli, $verb, $kv) = @_;
    my ($who) = $self->_chat_identity($cli, $kv);
    my $name = $kv->{session};
    unless (defined $name && length $name) {
        $self->_send($cli, format_err("$verb: missing session=")); return;
    }
    my $s = $self->{db}->get_chat_session($name);
    unless ($s) {
        $self->_send($cli, format_err("$verb: no such session '$name'")); return;
    }
    unless ($self->_chat_may_post($cli, $s, $who)) {
        $self->_send($cli, format_err("$verb: not authorized")); return;
    }
    return ($s, $who);
}

# CHAT_PUT session=N file=F offset=O [eof=1] data=base64 — write a file chunk
# into the chat's files/ dir. On eof, post a system message announcing it.
sub _handle_chat_put {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my ($s, $who) = $self->_chat_file_auth($cli, 'CHAT_PUT', $kv) or return;
    my $name = $s->{name};
    return $self->_send($cli, format_err("CHAT_PUT: session '$name' is closed"))
        if $s->{status} eq 'closed';
    my $file = $kv->{file};
    return $self->_send($cli, format_err("CHAT_PUT: missing file="))
        unless defined $file && length $file;

    my $path = eval { NetMgr::ChatArchive::file_path($self->_chat_archive_base, $name, $file) };
    return $self->_send($cli, format_err("CHAT_PUT: $@")) if $@;

    my $offset = $kv->{offset} // 0;
    require MIME::Base64;
    my $data = defined $kv->{data} ? MIME::Base64::decode_base64($kv->{data}) : '';

    my $mode = ($offset == 0) ? '>' : '+<';
    open my $fh, $mode, $path
        or return $self->_send($cli, format_err("CHAT_PUT: open $path: $!"));
    binmode $fh;
    seek($fh, $offset, 0) if $offset;
    print {$fh} $data;
    truncate($fh, $offset + length($data)) if $kv->{eof};   # drop any stale tail
    close $fh;

    unless ($kv->{eof}) {
        return $self->_send($cli, format_ok(session => $name, file => $file,
            offset => $offset + length($data)));
    }

    my $size = -s $path;
    my $msg = $self->{db}->insert_chat_message(
        session => $name, sender => 'system', sender_kind => 'system',
        body => ($who // 'someone') . " uploaded $file (" . _human_size($size) . ")");
    $self->{db}->touch_chat_activity($name);
    $self->_emit_change(table => 'chat_messages', op => 'insert', row => $msg);
    $self->_log("chat put $name/$file by " . ($who // '?') . " ($size bytes)");
    $self->_send($cli, format_ok(session => $name, file => $file, size => $size));
}

# CHAT_GET session=N file=F [offset=O] — return a base64 chunk; the reply
# carries size/offset/eof so the client can loop.
sub _handle_chat_get {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my ($s, $who) = $self->_chat_file_auth($cli, 'CHAT_GET', $kv) or return;
    my $name = $s->{name};
    my $file = $kv->{file};
    return $self->_send($cli, format_err("CHAT_GET: missing file="))
        unless defined $file && length $file;
    my $path = eval { NetMgr::ChatArchive::file_path($self->_chat_archive_base, $name, $file) };
    return $self->_send($cli, format_err("CHAT_GET: $@")) if $@;
    return $self->_send($cli, format_err("CHAT_GET: no such file '$file'")) unless -f $path;

    my $offset = $kv->{offset} // 0;
    my $total  = -s $path;
    open my $fh, '<', $path
        or return $self->_send($cli, format_err("CHAT_GET: open $path: $!"));
    binmode $fh;
    seek($fh, $offset, 0);
    my $got = read($fh, my $buf, 48 * 1024);
    close $fh;
    $buf = '' unless defined $got;
    my $eof = ($offset + length($buf) >= $total) ? 1 : 0;
    require MIME::Base64;
    $self->_send($cli, format_ok(session => $name, file => $file, size => $total,
        offset => $offset, eof => $eof,
        data => MIME::Base64::encode_base64($buf, '')));
}

# CHAT_LS session=N — list uploaded files (base64 JSON: [{name,size,mtime},…]).
sub _handle_chat_ls {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my ($s) = $self->_chat_file_auth($cli, 'CHAT_LS', $kv) or return;
    my $name = $s->{name};
    my $files = NetMgr::ChatArchive::list_files($self->_chat_archive_base, $name);
    require MIME::Base64;
    require JSON::PP;
    my $json = JSON::PP->new->canonical->encode($files);
    $self->_send($cli, format_ok(session => $name, count => scalar(@$files),
        files => MIME::Base64::encode_base64($json, '')));
}

# CHAT_RM session=N file=F — delete one uploaded file (posting ACL, like
# upload). Posts a system message announcing the removal.
sub _handle_chat_rm {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my ($s, $who) = $self->_chat_file_auth($cli, 'CHAT_RM', $kv) or return;
    my $name = $s->{name};
    my $file = $kv->{file};
    return $self->_send($cli, format_err("CHAT_RM: missing file="))
        unless defined $file && length $file;

    my $removed = eval {
        NetMgr::ChatArchive::delete_file($self->_chat_archive_base, $name, $file) };
    return $self->_send($cli, format_err("CHAT_RM: $@")) if $@;
    return $self->_send($cli, format_err("CHAT_RM: no such file '$file'"))
        unless $removed;

    my $msg = $self->{db}->insert_chat_message(
        session => $name, sender => 'system', sender_kind => 'system',
        body => ($who // 'someone') . " deleted $file");
    $self->{db}->touch_chat_activity($name);
    $self->_emit_change(table => 'chat_messages', op => 'insert', row => $msg);
    $self->_log("chat rm $name/$file by " . ($who // '?'));
    $self->_send($cli, format_ok(session => $name, file => $file, deleted => 1));
}

sub _handle_chat_join {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my ($who, $kind) = $self->_chat_identity($cli, $kv);
    return $self->_send($cli, format_err("CHAT_JOIN: not authorized (no identity)"))
        unless defined $who;
    my $name = $kv->{session} // $kv->{name};
    my $s = $self->{db}->get_chat_session($name)
        or return $self->_send($cli, format_err("CHAT_JOIN: no such session '".($name//'')."'"));
    return $self->_send($cli, format_err("CHAT_JOIN: session '$name' is closed"))
        if $s->{status} eq 'closed';

    my $mode      = $s->{access_mode};
    my $existing  = $self->{db}->get_chat_member($name, $who);
    my $is_member  = $existing && $existing->{state} eq 'member';
    my $is_invited = $existing && $existing->{state} eq 'invited';
    my $is_admin   = $self->_chat_may_admin($cli, $s, $who);
    # A key on the chat's persistent authorized-key list joins automatically,
    # even if its live member row is gone (e.g. roster cleared, or it was an
    # owner pre-load via CHAT_ALLOW <key_id>).
    my $key_ok = (($kind // '') eq 'agent'
                  && $self->{db}->get_chat_authorized_key($name, $who)) ? 1 : 0;

    # Unverified principals (unauthed remote with as=NAME) ALWAYS go through
    # the request flow, even on mode=open. mode=open means "any authed user may
    # join without per-session approval" — that trust premise doesn't apply to
    # a self-asserted name with no cryptographic backing.
    my $unverified = (($kind // '') eq 'unverified');
    unless ($is_member || $is_invited || $is_admin || $key_ok
            || ($mode eq 'open' && !$unverified)) {
        # Not authorized yet. Rather than a flat reject, record a join request
        # and notify owners + active members (anyone subscribed WHERE state=
        # "requested" gets the approval pop-up). Approving saves the key (see
        # _handle_chat_member_op), so the next join is automatic. Applies to
        # 'list', 'request', and an unverified user on 'open'.
        #
        # An optional pubkey kv lets the requester include their SSH public key
        # ("ssh-ed25519 AAAA... [comment]"). On approval that pubkey moves into
        # chat_authorized_keys; the user's next connect can AUTH with the
        # matching private key (chat-key fallthrough, NetMgr::Auth) and is
        # auto-admitted without a second ask. Only accepted for unverified
        # joins (an already-authed user is already known by their key).
        my $req_pubkey = ($unverified && defined $kv->{pubkey}
                                      && length $kv->{pubkey})
                         ? _normalize_pubkey($kv->{pubkey}) : undef;
        my $m = $self->{db}->set_chat_member(
            session => $name, principal => $who, state => 'requested',
            added_by => $who, request_pubkey => $req_pubkey);
        $self->_emit_change(table => 'chat_members', op => 'update', row => $m->{now})
            if $m->{now};
        $self->_log("chat join-request $name by $who"
                  . ($req_pubkey ? " [+pubkey for durable auth]" : ""));
        return $self->_send($cli, format_ok(session => $name, state => 'requested'));
    }

    # Allowed: ensure a member row (idempotent) and add live presence.
    if (!$is_member) {
        my $m = $self->{db}->set_chat_member(
            session => $name, principal => $who, state => 'member', added_by => $who);
        $self->_emit_change(table => 'chat_members', op => 'update', row => $m->{now})
            if $m->{now};
    }
    $self->_chat_presence_add($cli, $name, $who);
    $self->_log("chat join $name by $who");
    $self->_send($cli, format_ok(session => $name, state => 'member'));
}

sub _handle_chat_leave {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my $name = $kv->{session} // $kv->{name};
    return $self->_send($cli, format_err("CHAT_LEAVE: missing session="))
        unless defined $name;
    my $conn_id = fileno($cli->{sock});
    my $row = defined $conn_id
        ? $self->{db}->delete_chat_presence($name, $conn_id) : undef;
    $self->_emit_change(table => 'chat_presence', op => 'delete', row => $row) if $row;
    $self->_send($cli, format_ok(session => $name));
}

# CHAT_ALLOW / DENY / APPROVE / REJECT — owner edits to the membership
# list. allow/approve → state 'member'; deny/reject → state 'denied'.
sub _handle_chat_member_op {
    my ($self, $cli, $cmd, $op) = @_;
    my $kv = $cmd->{kv} || {};
    my ($who) = $self->_chat_identity($cli, $kv);
    my $name = $kv->{session} // $kv->{name};
    my $principal = $kv->{principal};
    my $verb = "CHAT_" . uc $op;
    my $s = $self->{db}->get_chat_session($name)
        or return $self->_send($cli, format_err("$verb: no such session '".($name//'')."'"));
    # Admin can always; an ACTIVE MEMBER (currently present in the session) may
    # also admit/deny — that's the see-and-request feature: anyone in the chat
    # can let an unverified user in, not just the owner. Unverified principals
    # themselves cannot approve others (would be a self-elevation loop).
    my $is_admin_op = $self->_chat_may_admin($cli, $s, $who);
    my $is_active   = defined $who
                   && ($who !~ /^unverified:/)
                   && $self->_chat_is_active_member($name, $who);
    return $self->_send($cli, format_err("$verb: not authorized"))
        unless $is_admin_op || $is_active;
    return $self->_send($cli, format_err("$verb: missing principal="))
        unless defined $principal && length $principal;
    my $state = ($op eq 'allow' || $op eq 'approve') ? 'member' : 'denied';
    my $m = $self->{db}->set_chat_member(
        session => $name, principal => $principal, state => $state, added_by => $who);
    $self->_emit_change(table => 'chat_members', op => 'update', row => $m->{now})
        if $m->{now};

    # Persist (or revoke) the SSH key on the chat's durable authorized-key list
    # when the principal is a key fingerprint. Humans on loopback ('as' names)
    # have no key, so they're tracked by membership only.
    my ($ktype, $label) = $self->{db}->host_key_identity($principal);
    if ($ktype ne '' || $principal =~ /^SHA256:/) {
        if ($state eq 'member') {
            my $k = $self->{db}->add_chat_authorized_key(
                session => $name, key_id => $principal,
                key_type => $ktype, label => $label, added_by => $who);
            $self->_emit_change(table => 'chat_authorized_keys', op => 'update', row => $k)
                if $k;
        } else {
            my $had = $self->{db}->get_chat_authorized_key($name, $principal);
            $self->{db}->remove_chat_authorized_key($name, $principal);
            $self->_emit_change(table => 'chat_authorized_keys', op => 'delete', row => $had)
                if $had;
        }
    }

    # Durable chat-key auth: an UNVERIFIED requester who included their SSH
    # pubkey at request time gets that key persisted to chat_authorized_keys on
    # approval. The fingerprint becomes the durable key_id; the future AUTH
    # chat-key fallthrough (NetMgr::Auth) will recognise the key and auto-admit.
    # Reject/deny clears the pending pubkey so it isn't preserved across a
    # rejected request.
    if ($principal =~ /^unverified:/) {
        my $row = $self->{db}->get_chat_member($name, $principal);
        my $pk  = $row ? $row->{request_pubkey} : undef;
        if ($state eq 'member' && defined $pk && length $pk) {
            my ($fp, $ktyp2) = _pubkey_fingerprint($pk);
            if (defined $fp) {
                # Strip "unverified:" for the label so it reads cleanly in the
                # owner's key list ("Alice" rather than "unverified:Alice").
                (my $lbl = $principal) =~ s/^unverified://;
                my $k = $self->{db}->add_chat_authorized_key(
                    session => $name, key_id => $fp,
                    key_type => $ktyp2, label => $lbl,
                    added_by => $who, pubkey => $pk);
                $self->_emit_change(table => 'chat_authorized_keys',
                                    op => 'update', row => $k) if $k;
                $self->_log("chat $op $name: bound pubkey $fp to '$lbl'");
            } else {
                $self->_log("chat $op $name: pubkey on '$principal' "
                          . "didn't parse — skipped durable-key persist");
            }
        }
        # Clear the pending pubkey regardless of outcome (it's done its job, or
        # the request was denied and shouldn't linger).
        $self->{db}->clear_chat_member_request_pubkey($name, $principal);
    }
    $self->_log("chat $op $name principal=$principal by ".($who//'?'));
    $self->_send($cli, format_ok(session => $name, principal => $principal, state => $state));
}

# CHAT_KEYS session=N — list a chat's authorized SSH keys (owner only). Returns
# OK count=N keys=<base64 JSON [{key_id,key_type,label,added_by,added_at},…]>.
sub _handle_chat_keys {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my ($who) = $self->_chat_identity($cli, $kv);
    my $name = $kv->{session} // $kv->{name};
    my $s = $self->{db}->get_chat_session($name)
        or return $self->_send($cli, format_err("CHAT_KEYS: no such session '".($name//'')."'"));
    return $self->_send($cli, format_err("CHAT_KEYS: not authorized"))
        unless $self->_chat_may_admin($cli, $s, $who);
    my $keys = $self->{db}->list_chat_authorized_keys($name);
    require MIME::Base64;
    require JSON::PP;
    my $json = JSON::PP->new->canonical->encode($keys);
    $self->_send($cli, format_ok(session => $name, count => scalar(@$keys),
        keys => MIME::Base64::encode_base64($json, '')));
}

# OBSERVE kind=chat_msg session=N body="..." [in_reply_to=ID] [as=NAME]
# Posts one message. Identity is server-stamped from the verified key
# (or loopback `as`); a closed session or a non-member (on list/request
# sessions) is rejected. Returns no events — it does its own emit.
sub _obs_chat_msg {
    my ($self, $cli, $kv) = @_;
    my ($who, $kind) = $self->_chat_identity($cli, $kv);
    die "not authorized to post\n" unless defined $who;
    my $name = $kv->{session} // $kv->{name};
    my $body = $kv->{body};
    die "chat_msg: missing session=\n" unless defined $name && length $name;
    die "chat_msg: missing body=\n"    unless defined $body && length $body;
    my $s = $self->{db}->get_chat_session($name)
        or die "chat_msg: no such session '$name'\n";
    die "chat_msg: session '$name' is closed\n" if $s->{status} eq 'closed';

    # Mode=open is public for AUTHED principals; unverified principals must be
    # explicit members regardless (see _chat_may_post — same rule).
    my $is_unverified = ($who =~ /^unverified:/);
    if (($s->{access_mode} ne 'open' || $is_unverified)
        && !_peer_is_loopback($cli)) {
        my $m = $self->{db}->get_chat_member($name, $who);
        die "chat_msg: not a member of '$name'\n"
            unless $m && $m->{state} eq 'member';
    }

    my $row = $self->{db}->insert_chat_message(
        session => $name, sender => $who, sender_kind => $kind,
        body => $body, in_reply_to => $kv->{in_reply_to});
    $self->{db}->touch_chat_activity($name);
    $self->_emit_change(table => 'chat_messages', op => 'insert', row => $row);
    # Stream the bumped last_activity so session lists re-sort live.
    my $fresh = $self->{db}->get_chat_session($name);
    $self->_emit_change(table => 'chat_sessions', op => 'update', row => $fresh)
        if $fresh;
    return ();   # not a network event; no events-table row
}

# ---- DB-native DHCP plan: reservations + ranges ----------------------
#
# Writes require an authorized identity (a verified key or a loopback
# peer) — same trust model as the chat admin ops. The upserts go through
# _upsert so the change streams to the net-reserve GUI and the cluster
# relay carries it to peers. Deletes snapshot-then-emit like the other
# *_delete observers.

# Mirror INET_ATON for the /24 a reservation falls in, when the caller
# didn't pass subnet_cidr explicitly.
sub _dhcp_subnet_of {
    my ($ip) = @_;
    return undef unless defined $ip && $ip =~ /\A(\d+\.\d+\.\d+)\.\d+\z/;
    return "$1.0/24";
}

# OBSERVE kind=dhcp_reservation ip=.. mac=.. [name=..] [subnet_cidr=..]
#   [grp=..] [notes=..] [as=NAME]
sub _obs_dhcp_reservation {
    my ($self, $cli, $kv) = @_;
    my ($who) = $self->_chat_identity($cli, $kv);
    die "dhcp_reservation: not authorized\n" unless defined $who;
    my $ip  = $kv->{ip};
    my $mac = $kv->{mac};
    die "dhcp_reservation: ip required\n"  unless defined $ip  && length $ip;
    die "dhcp_reservation: mac required\n" unless defined $mac && length $mac;
    die "dhcp_reservation: bad ip '$ip'\n"
        unless $ip =~ /\A\d+\.\d+\.\d+\.\d+\z/;
    die "dhcp_reservation: bad mac '$mac'\n"
        unless $mac =~ /\A[0-9a-fA-F:]{17}\z/;
    # One reservation per MAC: refuse a NEW reservation for a device already
    # reserved at another address (it should be moved/released, not duplicated).
    # Updating the reservation already at this IP is fine, as is an explicit
    # force=1 (multi-homed edge cases).
    unless ($self->{db}->get_dhcp_reservation($ip) || $kv->{force}) {
        my $other = $self->{db}->dhcp_reservation_for_mac($mac);
        die "dhcp_reservation: $mac is already reserved at $other->{ip}"
          . (defined $other->{name} && length $other->{name} ? " ($other->{name})" : '')
          . " - move or release it first (or force=1)\n"
            if $other;
    }
    # Auto-name from the MAC's correlated machine when the caller gives no name,
    # so reservations don't sit nameless in dnsmasq/DNS.
    my $name = $kv->{name};
    $name = $self->{db}->name_for_mac($mac) if !defined $name || $name eq '';
    $self->_upsert('dhcp_reservations', 'upsert_dhcp_reservation',
        ip          => $ip,
        mac         => $mac,
        name        => $name,
        subnet_cidr => ($kv->{subnet_cidr} // _dhcp_subnet_of($ip)),
        grp         => $kv->{grp},
        notes       => $kv->{notes},
        updated_by  => $who,
    );
    $self->_log("dhcp reservation $ip -> $mac by $who");
    return ();
}

# OBSERVE kind=dhcp_reservation_delete ip=..
sub _obs_dhcp_reservation_delete {
    my ($self, $cli, $kv) = @_;
    my ($who) = $self->_chat_identity($cli, $kv);
    die "dhcp_reservation_delete: not authorized\n" unless defined $who;
    my $ip = $kv->{ip};
    die "dhcp_reservation_delete: ip required\n" unless defined $ip && length $ip;
    my $row = $self->{db}->delete_dhcp_reservation($ip);
    $self->_emit_change(table => 'dhcp_reservations', op => 'delete', row => $row)
        if $row;
    $self->_log("dhcp reservation delete $ip by $who") if $row;
    return ();
}

# OBSERVE kind=dhcp_reservation_move ip=OLD new_ip=NEW — reallocate an
# existing reservation to a different address, atomically, keeping its
# mac/name/group. Emits a delete of the old row + insert of the new.
sub _obs_dhcp_reservation_move {
    my ($self, $cli, $kv) = @_;
    my ($who) = $self->_chat_identity($cli, $kv);
    die "dhcp_reservation_move: not authorized\n" unless defined $who;
    my $old = $kv->{ip} // $kv->{old_ip};
    my $new = $kv->{new_ip};
    die "dhcp_reservation_move: ip (old) required\n" unless defined $old && length $old;
    die "dhcp_reservation_move: new_ip required\n"   unless defined $new && length $new;
    die "dhcp_reservation_move: bad new_ip '$new'\n"
        unless $new =~ /\A\d+\.\d+\.\d+\.\d+\z/;
    my $res = $self->{db}->move_dhcp_reservation($old, $new,
        subnet_cidr => _dhcp_subnet_of($new), updated_by => $who);
    die "dhcp_reservation_move: no reservation at '$old'\n" unless $res;
    die "dhcp_reservation_move: '$new' is already reserved\n" if $res->{error};
    $self->_emit_change(table => 'dhcp_reservations', op => 'delete', row => $res->{old})
        if $res->{old};
    $self->_emit_change(table => 'dhcp_reservations', op => 'insert', row => $res->{new})
        if $res->{new};
    $self->_log("dhcp reservation move $old -> $new by $who");
    return ();
}

# OBSERVE kind=dhcp_range subnet_cidr=.. start_ip=.. end_ip=.. [zone=..] [notes=..]
sub _obs_dhcp_range {
    my ($self, $cli, $kv) = @_;
    my ($who) = $self->_chat_identity($cli, $kv);
    die "dhcp_range: not authorized\n" unless defined $who;
    my $cidr  = $kv->{subnet_cidr};
    my $start = $kv->{start_ip};
    my $end   = $kv->{end_ip};
    die "dhcp_range: subnet_cidr required\n" unless defined $cidr  && length $cidr;
    die "dhcp_range: start_ip required\n"    unless defined $start && length $start;
    die "dhcp_range: end_ip required\n"      unless defined $end   && length $end;
    $self->_upsert('dhcp_ranges', 'upsert_dhcp_range',
        subnet_cidr => $cidr, start_ip => $start, end_ip => $end,
        zone => $kv->{zone}, notes => $kv->{notes});
    $self->_log("dhcp range $cidr $start-$end by $who");
    return ();
}

# OBSERVE kind=dhcp_range_delete subnet_cidr=.. start_ip=..
sub _obs_dhcp_range_delete {
    my ($self, $cli, $kv) = @_;
    my ($who) = $self->_chat_identity($cli, $kv);
    die "dhcp_range_delete: not authorized\n" unless defined $who;
    my ($cidr, $start) = ($kv->{subnet_cidr}, $kv->{start_ip});
    die "dhcp_range_delete: subnet_cidr + start_ip required\n"
        unless defined $cidr && defined $start;
    my $row = $self->{db}->delete_dhcp_range($cidr, $start);
    $self->_emit_change(table => 'dhcp_ranges', op => 'delete', row => $row)
        if $row;
    $self->_log("dhcp range delete $cidr $start by $who") if $row;
    return ();
}

# kind=regen_dnsmasq — the master (or an operator, e.g. `net-cluster regen`)
# tells this node to regenerate its own dnsmasq config from its DB replica and
# reload. Honoured only if [dnsmasq] mode isn't 'off' (i.e. this node manages a
# local dnsmasq). Forked + reaped like any trigger; a single regen at a time.
sub _obs_regen_dnsmasq {
    my ($self, $cli, $kv) = @_;
    my $mode = $self->{config}{dnsmasq}{mode} // 'off';
    if ($mode eq 'off') { $self->_log("regen_dnsmasq: ignored ([dnsmasq] mode=off)"); return () }
    my $bin = $self->_producer_path('net-gen-dnsmasq');
    unless ($bin && -x $bin) { $self->_log("regen_dnsmasq: net-gen-dnsmasq missing"); return () }
    if (grep { ($_->{name} // '') eq 'regen-dnsmasq' } values %{ $self->{triggers} }) {
        return ();   # one in flight already
    }
    my $pid = fork();
    return () unless defined $pid;
    if ($pid == 0) {
        for my $c (values %{ $self->{clients} }) { close $c->{sock} if $c->{sock} }
        close $self->{listen} if $self->{listen};
        $ENV{NET_MGR_LISTEN} = $self->_self_connect_addr;
        exec $bin, '--from-db', '--reload';
        exit 127;
    }
    $self->_log("regen_dnsmasq: net-gen-dnsmasq --from-db --reload pid=$pid (told by "
              . ($cli->{ident} // '?') . ")");
    $self->{triggers}{$pid} = { cli_fd => undef, name => 'regen-dnsmasq', started_at => time() };
    return ();
}

# kind=ap_exclude — set the per-AP host blacklist (space-separated globs of
# names NOT to push to that AP's DHCP static leases; net-push-ap reads it).
# '' clears it. Stored on aps.exclude, kept across AP rescans (upsert_ap only
# rewrites it when given). Replicates via the normal aps change stream.
sub _obs_ap_exclude {
    my ($self, $cli, $kv) = @_;
    my $mac = lc($kv->{mac} // '');
    die "ap_exclude: valid mac required\n"
        unless $mac =~ /^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/;
    $self->_upsert('aps', 'upsert_ap',
        mac => $mac, exclude => (defined $kv->{exclude} ? $kv->{exclude} : ''));
    $self->_log("ap_exclude $mac = '" . ($kv->{exclude} // '') . "'");
    return ();
}

# OBSERVE kind=he_net action=up|down — bring the HE 6in4 uplink up or down on
# demand. Params come from [ipv6_vlan], overridable per-call (server=, prefix=,
# local_suffix=, name=, ext_if=, forwarding=). Gated on /etc/net-mgr/
# allowed_internet (may_internet) — it runs `ip tunnel`/`sysctl` as root. Lets an
# operator establish the IPv6 uplink on a gateway over the mesh with no ssh, with
# a narrow per-capability grant (no full scope needed).
sub _obs_he_net {
    my ($self, $cli, $kv) = @_;
    # Gated on the dedicated allowed_internet capability (or loopback/local
    # root). Full scope is not required — this is a narrow, per-capability grant.
    unless (_peer_is_loopback($cli) || ($cli->{auth} && $cli->{auth}{may_internet})) {
        die "he_net: not authorized (add the key to /etc/net-mgr/allowed_internet)\n";
    }
    my $name = $kv->{name} // 'he_net';
    my $e = ($self->{config}{ipv6_vlan} || {})->{$name} || {};
    # Fill anything missing from mesh_tunnels (the cluster-replicated table is
    # the durable source of truth; config-file keys override; OBSERVE kv still
    # overrides everything below).
    $e = $self->_merge_tunnel_from_db($name, $e);
    my $action = $kv->{action} // 'up';
    if ($action eq 'down') {
        NetMgr::Tunnel::down(name => $name, log => sub { $self->_log($_[0]) });
        return ();
    }
    my ($addr, $err) = NetMgr::Tunnel::up(
        name         => $name,
        server       => $kv->{server}       // $e->{server},
        prefix       => $kv->{prefix}       // $e->{prefix},
        local_suffix => $kv->{local_suffix} // $e->{local_suffix} // '2',
        forwarding   => (defined $kv->{forwarding} ? $kv->{forwarding}
                                                   : (defined $e->{forwarding} ? $e->{forwarding} : 1)),
        ext_if       => (($kv->{ext_if} // $e->{ext_if}) || undef),
        log          => sub { $self->_log($_[0]) },
    );
    die "he_net: $err\n" if $err;
    $self->_log("he_net: up via OBSERVE — local6=$addr");
    return ();
}

# OBSERVE kind=he_update — push the current WAN IPv4 to HE on demand (over the
# mesh). Same auth gate as he_net (may_internet), and the same secret-store path
# — useful to force a refresh after fixing a stale registration, or as the manual
# poke when [ddns] isn't watching the WAN interface. Without name=NAME refreshes
# every configured he6in4; with name=NAME refreshes just that one.
sub _obs_he_update {
    my ($self, $cli, $kv) = @_;
    unless (_peer_is_loopback($cli) || ($cli->{auth} && $cli->{auth}{may_internet})) {
        die "he_update: not authorized (add the key to /etc/net-mgr/allowed_internet)\n";
    }
    # Master-routed form: target=<owner_node> means "I am that owner, you have
    # the secret — please fire the curl on my behalf, with myip=<my WAN>".
    # The master looks up the row for the target in mesh_tunnels, reads its
    # local secret (named in mesh_tunnels.secret_name), and calls curl with
    # the supplied myip so HE registers the TARGET's WAN, not the master's.
    if (my $target = $kv->{target}) {
        my $kind = $kv->{tunnel_kind} // 'he6in4';
        my $row  = $self->{db}->get_mesh_tunnel($target, $kind)
            or die "he_update: no mesh_tunnels row for owner=$target kind=$kind\n";
        my %e = (
            tunnel_id     => $row->{provider_id},
            update_secret => $row->{secret_name},
            myip          => $kv->{myip},
        );
        die "he_update: row for $target has no provider_id\n"
            unless defined $e{tunnel_id} && length $e{tunnel_id};
        die "he_update: row for $target has no secret_name\n"
            unless defined $e{update_secret} && length $e{update_secret};
        $self->_he_update_endpoint($kv->{name} // 'he_net', \%e);
        return ();
    }
    if (my $name = $kv->{name}) {
        my $e = ($self->{config}{ipv6_vlan} || {})->{$name}
            or die "he_update: no [ipv6_vlan '$name']\n";
        $self->_he_update_endpoint($name, $e);
    } else {
        $self->_he_update_endpoints;
    }
    return ();
}

# OBSERVE kind=mesh_tunnel — write/delete a row of the cluster-replicated
# mesh_tunnels table (tunnel topology — server/prefixes/provider_id per owner).
# Required: action (set|delete), owner_node, kind. For set: any of provider_id,
# server_v4, tunnel_prefix, routed_prefix, notes (the upsert preserves columns
# not supplied — partial updates are allowed). Auth-gated on may_update (same
# trust as code/config writes — this IS a config write, just routed via DB
# instead of a file). Loopback exempt. Emits a row event so replication picks
# it up; followers get the change automatically.
sub _obs_publish_self {
    my ($self, $cli, $kv) = @_;
    # Any verified peer can publish ITS OWN inventory. Same trust as any
    # other producer writing addresses — the source tag carries the
    # publisher's name so reviewers can see who claimed what. Loopback
    # exempt (local register_self uses _apply_self_inventory directly,
    # but the OBSERVE path also has to be usable from local tools).
    unless (_peer_is_loopback($cli) || ($cli->{auth} && $cli->{auth}{verified})) {
        die "publish_self: not authorized (verified peer required)\n";
    }
    my $b64 = $kv->{inv_b64};
    die "publish_self: missing inv_b64\n" unless defined $b64 && length $b64;
    require MIME::Base64;
    require JSON::PP;
    my $json = MIME::Base64::decode_base64($b64);
    my $inv  = eval { JSON::PP->new->decode($json) };
    die "publish_self: bad inventory blob: $@\n" if $@ || ref($inv) ne 'HASH';
    die "publish_self: missing host\n"
        unless defined $inv->{host} && length $inv->{host};
    die "publish_self: missing ifaces\n"
        unless ref($inv->{ifaces}) eq 'ARRAY';
    $self->_apply_self_inventory($inv);
    my $n = scalar @{ $inv->{ifaces} || [] };
    my $who = ($cli->{auth} && $cli->{auth}{key_id}) // 'loopback';
    $self->_log("publish_self: applied inventory for '$inv->{host}' ($n ifaces) from $who");
    return ();
}

sub _obs_mesh_tunnel {
    my ($self, $cli, $kv) = @_;
    unless (_peer_is_loopback($cli) || ($cli->{auth} && $cli->{auth}{may_update})) {
        die "mesh_tunnel: not authorized (add the key to /etc/net-mgr/allowed_updaters)\n";
    }
    my $action = $kv->{action} // 'set';
    my $owner  = $kv->{owner_node};
    # Row column is called 'kind', but the OBSERVE dispatch key is ALSO 'kind' —
    # so the row kind arrives as 'tunnel_kind' here to avoid collision.
    my $tkind  = $kv->{tunnel_kind} // $kv->{row_kind};
    die "mesh_tunnel: owner_node required\n" unless defined $owner && length $owner;
    die "mesh_tunnel: tunnel_kind required\n" unless defined $tkind && length $tkind;
    if ($action eq 'delete') {
        my $was = $self->{db}->get_mesh_tunnel($owner, $tkind);
        $self->{db}->delete_mesh_tunnel($owner, $tkind);
        $self->_emit_change(table => 'mesh_tunnels', op => 'delete', row => $was)
            if $was;
        $self->_log("mesh_tunnel: delete owner=$owner kind=$tkind");
        return ({ type => 'mesh_tunnel_delete', owner_node => $owner, kind => $tkind });
    }
    # _upsert wraps upsert_mesh_tunnel and emits a 'mesh_tunnels' change event
    # so any subscriber (the followers' net-mgr-relay processes) receives the
    # new/updated row in their snapshot+stream session.
    my $r = $self->_upsert('mesh_tunnels', 'upsert_mesh_tunnel',
        owner_node    => $owner,
        kind          => $tkind,
        provider_id   => $kv->{provider_id},
        server_v4     => $kv->{server_v4},
        tunnel_prefix => $kv->{tunnel_prefix},
        routed_prefix => $kv->{routed_prefix},
        notes         => $kv->{notes},
        secret_name   => $kv->{secret_name},
    );
    my $row = $r->{now} || {};
    $self->_log("mesh_tunnel: set owner=$owner kind=$tkind"
              . ($kv->{provider_id}    ? " provider_id=$kv->{provider_id}"      : "")
              . ($kv->{server_v4}      ? " server_v4=$kv->{server_v4}"          : "")
              . ($kv->{tunnel_prefix}  ? " tunnel_prefix=$kv->{tunnel_prefix}"  : "")
              . ($kv->{routed_prefix}  ? " routed_prefix=$kv->{routed_prefix}"  : ""));
    return ({ type => 'mesh_tunnel_set',
              owner_node => $owner, kind => $tkind,
              map { $_ => $row->{$_} }
                  qw(provider_id server_v4 tunnel_prefix routed_prefix) });
}

# OBSERVE kind=write_config — write to a TIGHTLY BOUNDED set of net-mgr config
# paths over the mesh. Designed for the rare case where you need to land a
# config/secret on a node you can't ssh to (a gateway, a roaming follower).
#
# CONSTRAINTS — anything outside is rejected:
#   - path is exactly one of:
#       /etc/net-mgr/config                        (mode 644 default)
#       /etc/net-mgr/config.d/<name>.conf          (mode 644 default)
#       /etc/net-mgr/secrets/<name>                (mode 600 default; refuses other modes)
#       /etc/net-mgr/allowed_<cap>                 (mode 644 default)
#   - <name>/<cap> are [A-Za-z0-9._-]+ (no path traversal). Symlinks at the
#     destination are refused (we won't write THROUGH a symlink as root).
#   - content arrives base64-encoded (kv-safe across the protocol).
#
# AUTH — gated on may_update, same as kind=deploy/self_update (anyone you trust
# to push code is trusted to push config; we don't widen the trust surface).
# Loopback is exempt.
#
# SAFETY — atomic: writes to <path>.tmp.<pid>, fsync, rename into place. The
# previous content is preserved at <path>.bak for manual rollback. The SECRET
# VALUE is never logged; only path + sha1 of the new bytes + size + peer ID.
#
# Returns kv: path, sha1, size, mode, backup. The caller checks `sha1` against
# the local file to confirm the bytes landed verbatim.
sub _obs_write_config {
    my ($self, $cli, $kv) = @_;
    unless (_peer_is_loopback($cli) || ($cli->{auth} && $cli->{auth}{may_update})) {
        die "write_config: not authorized (add the key to /etc/net-mgr/allowed_updaters)\n";
    }
    my $path = $kv->{path} // '';
    my ($ok, $err, $default_mode) = _validate_write_config_path($path);
    die "write_config: $err\n" unless $ok;
    my $mode = $kv->{mode};
    if (defined $mode && length $mode) {
        $mode =~ /^0?[0-7]{3,4}$/ or die "write_config: bad mode '$mode'\n";
        $mode = oct($mode);
    } else {
        $mode = $default_mode;
    }
    # Secrets are mode 600 — refuse looser modes silently widening the surface.
    if ($path =~ m{^/etc/net-mgr/secrets/} && ($mode & 077)) {
        die sprintf("write_config: secret '%s' refuses mode 0%o — must be 0600\n", $path, $mode);
    }
    my $b64 = $kv->{content_b64};
    die "write_config: missing content_b64\n" unless defined $b64 && length $b64;
    require MIME::Base64;
    my $content = MIME::Base64::decode_base64($b64);
    die "write_config: empty decoded content\n" unless length $content;
    die "write_config: content too large (>1 MiB)\n" if length($content) > 1024*1024;

    require Digest::SHA;
    my $sha = Digest::SHA::sha1_hex($content);

    # If a symlink already lives at $path, refuse — we won't follow it as root.
    if (-l $path) { die "write_config: '$path' is a symlink (refused)\n" }

    # Atomic write: tmp + fsync + rename. Keep a .bak of the previous bytes.
    my $tmp = "$path.tmp.$$";
    my $bak = "$path.bak";
    require File::Path;
    my ($dir) = $path =~ m{^(.+)/[^/]+$};
    File::Path::make_path($dir, { mode => 0755 }) if $dir && !-d $dir;

    if (-e $path && !-l $path) {
        # best-effort backup; failure to backup is NOT fatal — but logged.
        if (system('cp', '-a', '--', $path, $bak) != 0) {
            $self->_log("write_config: could not back up '$path' to '$bak' (continuing)");
        }
    }
    open(my $fh, '>', $tmp) or die "write_config: open $tmp: $!\n";
    binmode($fh);
    print $fh $content or do { close $fh; unlink $tmp; die "write_config: write $tmp: $!\n" };
    $fh->flush;
    # fsync — guard against power loss between rename and content hitting disk.
    eval { require IO::Handle; $fh->sync };
    close $fh or do { unlink $tmp; die "write_config: close $tmp: $!\n" };
    chmod $mode, $tmp or do { unlink $tmp; die "write_config: chmod $tmp: $!\n" };
    rename($tmp, $path) or do { unlink $tmp; die "write_config: rename $tmp -> $path: $!\n" };

    my $who = $cli->{auth} ? ($cli->{auth}{key_id} // 'auth') : 'loopback';
    $self->_log(sprintf("write_config: %s wrote %s (%d bytes, sha1=%s, mode=0%o)",
                       $who, $path, length($content), $sha, $mode));
    $self->_send($cli, format_ok(
        path   => $path,
        sha1   => $sha,
        size   => length($content),
        mode   => sprintf('0%o', $mode),
        backup => (-e $bak ? $bak : ''),
    ));
    return ();
}

# Allow-list policy for write_config. Returns ($ok, $err, $default_mode).
# Reject any path that doesn't match one of the four patterns above. The
# patterns are exact strings/regexes — no globbing, no wildcards, no ../.
sub _validate_write_config_path {
    my ($path) = @_;
    return (0, "missing path") unless defined $path && length $path;
    return (0, "path must be absolute") unless $path =~ m{^/};
    return (0, "path contains '..'")    if index($path, '/../') >= 0 || $path =~ m{/\.\.$};
    return (0, "path contains '//'")    if index($path, '//')  >= 0;

    return (1, undef, 0644) if $path eq '/etc/net-mgr/config';
    return (1, undef, 0644) if $path =~ m{^/etc/net-mgr/config\.d/[A-Za-z0-9._-]+\.conf$};
    return (1, undef, 0600) if $path =~ m{^/etc/net-mgr/secrets/[A-Za-z0-9._-]+$};
    return (1, undef, 0644) if $path =~ m{^/etc/net-mgr/allowed_[a-z_]+$};
    # Per-host deploy overlay: /etc/net-mgr/deploy/<HOST>/<FILE>. The host
    # owning this overlay tree (typically nas3) rsyncs its contents to the
    # leaf during `make install-on`. Lets the deploy hub author config for
    # leaves that have no repo / no write_config trust of their own.
    # <HOST> is a hostname (alnum + dot/dash); <FILE> is one of the same
    # things this allow-list accepts for /etc/net-mgr/ directly.
    return (1, undef, 0644)
        if $path =~ m{^/etc/net-mgr/deploy/[A-Za-z0-9][A-Za-z0-9.-]*/
                       (?: config
                         | config\.d/[A-Za-z0-9._-]+\.conf
                         | allowed_[a-z_]+
                       )$}x;
    return (1, undef, 0600)
        if $path =~ m{^/etc/net-mgr/deploy/[A-Za-z0-9][A-Za-z0-9.-]*/
                       secrets/[A-Za-z0-9._-]+$}x;
    return (0, "path '$path' not in the write_config allow-list");
}

# OBSERVE kind=relay action=up — set up a type=relay IPv6 network on demand (a
# global address from the routed prefix on the control VLAN / LAN, and ::/0 via
# the uplink unless this node IS the uplink). Params from kv: prefix (routed /64),
# gateway (the uplink's DMZ IPv4), name. Gated on may_internet, like he_net —
# lets an operator stand up the relay on a gateway/node over the mesh, no ssh.
sub _obs_relay {
    my ($self, $cli, $kv) = @_;
    unless (_peer_is_loopback($cli) || ($cli->{auth} && $cli->{auth}{may_internet})) {
        die "relay: not authorized (add the key to /etc/net-mgr/allowed_internet)\n";
    }
    my $name = $kv->{name} // 'he_net_relay';
    $self->_attach_relay_network($name, {
        type    => 'relay',
        prefix  => $kv->{prefix},
        gateway => $kv->{gateway},
    });
    return ();
}

# ---- OBSERVE dispatch ------------------------------------------------

sub _handle_observe {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my $kind = $kv->{kind} // '';
    my @events;
    eval {
        if    ($kind eq 'ap_self')     { @events = $self->_obs_ap_self($cli, $kv) }
        elsif ($kind eq 'association') { @events = $self->_obs_association($cli, $kv) }
        elsif ($kind eq 'arp')         { @events = $self->_obs_arp($cli, $kv) }
        elsif ($kind eq 'lease')       { @events = $self->_obs_lease($cli, $kv) }
        elsif ($kind eq 'host')        { @events = $self->_obs_host($cli, $kv) }
        elsif ($kind eq 'ssh_host_key'){ @events = $self->_obs_ssh_host_key($cli, $kv) }
        elsif ($kind eq 'port')        { @events = $self->_obs_port($cli, $kv) }
        elsif ($kind eq 'ping')        { @events = $self->_obs_ping($cli, $kv) }
        elsif ($kind eq 'link')        { @events = $self->_obs_link($cli, $kv) }
        elsif ($kind eq 'isp_link')    { @events = $self->_obs_isp_link($cli, $kv) }
        elsif ($kind eq 'isp_secret')  { @events = $self->_obs_isp_secret($cli, $kv) }
        elsif ($kind eq 'isp_link_delete')
                                       { @events = $self->_obs_isp_link_delete($cli, $kv) }
        elsif ($kind eq 'lost_device_delete')
                                       { @events = $self->_obs_lost_device_delete($cli, $kv) }
        elsif ($kind eq 'peer_cap_set')
                                       { @events = $self->_obs_peer_cap_set($cli, $kv) }
        elsif ($kind eq 'peer_cap_clear')
                                       { @events = $self->_obs_peer_cap_clear($cli, $kv) }
        elsif ($kind eq 'event')       { @events = $self->_obs_event($cli, $kv) }
        elsif ($kind eq 'forward')     { @events = $self->_obs_forward($cli, $kv) }
        elsif ($kind eq 'chat_msg')    { @events = $self->_obs_chat_msg($cli, $kv) }
        elsif ($kind eq 'dhcp_reservation')
                                       { @events = $self->_obs_dhcp_reservation($cli, $kv) }
        elsif ($kind eq 'dhcp_reservation_delete')
                                       { @events = $self->_obs_dhcp_reservation_delete($cli, $kv) }
        elsif ($kind eq 'dhcp_reservation_move')
                                       { @events = $self->_obs_dhcp_reservation_move($cli, $kv) }
        elsif ($kind eq 'dhcp_range')  { @events = $self->_obs_dhcp_range($cli, $kv) }
        elsif ($kind eq 'dhcp_range_delete')
                                       { @events = $self->_obs_dhcp_range_delete($cli, $kv) }
        elsif ($kind eq 'ap_exclude')  { @events = $self->_obs_ap_exclude($cli, $kv) }
        elsif ($kind eq 'regen_dnsmasq'){ @events = $self->_obs_regen_dnsmasq($cli, $kv) }
        elsif ($kind eq 'self_update') { @events = $self->_obs_self_update($cli, $kv) }
        elsif ($kind eq 'deploy')      { @events = $self->_obs_deploy($cli, $kv) }
        elsif ($kind eq 'he_net')      { @events = $self->_obs_he_net($cli, $kv) }
        elsif ($kind eq 'he_update')   { @events = $self->_obs_he_update($cli, $kv) }
        elsif ($kind eq 'write_config'){ @events = $self->_obs_write_config($cli, $kv) }
        elsif ($kind eq 'mesh_tunnel') { @events = $self->_obs_mesh_tunnel($cli, $kv) }
        elsif ($kind eq 'publish_self'){ @events = $self->_obs_publish_self($cli, $kv) }
        elsif ($kind eq 'relay')       { @events = $self->_obs_relay($cli, $kv) }
        else {
            die "unknown observation kind '$kind'\n";
        }
    };
    if ($@) {
        my $err = $@; chomp $err;
        $self->_send($cli, format_err($err));
        $self->_log("err observe from $cli->{ident}: $err");
        return;
    }
    for my $e (@events) {
        $self->_log_event(%$e);
    }
    $self->_send($cli, format_ok());
}

sub _handle_gone {
    my ($self, $cli, $cmd) = @_;
    my $kv = $cmd->{kv} || {};
    my $mac = $kv->{mac};
    return $self->_send($cli, format_err("GONE needs mac=")) unless $mac;
    my $r = $self->_upsert('interfaces', 'upsert_interface',
                           mac => $mac, online => 0);
    if ($r->{op} eq 'update' && grep { $_ eq 'online' } @{ $r->{changed_fields} }) {
        $self->_log_event(type => 'interface_offline', mac => $mac);
    }
    $self->_send($cli, format_ok());
}

# Look up or create a machine identified by name and link an interface
# to it. Adds the (machine_id, name, source) tuple to hostnames. Used
# whenever a producer reports a hostname for a MAC (DHCP lease,
# AP self-name, future SSH-fingerprint).
#
# Auto-correlation rule 1 from the design memo: two interfaces that
# report the same name → same machine.
sub _associate_machine {
    my ($self, $mac, $name, $source) = @_;
    return unless defined $mac && defined $name && length $name && $name ne '*';
    $mac = lc $mac;
    my $iface = $self->{db}->get_interface_by_mac($mac);
    return unless $iface;

    my $mid = $iface->{machine_id};
    if (!$mid) {
        my ($existing) = $self->{db}->dbh->selectrow_array(
            "SELECT id FROM machines WHERE primary_name = ? LIMIT 1",
            undef, $name);
        if ($existing) {
            $mid = $existing;
        } else {
            my $r = $self->_upsert('machines', 'upsert_machine',
                primary_name => $name, online => 1);
            $mid = $r->{now}{id};
        }
        $self->_upsert('interfaces', 'upsert_interface',
            mac => $mac, machine_id => $mid);
    } else {
        # The machine exists but may be nameless (e.g. first seen by a portless
        # scan). Adopt this name as its primary_name when nothing better is set —
        # use the device's own (DHCP) name if none other is given.
        my ($pn) = $self->{db}->dbh->selectrow_array(
            "SELECT primary_name FROM machines WHERE id = ?", undef, $mid);
        $self->_upsert('machines', 'upsert_machine', id => $mid, primary_name => $name)
            unless defined $pn && length $pn;
    }
    $self->_upsert('hostnames', 'upsert_hostname',
        machine_id => $mid, name => $name, source => $source);
    return $mid;
}

# ---- per-kind observation handlers -----------------------------------

# Returns: list of event hashrefs to log.
sub _events_from_iface_change {
    my ($r, $extra_addr) = @_;
    my @ev;
    if ($r->{op} eq 'insert') {
        push @ev, { type => 'interface_new', mac => $r->{now}{mac},
                    addr => $extra_addr };
        if ($r->{now}{online}) {
            push @ev, { type => 'interface_online', mac => $r->{now}{mac},
                        addr => $extra_addr };
        }
    } elsif ($r->{op} eq 'update'
             && grep { $_ eq 'online' } @{ $r->{changed_fields} }) {
        push @ev, {
            type => $r->{now}{online} ? 'interface_online' : 'interface_offline',
            mac  => $r->{now}{mac},
            addr => $extra_addr,
        };
    }
    return @ev;
}

sub _events_for_addr_op {
    my ($a, $mac, $ip) = @_;
    return () unless ref $a;
    my @ev;
    push @ev, { type => 'address_added', mac => $mac, addr => $ip }
        if ($a->{op} // '') eq 'insert';
    push @ev, { type => 'address_removed', mac => $_, addr => $ip,
                reason => 'superseded' }
        for @{ $a->{superseded} // [] };
    return @ev;
}

sub _obs_ap_self {
    my ($self, $cli, $kv) = @_;
    my $mac = $kv->{mac} or die "ap_self: mac required (br0 not parsed?)\n";
    my @ev;
    my $iface = $self->_upsert('interfaces', 'upsert_interface',
        mac => $mac, kind => 'wifi', online => 1, live => 1);
    push @ev, _events_from_iface_change($iface, $kv->{ip});

    if ($kv->{ip}) {
        my $a = $self->_upsert('addresses', 'upsert_address',
            mac => $mac, family => 'v4', addr => $kv->{ip}, live => 1,
            defined $kv->{source} ? (source => $kv->{source}) : ());
        push @ev, _events_for_addr_op($a, $mac, $kv->{ip});
    }
    $self->_upsert('aps', 'upsert_ap',
        mac => $mac, ssid => $kv->{ssid},
        model => $kv->{model}, board => $kv->{board});
    # Promote the AP's router_name to a machine identity.
    $self->_associate_machine($mac, $kv->{name}, 'ap') if $kv->{name};
    return @ev;
}

sub _obs_association {
    my ($self, $cli, $kv) = @_;
    my $client_mac = $kv->{client_mac} or die "association: client_mac required\n";
    my $ap_ip      = $kv->{ap_ip};
    my @ev;

    my $iface = $self->_upsert('interfaces', 'upsert_interface',
        mac => $client_mac, kind => 'wifi', online => 1, live => 1);
    push @ev, _events_from_iface_change($iface);

    # Resolve ap_ip → ap_mac via aps/addresses join.
    my $ap_mac;
    if ($ap_ip) {
        my $row = $self->{db}->dbh->selectrow_array(
            "SELECT a.mac FROM aps a
               JOIN addresses ad ON ad.mac = a.mac
              WHERE ad.addr = ? LIMIT 1", undef, $ap_ip);
        $ap_mac = $row;
    }
    if ($ap_mac) {
        my $r = $self->_upsert('associations', 'upsert_association',
            ap_mac     => $ap_mac,
            client_mac => $client_mac,
            iface      => $kv->{iface},
            signal     => $kv->{signal},
            ssid       => $kv->{ssid},
        );
        if ($r->{op} eq 'insert') {
            push @ev, { type => 'ap_associated', mac => $client_mac,
                        details => qq({"ap_mac":"$ap_mac"}) };
        }
    }
    return @ev;
}

sub _obs_arp {
    my ($self, $cli, $kv) = @_;
    my $mac = $kv->{mac} or die "arp: mac required\n";
    my $ip  = $kv->{ip}  or die "arp: ip required\n";
    my @ev;
    my $iface = $self->_upsert('interfaces', 'upsert_interface',
        mac => $mac, kind => 'ethernet', online => 1, live => 1);
    push @ev, _events_from_iface_change($iface, $ip);
    my $a = $self->_upsert('addresses', 'upsert_address',
        mac => $mac, family => 'v4', addr => $ip, live => 1,
        defined $kv->{source} ? (source => $kv->{source}) : ());
    push @ev, _events_for_addr_op($a, $mac, $ip);
    return @ev;
}

sub _obs_lease {
    my ($self, $cli, $kv) = @_;
    my $mac = $kv->{mac} or die "lease: mac required\n";
    my $ip  = $kv->{ip}  or die "lease: ip required\n";
    my @ev;
    my $iface = $self->_upsert('interfaces', 'upsert_interface',
        mac => $mac, online => 1, live => 1);
    push @ev, _events_from_iface_change($iface, $ip);
    my $a = $self->_upsert('addresses', 'upsert_address',
        mac => $mac, family => 'v4', addr => $ip, live => 1,
        defined $kv->{source} ? (source => $kv->{source}) : ());
    push @ev, _events_for_addr_op($a, $mac, $ip);
    $self->_upsert('dhcp_leases', 'upsert_lease',
        mac      => $mac,
        ip       => $ip,
        hostname => $kv->{hostname},
        expires  => $kv->{expires},
    );
    # DHCP-supplied hostname → machine identity.
    $self->_associate_machine($mac, $kv->{hostname}, 'dhcp')
        if $kv->{hostname};
    return @ev;
}

sub _obs_host {
    my ($self, $cli, $kv) = @_;
    # generic host observation (e.g. from net-discover or net-import-dhcp)
    my $mac = $kv->{mac};
    my $ip  = $kv->{ip};
    my @ev;
    if ($mac) {
        # Only mark online for *live* observations. Imports from
        # dhcp.master / dhcp.extra are paper records — they don't
        # prove the device is currently reachable.
        my $src = $kv->{source} // '';
        # Liveness: an explicit live=0/1 wins — net-reserve --push pushes
        # reservations as paper records (known MAC<->name<->IP, but no proof
        # the device is up right now). Otherwise fall back to the source
        # heuristic: file imports (dhcp.master/extra) are paper, anything
        # else is a live sighting.
        my $is_live = defined $kv->{live} ? ($kv->{live} ? 1 : 0)
                    : ($src !~ /:dhcp\.(master|extra)$/);
        my %iface_args = (
            mac    => $mac,
            kind   => $kv->{iface_kind} // 'ethernet',
            vendor => $kv->{vendor},
        );
        if ($is_live) { $iface_args{online} = 1; $iface_args{live} = 1 }
        my $iface = $self->_upsert('interfaces', 'upsert_interface', %iface_args);
        push @ev, _events_from_iface_change($iface, $ip);
        if ($ip) {
            my $a = $self->_upsert('addresses', 'upsert_address',
                mac => $mac, family => $kv->{family} // 'v4', addr => $ip,
                ($is_live ? (live => 1) : ()),
                defined $kv->{source} ? (source => $kv->{source}) : ());
            push @ev, _events_for_addr_op($a, $mac, $ip);
        }
        # Producer supplied a hostname (e.g. dhcp.master importer) →
        # promote to a machine identity. name_source classifies the
        # hostnames row ('dhcp.master', 'dhcp.extra', 'config', ...).
        if ($kv->{name}) {
            $self->_associate_machine(
                $mac, $kv->{name}, $kv->{name_source} // 'config');
        }
    }
    return @ev;
}

# Find or create a machine by primary_name; returns its id. Used when we know
# the name but not (yet) a MAC to link — e.g. net-ssh recording a host key
# against the alias it just connected to.
sub _machine_id_for_name {
    my ($self, $name) = @_;
    return undef unless defined $name && length $name;
    my ($id) = $self->{db}->dbh->selectrow_array(
        "SELECT id FROM machines WHERE primary_name = ? LIMIT 1", undef, $name);
    return $id if $id;
    my $r = $self->_upsert('machines', 'upsert_machine',
        primary_name => $name, online => 1);
    return $r->{now}{id};
}

# kind=ssh_host_key key_id=SHA256:... [key_type=ed25519] [ip=IP] [mac=MAC]
#                   [name=NAME] [name_source=...] [source=...]
# Record an SSH host key against a machine. A host key is stable per machine,
# so a fingerprint we've seen before identifies the host even on a new IP/MAC.
# Machine resolution, strongest first: an explicit name (net-ssh knows the
# alias) wins; else a previously-recorded machine for this fingerprint (the
# floating-IP case); else the MAC's current machine. When mac+ip are present we
# also refresh their liveness, like a host observation.
sub _obs_ssh_host_key {
    my ($self, $cli, $kv) = @_;
    my $key_id = $kv->{key_id} or die "ssh_host_key: key_id required\n";
    my $mac    = $kv->{mac} ? lc $kv->{mac} : undef;
    my $ip     = $kv->{ip};
    my @ev;

    if ($mac && $ip) {
        my $iface = $self->_upsert('interfaces', 'upsert_interface',
            mac => $mac, kind => $kv->{iface_kind} // 'ethernet',
            online => 1, live => 1);
        push @ev, _events_from_iface_change($iface, $ip);
        my $a = $self->_upsert('addresses', 'upsert_address',
            mac => $mac, family => $kv->{family} // 'v4', addr => $ip, live => 1,
            defined $kv->{source} ? (source => $kv->{source}) : ());
        push @ev, _events_for_addr_op($a, $mac, $ip);
    }

    my $known = $self->{db}->host_key_machine($key_id);
    my $mid;
    if ($kv->{name}) {
        $mid = $self->_machine_id_for_name($kv->{name});
        $self->_associate_machine($mac, $kv->{name},
            $kv->{name_source} // 'ssh-hostkey') if $mac;
    } elsif ($known) {
        # Seen this key before → same machine, wherever it is now.
        $mid = $known;
        if ($mac) {
            my ($pname) = $self->{db}->dbh->selectrow_array(
                "SELECT primary_name FROM machines WHERE id = ?", undef, $known);
            $self->_associate_machine($mac, $pname, 'ssh-hostkey')
                if defined $pname && length $pname;
        }
    } elsif ($mac) {
        my $iface = $self->{db}->get_interface_by_mac($mac);
        $mid = $iface->{machine_id} if $iface && $iface->{machine_id};
    }

    $self->{db}->upsert_host_key(
        key_id => $key_id, key_type => $kv->{key_type}, machine_id => $mid);
    return @ev;
}

sub _obs_forward {
    my ($self, $cli, $kv) = @_;
    my $direction = uc($kv->{direction} // '');
    die "forward: direction must be L/R/D\n" unless $direction =~ /^[LRD]$/;
    die "forward: source_host required\n"    unless $kv->{source_host};
    die "forward: bind_port required\n"      unless defined $kv->{bind_port};

    my $bind_addr = $kv->{bind_addr};
    $bind_addr = '*' if !defined $bind_addr || $bind_addr eq '';

    # Check for existence to pick the right op for downstream subscribers.
    # upsert_forwarding_rule uses INSERT ... ON DUPLICATE KEY UPDATE and
    # returns the post-write row; we just need was-or-wasn't here.
    my $existed = $self->{db}->dbh->selectrow_array(
        "SELECT 1 FROM forwarding_rules
          WHERE source_host = ? AND direction = ?
            AND bind_addr   = ? AND bind_port = ?",
        undef, $kv->{source_host}, $direction, $bind_addr, $kv->{bind_port}
    );

    my $row = $self->{db}->upsert_forwarding_rule(
        source      => $kv->{source}      // 'ssh',
        source_host => $kv->{source_host},
        source_pid  => $kv->{source_pid},
        direction   => $direction,
        bind_addr   => $bind_addr,
        bind_port   => $kv->{bind_port},
        target_host => $kv->{target_host},
        target_port => $kv->{target_port},
        ssh_user    => $kv->{ssh_user},
        ssh_host    => $kv->{ssh_host},
        ssh_port    => $kv->{ssh_port},
        notes       => $kv->{notes},
    );
    $self->_emit_change(
        table => 'forwarding_rules',
        op    => $existed ? 'update' : 'insert',
        row   => $row,
    ) if $row;
    return;
}

sub _obs_port {
    my ($self, $cli, $kv) = @_;
    my $mac  = $kv->{mac}  or die "port: mac required\n";
    my $port = $kv->{port}; defined $port or die "port: port required\n";
    my @ev;
    my $r = $self->_upsert('ports', 'upsert_port',
        mac => $mac, port => $port,
        proto => $kv->{proto} // 'tcp',
        service => $kv->{service},
    );
    if ($r->{op} eq 'insert') {
        push @ev, { type => 'port_opened', mac => $mac,
                    details => qq({"port":$port}) };
    }
    return @ev;
}

# Threshold for emitting ping_slow: rtt must be at least 5× the
# known minimum AND at least 50ms above it. Both gates: avoids
# false positives on tiny baselines (1ms × 5 = 5ms isn't really
# "slow") and on large stable baselines (100ms × 1.5 isn't a spike).
use constant PING_SLOW_RATIO => 5.0;
use constant PING_SLOW_MIN_DELTA_MS => 50.0;

sub _obs_ping {
    my ($self, $cli, $kv) = @_;
    my $mac    = $kv->{mac}    or die "ping: mac required\n";
    my $addr   = $kv->{addr}   or die "ping: addr required\n";
    my $rtt    = $kv->{rtt_ms};
    die "ping: rtt_ms required\n" unless defined $rtt;
    die "ping: rtt_ms not numeric\n" unless $rtt =~ /^\d+(?:\.\d+)?$/;
    my $loss = $kv->{loss_pct};
    if (defined $loss) {
        die "ping: loss_pct not numeric\n" unless $loss =~ /^\d+(?:\.\d+)?$/;
    }

    my %args = (mac => $mac, addr => $addr, family => 'v4', rtt_ms => $rtt);
    $args{loss_pct} = $loss if defined $loss;
    my $r = $self->{db}->update_rtt(%args);
    return unless $r->{found};   # row missing — silent no-op (producer bug)

    # update_rtt writes directly (not via _upsert) so it doesn't auto-
    # broadcast to subscribers. Emit explicitly so net-watch and other
    # streaming consumers see the new last_rtt_ms / min_rtt_ms.
    my $row = $self->{db}->dbh->selectrow_hashref(
        "SELECT * FROM addresses WHERE mac = ? AND family = 'v4' AND addr = ?",
        undef, lc $mac, $addr
    );
    $self->_emit_change(table => 'addresses', op => 'update', row => $row)
        if $row;

    my @ev;

    # Successful ping = the interface is reachable. Flip online=1 if it
    # wasn't already; the interface_online event fires on the offline→
    # online transition (paired with the interface_offline that GONE
    # emits when all of a mac's addresses go silent). Without this,
    # a host that recovered would never log a "came back" event.
    my $iface = $self->_upsert('interfaces', 'upsert_interface',
        mac => $mac, online => 1, live => 1);
    push @ev, _events_from_iface_change($iface, $addr);

    # Emit ping_slow only on the OK→slow transition so a sustained
    # slowness doesn't generate one event per probe. The transition
    # check uses prev_last (the rtt from the previous ping cycle) —
    # if it was already slow, we already emitted then.
    my $min  = $r->{prev_min};
    my $prev = $r->{prev_last};
    if (defined $min && $min > 0
        && $rtt > PING_SLOW_RATIO * $min
        && ($rtt - $min) > PING_SLOW_MIN_DELTA_MS
        && !(defined $prev
             && $prev > PING_SLOW_RATIO * $min
             && ($prev - $min) > PING_SLOW_MIN_DELTA_MS))
    {
        push @ev, {
            type => 'ping_slow',
            mac  => $mac,
            addr => $addr,
            details => sprintf('{"min_rtt_ms":%.3f,"rtt_ms":%.3f}', $min, $rtt),
        };
    }

    return @ev;
}

# kind=link mac=NAME link_speed_mbps=N — push interface link rate.
# Source is sysfs (/sys/class/net/$IF/speed) for wired, iw for wifi;
# producer is bin/net-link-stats. Silent no-op if the interface row
# doesn't exist yet (the producer should know its own MACs).
sub _obs_link {
    my ($self, $cli, $kv) = @_;
    my $mac = $kv->{mac} or die "link: mac required\n";
    my $sp  = $kv->{link_speed_mbps};
    die "link: link_speed_mbps required\n" unless defined $sp;
    die "link: link_speed_mbps not an integer\n" unless $sp =~ /^-?\d+$/;
    my $rows = $self->{db}->update_link_speed(
        mac => $mac, link_speed_mbps => $sp + 0
    );
    if ($rows) {
        # Re-fetch + emit so streaming consumers see the new value.
        my $row = $self->{db}->dbh->selectrow_hashref(
            "SELECT * FROM interfaces WHERE mac = ?", undef, lc $mac
        );
        $self->_emit_change(table => 'interfaces', op => 'update', row => $row)
            if $row;
    }
    return ();
}

# kind=isp_link gateway=NAME isp=NAME [iface=...] [mac=...] [auth_type=...]
#   [auth_user=...] [status=active|standby|broken|unknown] [notes=...]
# Records that a gateway machine connects (or could connect) to a
# given ISP via the named iface, with the listed credentials. Public-
# readable. Resolves the gateway name → machine_id by primary_name.
sub _obs_isp_link {
    my ($self, $cli, $kv) = @_;
    my $gw  = $kv->{gateway} or die "isp_link: gateway required\n";
    my $isp = $kv->{isp}     or die "isp_link: isp required\n";
    my $mid = $self->_machine_id_by_name($gw)
        or die "isp_link: no machine named '$gw'\n";
    my $r = $self->_upsert('isp_links', 'upsert_isp_link',
        gateway_machine_id => $mid,
        isp_name           => $isp,
        iface              => $kv->{iface},
        mac                => $kv->{mac},
        auth_type          => $kv->{auth_type},
        auth_user          => $kv->{auth_user},
        status             => $kv->{status},
        notes              => $kv->{notes},
    );
    return ();
}

# kind=isp_link_delete gateway=NAME isp=NAME — removes the link
# (and via FK CASCADE, any matching secret).
sub _obs_isp_link_delete {
    my ($self, $cli, $kv) = @_;
    my $gw  = $kv->{gateway} or die "isp_link_delete: gateway required\n";
    my $isp = $kv->{isp}     or die "isp_link_delete: isp required\n";
    my $mid = $self->_machine_id_by_name($gw)
        or die "isp_link_delete: no machine named '$gw'\n";
    # Snapshot the row first so we can emit a delete event.
    my $row = $self->{db}->dbh->selectrow_hashref(
        "SELECT * FROM isp_links
          WHERE gateway_machine_id = ? AND isp_name = ?",
        undef, $mid, $isp
    );
    $self->{db}->delete_isp_link(gateway_machine_id => $mid, isp_name => $isp);
    $self->_emit_change(table => 'isp_links', op => 'delete', row => $row)
        if $row;
    return ();
}

# kind=isp_secret gateway=NAME isp=NAME secret=PASS — stores or
# updates the credential. Restricted: requires either a loopback
# peer or an authenticated connection (matching the SUBSCRIBE gate
# on isp_secrets).
sub _obs_isp_secret {
    my ($self, $cli, $kv) = @_;
    unless ($self->_auth_is_full($cli)) {
        die "isp_secret: requires full-scope AUTH (or loopback peer)\n";
    }
    my $gw     = $kv->{gateway} or die "isp_secret: gateway required\n";
    my $isp    = $kv->{isp}     or die "isp_secret: isp required\n";
    my $secret = $kv->{secret};
    die "isp_secret: secret required\n" unless defined $secret;
    my $mid = $self->_machine_id_by_name($gw)
        or die "isp_secret: no machine named '$gw'\n";
    # The corresponding isp_links row must exist (FK).
    my ($exists) = $self->{db}->dbh->selectrow_array(
        "SELECT 1 FROM isp_links
          WHERE gateway_machine_id = ? AND isp_name = ?",
        undef, $mid, $isp
    );
    die "isp_secret: no isp_link for $gw/$isp (create with isp_link first)\n"
        unless $exists;
    $self->{db}->upsert_isp_secret(
        gateway_machine_id => $mid,
        isp_name           => $isp,
        auth_secret        => $secret,
    );
    return ();
}

# kind=lost_device_delete subnet=CIDR mac=MAC — clears the
# lost_devices row that net-find-lost created. Used by the recovery
# scripts after they've put a wandering device back at its proper
# IP, so the device doesn't keep showing on the "Lost devices"
# page.
sub _obs_lost_device_delete {
    my ($self, $cli, $kv) = @_;
    my $subnet = $kv->{subnet} or die "lost_device_delete: subnet required\n";
    my $mac    = $kv->{mac}    or die "lost_device_delete: mac required\n";
    # Snapshot the row first so we can broadcast a delete event.
    my $row = $self->{db}->dbh->selectrow_hashref(
        "SELECT * FROM lost_devices WHERE subnet = ? AND mac = ?",
        undef, $subnet, lc $mac
    );
    $self->{db}->delete_lost_device(subnet => $subnet, mac => $mac);
    $self->_emit_change(table => 'lost_devices', op => 'delete', row => $row)
        if $row;
    return ();
}

# kind=peer_cap_set peer=NAME caps=cap1,cap2[,...] — grant the
# listed capabilities to a peer in THIS daemon's local authority
# table. Persisted to /etc/net-mgr/peers. Requires AUTH (or
# loopback) because changing who can be master is a privileged op.
sub _obs_peer_cap_set {
    my ($self, $cli, $kv) = @_;
    unless ($self->_auth_is_full($cli)) {
        die "peer_cap_set: requires full-scope AUTH (or loopback peer)\n";
    }
    my $peer = $kv->{peer} or die "peer_cap_set: peer required\n";
    die "peer_cap_set: bad peer name '$peer'\n"
        unless $peer =~ /^[\w.-]+$/;
    my $caps = _split_caps($kv->{caps});
    $self->{cluster}{peer_caps}{$peer} = $caps;
    my $err = _write_peers_file($self->{cluster}{peers_file},
                                $self->{cluster}{peer_caps});
    die "peer_cap_set: write failed: $err\n" if $err;
    $self->_log("peer_cap_set $peer = " . join(',', @$caps));
    return ();
}

# kind=peer_cap_clear peer=NAME — remove the peer from this
# daemon's local authority table entirely. Same auth gate.
sub _obs_peer_cap_clear {
    my ($self, $cli, $kv) = @_;
    unless ($self->_auth_is_full($cli)) {
        die "peer_cap_clear: requires full-scope AUTH (or loopback peer)\n";
    }
    my $peer = $kv->{peer} or die "peer_cap_clear: peer required\n";
    delete $self->{cluster}{peer_caps}{$peer};
    my $err = _write_peers_file($self->{cluster}{peers_file},
                                $self->{cluster}{peer_caps});
    die "peer_cap_clear: write failed: $err\n" if $err;
    $self->_log("peer_cap_clear $peer");
    return ();
}

# Atomic rewrite of the peers file. Writes to a sibling tempfile
# and renames over the target, so a partial write can never leave
# a corrupt table. Existing comments / formatting in the file are
# NOT preserved — the daemon owns this file when it's writing it.
# Operator hand-edits should happen with the daemon down (and would
# need to be re-checked against any in-memory state on restart).
# Returns undef on success, an error string otherwise.
sub _write_peers_file {
    my ($path, $caps) = @_;
    my $tmp = "$path.tmp.$$";
    open my $fh, '>', $tmp or return "open $tmp: $!";
    print $fh "# /etc/net-mgr/peers — local authority table\n";
    print $fh "# managed by net-mgr (OBSERVE kind=peer_cap_set/clear)\n";
    print $fh "# format: name: cap1, cap2, ...\n\n";
    for my $name (sort keys %$caps) {
        my $list = join(', ', @{ $caps->{$name} || [] });
        printf $fh "%-20s: %s\n", $name, $list;
    }
    close $fh or return "close $tmp: $!";
    chmod 0644, $tmp;
    rename $tmp, $path or return "rename $tmp $path: $!";
    return undef;
}

sub _machine_id_by_name {
    my ($self, $name) = @_;
    my ($id) = $self->{db}->dbh->selectrow_array(
        "SELECT id FROM machines WHERE primary_name = ? LIMIT 1",
        undef, $name
    );
    return $id;
}

# Lets clients persist arbitrary events without DB credentials. Used by
# net-roam to record wifi_deauth (so the next run can honor a cooldown).
# The dispatch loop in _handle_observe runs returned events through
# _log_event, which writes the row and broadcasts to subscribers.
sub _obs_event {
    my ($self, $cli, $kv) = @_;
    my $type = $kv->{type} or die "event: type required\n";
    return ({
        type    => $type,
        mac     => $kv->{mac},
        addr    => $kv->{addr},
        details => $kv->{details},
    });
}

# ---- dnsmasq event-socket listeners ----------------------------------
#
# Each --event-listen=HOST:PORT-equipped dnsmasq we can reach gets a
# persistent TCP connection from inside this daemon. Sockets are added
# to the same IO::Select that handles client traffic, so events flow
# through the existing main-loop dispatch with no extra threads.

use IO::Socket::INET ();

# Periodic: scan the DB for hosts likely to be running dnsmasq (port
# 53 or 67 known open) and try to connect to their event-listen port,
# default 7532. Re-attempt every minute by default; once attached the
# socket stays in select() forever.
sub _check_dnsmasq_listeners {
    my ($self) = @_;
    my $cfg = $self->{config}{scanner} // {};
    my $port  = $cfg->{dnsmasq_event_port}           // 7532;
    my $every = $cfg->{dnsmasq_event_check_interval} // 60;
    my $now = time();
    $self->{periodic_last} //= {};
    return if ($now - ($self->{periodic_last}{dnsmasq_listeners} // 0)) < $every;
    $self->{periodic_last}{dnsmasq_listeners} = $now;

    my $rows = $self->{db}->dbh->selectall_arrayref(<<'SQL', { Slice => {} });
        SELECT DISTINCT a.addr
          FROM addresses a
          JOIN ports     p ON p.mac = a.mac
         WHERE a.family = 'v4'
           AND p.port IN (53, 67)
SQL
    for my $r (@$rows) {
        my $key = "$r->{addr}:$port";
        next if $self->{dnsmasq_listeners}{$key};
        $self->_try_connect_dnsmasq($r->{addr}, $port);
    }
}

sub _try_connect_dnsmasq {
    my ($self, $host, $port) = @_;
    my $sock = IO::Socket::INET->new(
        PeerAddr => $host, PeerPort => $port,
        Proto    => 'tcp', Timeout => 1,
    );
    return unless $sock;
    $sock->blocking(0);
    my $key = "$host:$port";
    $self->{dnsmasq_listeners}{$key} = {
        sock => $sock, host => $host, port => $port, buffer => '',
    };
    $self->{select}->add($sock);
    $self->_log("dnsmasq listener attached to $key");
}

sub _drop_dnsmasq_listener {
    my ($self, $key) = @_;
    my $L = delete $self->{dnsmasq_listeners}{$key} // return;
    $self->{select}->remove($L->{sock});
    eval { $L->{sock}->close };
    $self->_log("dnsmasq listener dropped from $key");
}

sub _handle_dnsmasq_data {
    my ($self, $key) = @_;
    my $L = $self->{dnsmasq_listeners}{$key} or return;
    my $buf;
    my $n = sysread $L->{sock}, $buf, 4096;
    if (!defined $n || $n == 0) {
        $self->_drop_dnsmasq_listener($key);
        return;
    }
    $L->{buffer} .= $buf;
    while ($L->{buffer} =~ s/^([^\n]*)\n//) {
        $self->_process_dnsmasq_event($1, $key);
    }
}

# Wire format from src/event-socket.c in our patched dnsmasq:
#   EVENT action=<add|del|old|have> ts=<unix> mac=<hex:..> ip=<v4|v6>
#         hostname=<name>
sub _process_dnsmasq_event {
    my ($self, $line, $key) = @_;
    return unless $line =~ /^EVENT\s/;
    my %kv;
    while ($line =~ /\b([\w-]+)=(\S+)/g) { $kv{$1} = $2 }
    my $action = $kv{action} // '';
    my $mac    = $kv{mac};
    my $ip     = $kv{ip};
    return unless $mac && $ip;

    my @ev;
    if ($action =~ /^(?:add|old|have)$/) {
        my $iface = $self->_upsert('interfaces', 'upsert_interface',
            mac => $mac, online => 1, live => 1);
        push @ev, _events_from_iface_change($iface, $ip);
        my $a = $self->_upsert('addresses', 'upsert_address',
            mac => $mac, family => ($ip =~ /:/ ? 'v6' : 'v4'),
            addr => $ip, live => 1, source => "$key:dnsmasq");
        push @ev, _events_for_addr_op($a, $mac, $ip);
        $self->_upsert('dhcp_leases', 'upsert_lease',
            mac      => $mac,
            ip       => $ip,
            hostname => $kv{hostname},
        );
        $self->_associate_machine($mac, $kv{hostname}, 'dhcp')
            if $kv{hostname};
    }
    elsif ($action eq 'del') {
        my $r = $self->_upsert('interfaces', 'upsert_interface',
            mac => $mac, online => 0);
        if ($r->{op} eq 'update'
            && grep { $_ eq 'online' } @{ $r->{changed_fields} })
        {
            push @ev, { type => 'interface_offline', mac => $mac };
        }
    }
    $self->_log_event(%$_) for @ev;
}

# ---- forward backend (iptables / socat) -----------------------------
#
# Two implementations behind one interface so the FORWARD verb doesn't
# care which is in use. Iptables is preferred when available because
# it's stateless from the daemon's POV (one rule, no child process to
# supervise). Socat is the no-root fallback.
#
# Forward record shape:
#   { method => 'iptables',
#     slot   => 5901,
#     target => '192.168.15.104:5900',
#     cookie => 'net-mgr:fwd:42:5901',   # iptables comment marker
#   }
#   { method => 'socat',
#     slot   => 5901,
#     target => '192.168.15.104:5900',
#     pid    => 12345,
#   }

sub _forward_method {
    my ($self) = @_;
    return $self->{_fwd_method_cache}
        if exists $self->{_fwd_method_cache};

    # Allow explicit pin via [forward] method = iptables|socat in the
    # daemon config. Otherwise probe.
    my $cfg_method = eval { $self->{cfg}{forward}{method} } // 'auto';
    if ($cfg_method eq 'iptables' || $cfg_method eq 'socat') {
        $self->_log("forward backend pinned to '$cfg_method' by config");
        return $self->{_fwd_method_cache} = $cfg_method;
    }

    # Auto: prefer iptables if we can run it AND we're root.
    if ($> == 0 && _have_cmd('iptables')) {
        # Enable route_localnet on lo; harmless if already on. Required
        # for OUTPUT-chain DNAT from 127.0.0.1/* to a non-loopback dest.
        system('sysctl', '-q', '-w',
               'net.ipv4.conf.lo.route_localnet=1') == 0
            or $self->_log("warn: sysctl route_localnet=1 failed (rc=$?)");
        $self->_log("forward backend = iptables (root + iptables found)");
        return $self->{_fwd_method_cache} = 'iptables';
    }
    if (_have_cmd('socat')) {
        $self->_log("forward backend = socat (no iptables / not root)");
        return $self->{_fwd_method_cache} = 'socat';
    }
    $self->_log("warn: no forward backend available (need iptables+root or socat)");
    return $self->{_fwd_method_cache} = '';
}

sub _have_cmd {
    my ($cmd) = @_;
    for my $d (split /:/, $ENV{PATH} // '/usr/sbin:/sbin:/usr/bin:/bin') {
        return 1 if -x "$d/$cmd";
    }
    return 0;
}

sub _install_forward {
    my ($self, %args) = @_;
    my $slot   = $args{slot}   or croak "slot required";
    my $target = $args{target} or croak "target required";
    my $owner  = $args{owner}  // 'anon';
    my $fd     = $args{fd}     // 0;

    my $method = $self->_forward_method
        or croak "no forward backend available";

    if ($method eq 'iptables') {
        return $self->_iptables_install($slot, $target, $fd);
    } else {
        return $self->_socat_install($slot, $target);
    }
}

sub _remove_forward {
    my ($self, $f) = @_;
    return unless ref $f;
    if ($f->{method} eq 'iptables') {
        return $self->_iptables_remove($f);
    } elsif ($f->{method} eq 'socat') {
        return $self->_socat_remove($f);
    }
    croak "unknown forward method '$f->{method}'";
}

# OUTPUT-chain DNAT in the nat table. -d 127.0.0.1 matches the
# loopback destination that ssh's local end of `ssh -L slot:127.0.0.1:slot`
# will connect to. Comment marker carries fd so cleanup-on-disconnect
# can identify our own rules even if state is lost mid-restart.
sub _iptables_install {
    my ($self, $slot, $target, $fd) = @_;
    my ($ip, $port) = split /:/, $target, 2;
    my $cookie = "net-mgr:fwd:$$:$fd:$slot";
    my @cmd = ('iptables', '-t', 'nat', '-I', 'OUTPUT',
               '-p', 'tcp', '-d', '127.0.0.1', '--dport', $slot,
               '-m', 'comment', '--comment', $cookie,
               '-j', 'DNAT', '--to-destination', "$ip:$port");
    my $rc = system(@cmd);
    if ($rc != 0) {
        croak "iptables install rc=" . ($rc >> 8);
    }
    return {
        method => 'iptables',
        slot   => $slot,
        target => $target,
        cookie => $cookie,
    };
}

sub _iptables_remove {
    my ($self, $f) = @_;
    my ($ip, $port) = split /:/, $f->{target}, 2;
    my @cmd = ('iptables', '-t', 'nat', '-D', 'OUTPUT',
               '-p', 'tcp', '-d', '127.0.0.1', '--dport', $f->{slot},
               '-m', 'comment', '--comment', $f->{cookie},
               '-j', 'DNAT', '--to-destination', "$ip:$port");
    my $rc = system(@cmd);
    croak "iptables remove rc=" . ($rc >> 8) if $rc != 0;
    return 1;
}

# Socat fallback — listens on 127.0.0.1:slot, forks per connection,
# proxies to the target. Detached so a daemon restart doesn't kill
# them, but tracked by pid for explicit teardown.
sub _socat_install {
    my ($self, $slot, $target) = @_;
    my ($ip, $port) = split /:/, $target, 2;
    my $pid = fork;
    croak "fork: $!" unless defined $pid;
    if ($pid == 0) {
        # child: run socat, replacing this process
        POSIX::setsid();
        open STDIN,  '<', '/dev/null';
        open STDOUT, '>>', '/dev/null';
        open STDERR, '>>', '/dev/null';
        exec 'socat',
            "TCP-LISTEN:$slot,bind=127.0.0.1,fork,reuseaddr",
            "TCP:$ip:$port";
        exit 127;
    }
    # parent: tiny grace period, then check it didn't exit immediately
    select(undef, undef, undef, 0.1);
    if (waitpid($pid, POSIX::WNOHANG()) == $pid) {
        croak "socat exited immediately (rc=" . ($? >> 8) . ")";
    }
    return {
        method => 'socat',
        slot   => $slot,
        target => $target,
        pid    => $pid,
    };
}

sub _socat_remove {
    my ($self, $f) = @_;
    my $pid = $f->{pid} or return 1;
    kill 'TERM', $pid;
    # Brief wait for it to die; SIGKILL if it doesn't.
    for (1..10) {
        return 1 if waitpid($pid, POSIX::WNOHANG()) == $pid;
        select(undef, undef, undef, 0.05);
    }
    kill 'KILL', $pid;
    waitpid($pid, 0);
    return 1;
}

1;
