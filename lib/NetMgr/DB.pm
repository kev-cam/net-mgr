package NetMgr::DB;
# DBI wrapper for net-mgr. Connects via the [<section>] group of an option
# file (default /etc/net-mgr/root.conf; callers usually resolve this with
# NetMgr::Config->mysql_defaults_file), bootstraps the schema if absent, and
# exposes UPSERT helpers that return change-info so the daemon can emit
# transition events.

use strict;
use warnings;
use Carp qw(croak);
use DBI;
use FindBin;

our $SCHEMA_VERSION = 32;

sub new {
    my ($class, %args) = @_;
    my $self = bless {
        defaults_file => $args{defaults_file} // '/etc/net-mgr/root.conf',
        section       => $args{section}       // 'net-mgr',
        db            => $args{db}            // 'netmgr',
        schema_dir    => $args{schema_dir}    // "$FindBin::Bin/../sql",
        dbh           => undef,
    }, $class;
    return $self;
}

sub connect {
    my ($self) = @_;
    croak "defaults file '$self->{defaults_file}' not readable"
        unless -r $self->{defaults_file};
    my $dsn = "DBI:mysql:database=$self->{db}"
            . ";mysql_read_default_file=$self->{defaults_file}"
            . ";mysql_read_default_group=$self->{section}";
    my $dbh = DBI->connect($dsn, undef, undef, {
        RaiseError           => 1,
        PrintError           => 0,
        AutoCommit           => 1,
        mysql_enable_utf8mb4 => 1,
        mysql_auto_reconnect => 1,   # idle-drop survivability for the daemon
    });
    $self->{dbh} = $dbh;
    return $self;
}

sub dbh { $_[0]->{dbh} }

sub disconnect {
    my ($self) = @_;
    if ($self->{dbh}) { $self->{dbh}->disconnect; $self->{dbh} = undef }
}

# ---- schema bootstrap ---------------------------------------------------

sub current_schema_version {
    my ($self) = @_;
    my $exists = $self->{dbh}->selectrow_array(
        "SELECT COUNT(*) FROM information_schema.tables
          WHERE table_schema = DATABASE() AND table_name = 'schema_version'"
    );
    return 0 unless $exists;
    my ($v) = $self->{dbh}->selectrow_array(
        "SELECT MAX(version) FROM schema_version"
    );
    return $v // 0;
}

sub bootstrap_schema {
    my ($self) = @_;
    my $cur = $self->current_schema_version;
    return $cur if $cur >= $SCHEMA_VERSION;

    if ($cur == 0) {
        # Fresh install — load schema.sql wholesale.
        my $path = "$self->{schema_dir}/schema.sql";
        open my $fh, '<', $path or croak "open $path: $!";
        my $sql = do { local $/; <$fh> };
        close $fh;
        # Strip '-- ...' line comments before splitting on ';' — a stray
        # ';' inside a comment would otherwise be mis-treated as a
        # statement terminator and chop a CREATE TABLE in half.
        $sql =~ s/--[^\n]*//g;
        my @stmts = split /;\s*\n/, $sql;
        for my $s (@stmts) {
            $s =~ s/^\s+|\s+$//g;
            next if $s eq '';
            $self->{dbh}->do($s);
        }
        return $self->current_schema_version;
    }

    # Incremental migrations from $cur to $SCHEMA_VERSION.
    while ($cur < $SCHEMA_VERSION) {
        my $next = $cur + 1;
        $self->_apply_migration($next);
        $self->{dbh}->do("INSERT IGNORE INTO schema_version (version) VALUES (?)",
                         undef, $next);
        $cur = $next;
    }
    return $self->current_schema_version;
}

# Per-version DDL migrations. Inline rather than separate files for now —
# add a sql/migrations/ tree if/when the count justifies it.
sub _apply_migration {
    my ($self, $v) = @_;
    if ($v == 2) {
        # Add addresses.source so we can track where each (mac, addr)
        # assignment came from (DHCP server, dhcp.master, dhcp.extra, nmap).
        $self->{dbh}->do(
            "ALTER TABLE addresses ADD COLUMN source VARCHAR(64) AFTER addr"
        );
        $self->{dbh}->do(
            "ALTER TABLE addresses ADD KEY idx_source (source)"
        );
        return;
    }
    if ($v == 4) {
        # Add last_observed to track *live* observations, separate from
        # last_seen (any DB touch). NULL = never observed live (paper-only
        # entries from dhcp.master). interfaces and addresses both get it.
        $self->{dbh}->do(
            "ALTER TABLE interfaces ADD COLUMN last_observed DATETIME NULL"
        );
        $self->{dbh}->do(
            "ALTER TABLE interfaces ADD KEY idx_last_observed (last_observed)"
        );
        $self->{dbh}->do(
            "ALTER TABLE addresses ADD COLUMN last_observed DATETIME NULL"
        );
        $self->{dbh}->do(
            "ALTER TABLE addresses ADD KEY idx_last_observed (last_observed)"
        );
        return;
    }
    if ($v == 5) {
        # Per-(mac,addr) ping RTT tracking. min_rtt_ms is monotone-
        # decreasing, reset_rtt() clears it. last_rtt_ms is the most-
        # recent fping reading, used by the ping_slow event detector.
        $self->{dbh}->do(
            "ALTER TABLE addresses ADD COLUMN min_rtt_ms FLOAT NULL"
        );
        $self->{dbh}->do(
            "ALTER TABLE addresses ADD COLUMN last_rtt_ms FLOAT NULL"
        );
        return;
    }
    if ($v == 6) {
        # Per-association SSID — the actual network the client is on.
        # Captured by net-poll-ap from `wl -i <iface> ssid`. Lets
        # net-roam --list show "scorpius" instead of the AP's full
        # joined SSID list.
        $self->{dbh}->do(
            "ALTER TABLE associations ADD COLUMN ssid VARCHAR(64) NULL AFTER iface"
        );
        return;
    }
    if ($v == 7) {
        # dhcp_vars: named placeholder values for net-gen-dnsmasq
        # substitution (DNSH=192.168.15.252, etc.). Plain key=value.
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS dhcp_vars (
    name        VARCHAR(64)  NOT NULL PRIMARY KEY,
    value       VARCHAR(255) NOT NULL,
    notes       TEXT,
    updated_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                             ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        return;
    }
    if ($v == 8) {
        # Per-subnet AP ranking, used when net-var auto picks which
        # AP fills ROUTER_* placeholders. Higher rank wins.
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS subnet_routers (
    subnet_cidr  VARCHAR(45)  NOT NULL,
    ap_mac       CHAR(17)     NOT NULL,
    `rank`       INT          NOT NULL DEFAULT 0,
    notes        TEXT,
    PRIMARY KEY (subnet_cidr, ap_mac),
    KEY idx_subnet (subnet_cidr),
    CONSTRAINT fk_subnet_router_ap
        FOREIGN KEY (ap_mac) REFERENCES interfaces(mac) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        return;
    }
    if ($v == 9) {
        # User-supplied display names, override the producer-set
        # primary_name on the web UI list.
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS friendly_names (
    machine_id  INT          NOT NULL PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    notes       TEXT,
    updated_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                             ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_friendly_machine
        FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        return;
    }
    if ($v == 10) {
        # Things plugged into Wi-Fi smart sockets, populated by
        # net-tp-scan. One row per outlet.
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS wifi_sockets (
    machine_id      INT          NOT NULL,
    outlet          INT          NOT NULL,
    name            VARCHAR(255),
    state           TINYINT      NULL,
    controller_type VARCHAR(64),
    last_seen       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                                 ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (machine_id, outlet),
    CONSTRAINT fk_wifi_socket_machine
        FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        return;
    }
    if ($v == 3) {
        # Add aliases for explicit name → (machine, preferred-subnet) overrides
        # used by the DNS resolver. machine_id FK with cascade delete.
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS aliases (
    name               VARCHAR(255) NOT NULL PRIMARY KEY,
    machine_id         INT          NOT NULL,
    prefer_subnet_cidr VARCHAR(45),
    source             VARCHAR(64),
    notes              TEXT,
    created_at         DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_alias_machine (machine_id),
    CONSTRAINT fk_alias_machine
        FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        return;
    }
    if ($v == 11) {
        # Devices found by net-find-lost on a vendor-default subnet but
        # not yet recovered. Upserted on (subnet, mac).
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS lost_devices (
    id           INT          NOT NULL AUTO_INCREMENT PRIMARY KEY,
    first_seen   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                              ON UPDATE CURRENT_TIMESTAMP,
    iface        VARCHAR(16)  NOT NULL,
    subnet       VARCHAR(45)  NOT NULL,
    ip           VARCHAR(45)  NOT NULL,
    mac          CHAR(17)     NOT NULL,
    vendor       VARCHAR(128),
    handler      VARCHAR(64),
    status       VARCHAR(32)  NOT NULL DEFAULT 'no-handler',
    last_attempt DATETIME     NULL,
    notes        TEXT,
    UNIQUE KEY uniq_subnet_mac (subnet, mac),
    KEY idx_status    (status),
    KEY idx_last_seen (last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        return;
    }
    if ($v == 12) {
        # Peer net-mgr instances discovered on the LAN by net-find-peers.
        # Upserted on (host, port). schema_version / started_at /
        # rtt_ms come from the peer's STATUS reply.
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS peers (
    host           VARCHAR(64)  NOT NULL,
    port           SMALLINT     UNSIGNED NOT NULL DEFAULT 7531,
    first_seen     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                                ON UPDATE CURRENT_TIMESTAMP,
    last_status    VARCHAR(32)  NOT NULL DEFAULT 'reachable',
    schema_version INT          NULL,
    started_at     DATETIME     NULL,
    rtt_ms         FLOAT        NULL,
    notes          TEXT,
    PRIMARY KEY (host, port),
    KEY idx_last_seen (last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        return;
    }
    if ($v == 13) {
        # Per-host uplink probe state. Each row is one upstream path
        # this gateway has (e.g. 'comcast' via eth0, 'wifi' via wlan0).
        # Populated by net-uplink-probe; the daemon does NOT manage
        # these — they're driven by [uplinks] in /etc/net-mgr/config.
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS uplinks (
    label                VARCHAR(64)  NOT NULL PRIMARY KEY,
    target               VARCHAR(64)  NOT NULL,        -- ping target, e.g. 1.1.1.1
    via_iface            VARCHAR(32)  NULL,            -- bind-to-iface (-I)
    role                 VARCHAR(16)  NOT NULL DEFAULT 'active',
                                                       -- 'active' | 'backup'
    interval_s           INT          NOT NULL DEFAULT 60,
    last_check           DATETIME     NULL,
    last_ok              DATETIME     NULL,            -- last successful probe
    last_status          VARCHAR(16)  NOT NULL DEFAULT 'unknown',
                                                       -- 'ok' | 'fail' | 'unknown'
    last_rtt_ms          FLOAT        NULL,
    consecutive_failures INT          NOT NULL DEFAULT 0,
    notes                TEXT,
    KEY idx_role       (role),
    KEY idx_last_check (last_check)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        return;
    }
    if ($v == 14) {
        # Port-forwarding rules.  Populated by net-import-ssh-forwards
        # from `pgrep -lfa ssh` output on firewalls/gateways, plus any
        # manually-added rules.  Future consumer: iptables generator.
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS forwarding_rules (
    id           INT          NOT NULL AUTO_INCREMENT PRIMARY KEY,
    source       VARCHAR(32)  NOT NULL,
    source_host  VARCHAR(64)  NOT NULL,
    source_pid   INT          NULL,
    direction    CHAR(1)      NOT NULL,
    bind_addr    VARCHAR(64)  NOT NULL DEFAULT '*',
    bind_port    INT          NOT NULL,
    target_host  VARCHAR(64)  NULL,
    target_port  INT          NULL,
    ssh_user     VARCHAR(64)  NULL,
    ssh_host     VARCHAR(64)  NULL,
    ssh_port     INT          NULL,
    notes        TEXT,
    first_seen   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                              ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_rule (source_host, direction, bind_addr, bind_port),
    KEY idx_source_host (source_host),
    KEY idx_target      (target_host, target_port)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        return;
    }
    if ($v == 15) {
        # Zone classification.  zone_classes is the flat enumeration;
        # interface_zones / wifi_zones derive concrete (class, name)
        # tuples from network signals.  Manual rule-zone tagging and
        # iptables emission both land in later migrations.
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS zone_classes (
    name        VARCHAR(32) NOT NULL PRIMARY KEY,
    sort_order  INT         NOT NULL DEFAULT 0,
    notes       TEXT,
    created_at  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        $self->{dbh}->do(<<'SQL');
INSERT IGNORE INTO zone_classes (name, sort_order) VALUES
    ('Internet',  0),
    ('DMZ',      10),
    ('Private',  20)
SQL
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS interface_zones (
    host        VARCHAR(64) NOT NULL,
    iface       VARCHAR(32) NOT NULL,
    cidr        VARCHAR(45) NOT NULL,
    zone_class  VARCHAR(32) NOT NULL,
    zone_name   VARCHAR(64) NOT NULL DEFAULT '',
    notes       TEXT,
    updated_at  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
                            ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (host, iface, cidr),
    KEY idx_zone (zone_class, zone_name),
    CONSTRAINT fk_iz_class FOREIGN KEY (zone_class)
        REFERENCES zone_classes(name) ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS wifi_zones (
    ssid        VARCHAR(64) NOT NULL PRIMARY KEY,
    zone_class  VARCHAR(32) NOT NULL,
    zone_name   VARCHAR(64) NOT NULL DEFAULT '',
    notes       TEXT,
    updated_at  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
                            ON UPDATE CURRENT_TIMESTAMP,
    KEY idx_zone (zone_class, zone_name),
    CONSTRAINT fk_wz_class FOREIGN KEY (zone_class)
        REFERENCES zone_classes(name) ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        return;
    }
    if ($v == 16) {
        # audit_annotations: mark sinks (target host:port absorbs stray
        # traffic) or intentional Internet-facing forwards so net-audit
        # doesn't re-flag them.  host='' means "any host" — useful for
        # sink-target where the property attaches to the destination.
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS audit_annotations (
    kind       VARCHAR(32) NOT NULL,
    host       VARCHAR(64) NOT NULL DEFAULT '',
    addr       VARCHAR(64) NOT NULL DEFAULT '*',
    port       INT         NOT NULL,
    reason     TEXT,
    created_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
                           ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (kind, host, addr, port),
    KEY idx_target (addr, port)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        return;
    }
    if ($v == 17) {
        # wifi_scan_results: latest 'wl scanresults' observation per
        # (scanner_mac, scanner_iface, bssid).  Populated by
        # net-wifi-survey.
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS wifi_scan_results (
    scanner_mac    CHAR(17)    NOT NULL,
    scanner_iface  VARCHAR(16) NOT NULL,
    bssid          CHAR(17)    NOT NULL,
    ssid           VARCHAR(64),
    channel        INT,
    band           VARCHAR(8),
    rssi_dbm       INT,
    encryption     VARCHAR(64),
    bandwidth_mhz  INT,
    first_seen     DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen      DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
                               ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (scanner_mac, scanner_iface, bssid),
    KEY idx_bssid     (bssid),
    KEY idx_channel   (channel),
    KEY idx_last_seen (last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        return;
    }
    if ($v == 18) {
        # wifi_radio_state: current channel per (scanner_mac, scanner_iface).
        # Populated by net-wifi-survey alongside the foreign-AP scan.
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS wifi_radio_state (
    scanner_mac     CHAR(17)    NOT NULL,
    scanner_iface   VARCHAR(16) NOT NULL,
    band            VARCHAR(8),
    current_channel INT,
    updated_at      DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
                                ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (scanner_mac, scanner_iface)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        return;
    }
    if ($v == 19) {
        # ISP-link bookkeeping. Failover decisions need to know which
        # gateway machine can reach which ISP, with what credentials.
        # Public-readable in isp_links; the secret column lives in a
        # separate isp_secrets table that's gated to AUTH'd peers only
        # (see %SUBSCRIBABLE_AUTH in Manager.pm).
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS isp_links (
    gateway_machine_id INT          NOT NULL,
    isp_name           VARCHAR(64)  NOT NULL,    -- 'comcast', 'tmobile', ...
    iface              VARCHAR(32),               -- WAN iface on the gateway
    mac                CHAR(17),                  -- MAC used (cloned for Comcast)
    auth_type          VARCHAR(32),               -- 'mac', 'pppoe', 'dhcp', 'wpa2'
    auth_user          VARCHAR(255),
    status             VARCHAR(32) NOT NULL DEFAULT 'active',
                                                  -- active | standby | broken | unknown
    notes              TEXT,
    last_seen          DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
                                   ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (gateway_machine_id, isp_name),
    KEY idx_isp        (isp_name),
    KEY idx_status     (status),
    CONSTRAINT fk_isp_links_machine
        FOREIGN KEY (gateway_machine_id) REFERENCES machines(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS isp_secrets (
    gateway_machine_id INT          NOT NULL,
    isp_name           VARCHAR(64)  NOT NULL,
    auth_secret        VARCHAR(255),              -- PPPoE password / WPA passphrase
    last_changed       DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
                                   ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (gateway_machine_id, isp_name),
    CONSTRAINT fk_isp_secrets_link
        FOREIGN KEY (gateway_machine_id, isp_name)
            REFERENCES isp_links(gateway_machine_id, isp_name)
            ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        return;
    }
    if ($v == 20) {
        # Link-speed + per-destination packet-loss columns. Used by
        # net-lookup's scoring (wired-over-wifi tiebreak via
        # interfaces.kind, RTT/loss for fine-grained ranking).
        # Producers (ethtool, fping, iw) populate them; columns
        # default NULL until that lands. Skipped if a column already
        # exists (re-run safety on hand-migrated DBs).
        for my $alter (
            "ALTER TABLE interfaces ADD COLUMN link_speed_mbps INT NULL",
            "ALTER TABLE addresses  ADD COLUMN loss_pct        FLOAT NULL",
        ) {
            eval { $self->{dbh}->do($alter) };
            if ($@ && $@ !~ /duplicate column|Duplicate column/i) {
                die $@;
            }
        }
        return;
    }
    if ($v == 21) {
        # replicated_from: which cluster master a row came from,
        # NULL = locally-observed. Relay sets it on every UPSERT;
        # local OBSERVE writes don't touch it. Master's next
        # replication tick overwrites local divergence, so this
        # column is both an audit trail (where did this row come
        # from?) and the mechanism behind "master's info takes
        # precedence". Re-run safe.
        for my $tbl (qw(machines hostnames interfaces addresses ports
                        aps associations dhcp_leases aliases)) {
            eval {
                $self->{dbh}->do(
                    "ALTER TABLE $tbl ADD COLUMN replicated_from VARCHAR(64) NULL");
                $self->{dbh}->do(
                    "ALTER TABLE $tbl ADD KEY idx_replicated_from (replicated_from)");
            };
            if ($@ && $@ !~ /duplicate column|Duplicate column|Duplicate key name/i) {
                die $@;
            }
        }
        return;
    }
    if ($v == 22) {
        # net-chat: named chat sessions hosted by the daemon. See the
        # matching block in sql/schema.sql for column docs.
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS chat_sessions (
    name          VARCHAR(64)  NOT NULL PRIMARY KEY,
    topic         TEXT,
    created_by    VARCHAR(128) NOT NULL,
    access_mode   ENUM('open','list','request') NOT NULL DEFAULT 'open',
    status        ENUM('open','closed')         NOT NULL DEFAULT 'open',
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_activity DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_at     DATETIME     NULL,
    KEY idx_status        (status),
    KEY idx_last_activity (last_activity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS chat_members (
    session      VARCHAR(64)  NOT NULL,
    principal    VARCHAR(128) NOT NULL,
    role         ENUM('owner','member')                        NOT NULL DEFAULT 'member',
    state        ENUM('member','requested','invited','denied') NOT NULL DEFAULT 'member',
    added_by     VARCHAR(128),
    requested_at DATETIME     NULL,
    joined_at    DATETIME     NULL,
    PRIMARY KEY (session, principal),
    KEY idx_member_state (state),
    CONSTRAINT fk_chat_members_session
        FOREIGN KEY (session) REFERENCES chat_sessions(name) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS chat_messages (
    id           BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    session      VARCHAR(64)  NOT NULL,
    ts           DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    sender       VARCHAR(128) NOT NULL,
    sender_kind  ENUM('agent','human','system') NOT NULL DEFAULT 'agent',
    body         TEXT         NOT NULL,
    in_reply_to  BIGINT       NULL,
    KEY idx_session_ts (session, ts),
    KEY idx_ts         (ts),
    CONSTRAINT fk_chat_messages_session
        FOREIGN KEY (session) REFERENCES chat_sessions(name) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS chat_presence (
    session      VARCHAR(64)  NOT NULL,
    conn_id      BIGINT       NOT NULL,
    principal    VARCHAR(128) NOT NULL,
    since        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (session, conn_id),
    KEY idx_presence_session   (session),
    KEY idx_presence_principal (principal),
    CONSTRAINT fk_chat_presence_session
        FOREIGN KEY (session) REFERENCES chat_sessions(name) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        return;
    }
    if ($v == 23) {
        # host_keys: SSH host-key fingerprint -> machine. A host key is stable
        # across IP and even MAC changes, so it identifies a machine on a
        # floating IP. See sql/schema.sql for column docs.
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS host_keys (
    key_id     VARCHAR(80)  NOT NULL PRIMARY KEY,   -- "SHA256:..." fingerprint
    key_type   VARCHAR(20)  NOT NULL DEFAULT '',    -- ed25519 / rsa / ecdsa
    machine_id INT          NULL,                   -- owning machine (NULL = orphan)
    first_seen DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_host_keys_machine (machine_id),
    CONSTRAINT fk_host_keys_machine
        FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        return;
    }
    if ($v == 24) {
        # DB-native DHCP plan: dynamic-pool ranges + static reservations,
        # both cluster-replicated. See sql/schema.sql for column docs.
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS dhcp_ranges (
    subnet_cidr  VARCHAR(45)  NOT NULL,
    start_ip     VARCHAR(45)  NOT NULL,
    end_ip       VARCHAR(45)  NOT NULL,
    zone         VARCHAR(64)  NULL,
    notes        TEXT         NULL,
    updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                              ON UPDATE CURRENT_TIMESTAMP,
    replicated_from VARCHAR(64) NULL,
    PRIMARY KEY (subnet_cidr, start_ip),
    KEY idx_dhcp_ranges_subnet (subnet_cidr),
    KEY idx_dhcp_ranges_replicated (replicated_from)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS dhcp_reservations (
    ip           VARCHAR(45)  NOT NULL PRIMARY KEY,
    mac          CHAR(17)     NOT NULL,
    name         VARCHAR(255) NULL,
    subnet_cidr  VARCHAR(45)  NULL,
    grp          VARCHAR(64)  NULL,
    notes        TEXT         NULL,
    updated_by   VARCHAR(128) NULL,
    updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                              ON UPDATE CURRENT_TIMESTAMP,
    replicated_from VARCHAR(64) NULL,
    KEY idx_resv_mac    (mac),
    KEY idx_resv_subnet (subnet_cidr),
    KEY idx_resv_grp    (grp),
    KEY idx_resv_replicated (replicated_from)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        return;
    }
    if ($v == 25) {
        # net-chat: persistent per-chat authorized SSH keys. When an owner
        # approves a join request the requester's key is recorded here, so the
        # authorization survives independent of live membership and can be
        # inspected / exported / pre-loaded. See sql/schema.sql for column docs.
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS chat_authorized_keys (
    session    VARCHAR(64)  NOT NULL,
    key_id     VARCHAR(80)  NOT NULL,            -- "SHA256:..." fingerprint
    key_type   VARCHAR(20)  NOT NULL DEFAULT '', -- ed25519 / rsa / ecdsa
    label      VARCHAR(128) NOT NULL DEFAULT '', -- friendly name (machine) at approval
    added_by   VARCHAR(128) NULL,                -- principal who authorized it
    added_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (session, key_id),
    KEY idx_cak_key (key_id),
    CONSTRAINT fk_cak_session
        FOREIGN KEY (session) REFERENCES chat_sessions(name) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        return;
    }
    if ($v == 26) {
        # aps.exclude: per-AP globs of hosts NOT to push to that AP's DHCP
        # static leases (net-push-ap). Set via OBSERVE kind=ap_exclude; AP
        # rescans (upsert_ap) leave it untouched. See sql/schema.sql.
        $self->{dbh}->do(
            "ALTER TABLE aps ADD COLUMN exclude TEXT NULL AFTER board"
        );
        return;
    }
    if ($v == 28) {
        # Durable chat-key auth: persist the requester's SSH pubkey through the
        # see-and-request approval flow. See sql/schema.sql for the rationale.
        $self->{dbh}->do(
            "ALTER TABLE chat_members ADD COLUMN request_pubkey TEXT NULL"
        );
        $self->{dbh}->do(
            "ALTER TABLE chat_authorized_keys ADD COLUMN pubkey TEXT NULL"
        );
        return;
    }
    if ($v == 29) {
        # mesh_tunnels.secret_name: per-tunnel pointer to the credential needed
        # for provider DDNS (HE tunnelbroker). See sql/schema.sql.
        $self->{dbh}->do(
            "ALTER TABLE mesh_tunnels ADD COLUMN secret_name VARCHAR(64) NULL"
        );
        return;
    }
    if ($v == 30) {
        # peers.cluster_member: peer's STATUS-reported cluster_member name, so
        # AutoDiscover can resolve peers without machines table data.
        $self->{dbh}->do(
            "ALTER TABLE peers ADD COLUMN cluster_member VARCHAR(64) NULL"
        );
        return;
    }
    if ($v == 31) {
        # chat_members.requested_from: peer IP/host the join request came in
        # on, so an approver can see WHERE the request originated, not just
        # WHO claimed to send it. Especially useful for unverified joins
        # (the principal is a self-asserted name; the source addr is real).
        $self->{dbh}->do(
            "ALTER TABLE chat_members ADD COLUMN requested_from VARCHAR(64) NULL"
        );
        return;
    }
    if ($v == 32) {
        # node_capabilities: per-mesh-member snapshot of the host's runtime
        # capabilities (BLE, IPv6 forwarding, gateway, wifi_ap, cargo, ...).
        # Published by each daemon via HEARTBEAT and persisted by the master.
        # Lets consumers (net-cluster --capable=ble, the bitchat-bridge site
        # picker, etc.) route mesh work to hosts that can do it, without
        # walking every daemon's STATUS live. Keyed by mesh member name
        # because HEARTBEAT identifies by member (not host:port).
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS node_capabilities (
    member          VARCHAR(64)  NOT NULL,
    capabilities    TEXT         NOT NULL,
    updated_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                                 ON UPDATE CURRENT_TIMESTAMP,
    replicated_from VARCHAR(64)  NULL,
    PRIMARY KEY (member),
    KEY idx_nc_replicated (replicated_from)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        return;
    }
    if ($v == 27) {
        # mesh_tunnels: tunnel/uplink metadata replicated cluster-wide. The
        # source-of-truth for net-mgr's "overlay" tunnels — see sql/schema.sql
        # for the column reference. A node's [ipv6_vlan] config OVERRIDES
        # these columns when set ("config is for overrides only" — the design
        # intent in project_net-mgr-vision).
        $self->{dbh}->do(<<'SQL');
CREATE TABLE IF NOT EXISTS mesh_tunnels (
    owner_node       VARCHAR(64)  NOT NULL,
    kind             VARCHAR(32)  NOT NULL,
    provider_id      VARCHAR(64)  NULL,
    server_v4        VARCHAR(45)  NULL,
    tunnel_prefix    VARCHAR(64)  NULL,
    routed_prefix    VARCHAR(64)  NULL,
    notes            VARCHAR(255) NULL,
    last_modified    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                                  ON UPDATE CURRENT_TIMESTAMP,
    replicated_from  VARCHAR(64)  NULL,
    PRIMARY KEY (owner_node, kind),
    KEY idx_mt_replicated (replicated_from)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
SQL
        return;
    }
    croak "no migration for schema v$v";
}

# host_keys: SSH host-key fingerprint <-> machine identity. The fingerprint is
# the stable key; machine_id is filled when we know whose it is (NULL until).
sub upsert_host_key {
    my ($self, %f) = @_;
    my $key_id = $f{key_id} or croak "upsert_host_key: key_id required";
    $self->{dbh}->do(
        "INSERT INTO host_keys (key_id, key_type, machine_id)
         VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE
           key_type   = VALUES(key_type),
           machine_id = COALESCE(VALUES(machine_id), machine_id),
           last_seen  = NOW()",
        undef, $key_id, ($f{key_type} // ''), $f{machine_id});
    return;
}

# Machine id this host key already belongs to, or undef if unseen/orphan.
sub host_key_machine {
    my ($self, $key_id) = @_;
    return undef unless defined $key_id && length $key_id;
    my ($mid) = $self->{dbh}->selectrow_array(
        "SELECT machine_id FROM host_keys WHERE key_id = ?", undef, $key_id);
    return $mid;
}

# Friendly identification for an SSH key_id from host_keys + machines:
# returns (key_type, machine_name), each '' when unknown. Used to label a
# chat's authorized keys with something more human than a raw fingerprint.
sub host_key_identity {
    my ($self, $key_id) = @_;
    return ('', '') unless defined $key_id && length $key_id;
    my $row = $self->{dbh}->selectrow_hashref(
        "SELECT hk.key_type AS key_type, m.primary_name AS name
           FROM host_keys hk
           LEFT JOIN machines m ON m.id = hk.machine_id
          WHERE hk.key_id = ?", undef, $key_id);
    return ('', '') unless $row;
    return ($row->{key_type} // '', $row->{name} // '');
}

# ---- UPSERT helpers ----------------------------------------------------
# Each returns: { op => 'insert'|'update'|'noop', changed_fields => [..],
#                 was => \%before|undef, now => \%after }

sub upsert_interface {
    my ($self, %f) = @_;
    croak "mac required" unless $f{mac};
    $f{mac} = lc $f{mac};

    # `live => 1` (callers passing live observations) bumps last_observed
    # to NOW. Relay can override by passing an explicit
    # `last_observed => $datetime` (preserves the source's value).
    my $live = delete $f{live};
    my $last_observed_explicit = delete $f{last_observed};

    my $was = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM interfaces WHERE mac = ?", undef, $f{mac}
    );
    if ($was) {
        my @changed;
        my @set;
        my @bind;
        for my $k (qw(machine_id vendor kind online)) {
            next unless exists $f{$k};
            my $old = $was->{$k};
            my $new = $f{$k};
            next if (!defined $old && !defined $new);
            next if (defined $old && defined $new && $old eq $new);
            push @changed, $k;
            push @set,  "$k = ?";
            push @bind, $new;
        }
        push @set,  "last_seen = CURRENT_TIMESTAMP";
        if (defined $last_observed_explicit) {
            push @set, "last_observed = ?";
            push @bind, $last_observed_explicit;
        } elsif ($live) {
            push @set, "last_observed = CURRENT_TIMESTAMP";
        }
        my $sql = "UPDATE interfaces SET " . join(', ', @set) . " WHERE mac = ?";
        $self->{dbh}->do($sql, undef, @bind, $f{mac});
        my $now = $self->{dbh}->selectrow_hashref(
            "SELECT * FROM interfaces WHERE mac = ?", undef, $f{mac});
        return {
            op             => @changed ? 'update' : 'noop',
            changed_fields => \@changed,
            was            => $was,
            now            => $now,
        };
    }

    # Insert: if live (or explicit), set last_observed; otherwise leave NULL
    my $insert_last_observed;
    if (defined $last_observed_explicit) {
        $insert_last_observed = $last_observed_explicit;
    } elsif ($live) {
        $insert_last_observed = $self->{dbh}->selectrow_array("SELECT NOW()");
    }
    $self->{dbh}->do(
        "INSERT INTO interfaces (mac, machine_id, vendor, kind, online, last_observed)
         VALUES (?, ?, ?, ?, ?, ?)", undef,
        $f{mac}, $f{machine_id}, $f{vendor}, ($f{kind} // 'unknown'),
        ($f{online} // 0), $insert_last_observed
    );
    my $now = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM interfaces WHERE mac = ?", undef, $f{mac});
    return { op => 'insert', changed_fields => [keys %$now], was => undef, now => $now };
}

sub upsert_address {
    my ($self, %f) = @_;
    croak "mac required"    unless $f{mac};
    croak "addr required"   unless $f{addr};
    croak "family required" unless $f{family};
    $f{mac} = lc $f{mac};

    # Same `live` / explicit `last_observed` semantics as upsert_interface
    my $live = delete $f{live};
    my $last_observed_explicit = delete $f{last_observed};

    # Cross-MAC IP conflict resolution.  A given IP normally belongs to
    # exactly one MAC at a time; stale ARP scans + paper records like
    # dhcp.master can leave behind rows for the same (family, addr) but
    # a different mac.  Compare source priorities:
    #   * If a strictly higher-priority claim already names a different
    #     mac at this addr, skip the incoming observation entirely (the
    #     authoritative source wins).
    #   * If our priority is at least equal, the existing rows are
    #     superseded — delete them after our upsert lands.
    my @to_supersede;
    if (defined $f{source}) {
        my $new_prio = _source_priority($f{source});
        my $existing = $self->{dbh}->selectall_arrayref(
            "SELECT mac, source FROM addresses
              WHERE family = ? AND addr = ? AND mac != ?",
            { Slice => {} }, $f{family}, $f{addr}, $f{mac}
        );
        for my $e (@$existing) {
            my $old_prio = _source_priority($e->{source});
            if ($new_prio < $old_prio) {
                # An authoritative claim from another mac wins — drop this.
                return { op => 'skipped_lower_priority',
                         changed_fields => [], was => undef, now => undef };
            }
            push @to_supersede, $e->{mac};   # equal-or-higher → we win
        }
    }

    my $was = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM addresses WHERE mac = ? AND family = ? AND addr = ?",
        undef, $f{mac}, $f{family}, $f{addr}
    );
    if ($was) {
        my @changed;
        my @set; my @bind;
        push @set,  "last_seen = CURRENT_TIMESTAMP";
        my $new_src = $f{source};
        if (defined $new_src
            && _source_priority($new_src) >= _source_priority($was->{source})
            && (($was->{source} // '') ne $new_src))
        {
            push @changed, 'source';
            push @set,  "source = ?";
            push @bind, $new_src;
        }
        if (defined $last_observed_explicit) {
            push @set, "last_observed = ?";
            push @bind, $last_observed_explicit;
        } elsif ($live) {
            push @set, "last_observed = CURRENT_TIMESTAMP";
        }
        my $sql = "UPDATE addresses SET " . join(', ', @set)
                . " WHERE mac = ? AND family = ? AND addr = ?";
        $self->{dbh}->do($sql, undef, @bind, $f{mac}, $f{family}, $f{addr});
        my $now = $self->{dbh}->selectrow_hashref(
            "SELECT * FROM addresses WHERE mac = ? AND family = ? AND addr = ?",
            undef, $f{mac}, $f{family}, $f{addr}
        );
        $self->_supersede_addresses($f{family}, $f{addr}, \@to_supersede)
            if @to_supersede;
        return { op => @changed ? 'update' : 'noop',
                 changed_fields => \@changed, was => $was, now => $now,
                 superseded => [@to_supersede] };
    }
    my $insert_last_observed;
    if    (defined $last_observed_explicit) { $insert_last_observed = $last_observed_explicit }
    elsif ($live) { $insert_last_observed = $self->{dbh}->selectrow_array("SELECT NOW()") }
    $self->{dbh}->do(
        "INSERT INTO addresses (mac, family, addr, source, last_observed)
         VALUES (?, ?, ?, ?, ?)",
        undef, $f{mac}, $f{family}, $f{addr}, $f{source}, $insert_last_observed
    );
    my $now = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM addresses WHERE mac = ? AND family = ? AND addr = ?",
        undef, $f{mac}, $f{family}, $f{addr}
    );
    $self->_supersede_addresses($f{family}, $f{addr}, \@to_supersede)
        if @to_supersede;
    return { op => 'insert', changed_fields => [qw(mac family addr source)],
             was => undef, now => $now, superseded => [@to_supersede] };
}

sub _supersede_addresses {
    my ($self, $family, $addr, $macs) = @_;
    return unless $macs && @$macs;
    my $placeholders = join(',', ('?') x @$macs);
    $self->{dbh}->do(
        "DELETE FROM addresses
          WHERE family = ? AND addr = ? AND mac IN ($placeholders)",
        undef, $family, $addr, @$macs);
}

# Update the ping RTT fields on an existing addresses row. Does NOT
# upsert — pinging happens against IPs we already know; if the row is
# missing it's a producer bug, not a discovery event. Returns
#   { found => 0|1, prev_min => $f|undef, new_min => $f|undef,
#     prev_last => $f|undef, last_rtt_ms => $f }
# so the caller (Manager::_obs_ping) can decide whether the new
# reading crossed a "ping_slow" threshold.
sub update_rtt {
    my ($self, %f) = @_;
    croak "mac required"  unless $f{mac};
    croak "addr required" unless $f{addr};
    croak "rtt_ms required" unless defined $f{rtt_ms};
    my $mac    = lc $f{mac};
    my $addr   = $f{addr};
    my $family = $f{family} // 'v4';
    my $rtt    = $f{rtt_ms} + 0;

    my $was = $self->{dbh}->selectrow_hashref(
        "SELECT min_rtt_ms, last_rtt_ms FROM addresses
          WHERE mac = ? AND family = ? AND addr = ?",
        undef, $mac, $family, $addr
    );
    return { found => 0 } unless $was;

    # Optional loss_pct (multi-sample fping; 0..100 float). Pass undef
    # to leave the existing value alone.
    my $loss = $f{loss_pct};
    if (defined $loss) {
        $self->{dbh}->do(
            "UPDATE addresses
                SET last_rtt_ms   = ?,
                    min_rtt_ms    = LEAST(IFNULL(min_rtt_ms, ?), ?),
                    loss_pct      = ?,
                    last_observed = CURRENT_TIMESTAMP,
                    last_seen     = CURRENT_TIMESTAMP
              WHERE mac = ? AND family = ? AND addr = ?",
            undef, $rtt, $rtt, $rtt, $loss + 0, $mac, $family, $addr
        );
    } else {
        $self->{dbh}->do(
            "UPDATE addresses
                SET last_rtt_ms   = ?,
                    min_rtt_ms    = LEAST(IFNULL(min_rtt_ms, ?), ?),
                    last_observed = CURRENT_TIMESTAMP,
                    last_seen     = CURRENT_TIMESTAMP
              WHERE mac = ? AND family = ? AND addr = ?",
            undef, $rtt, $rtt, $rtt, $mac, $family, $addr
        );
    }
    my ($new_min) = $self->{dbh}->selectrow_array(
        "SELECT min_rtt_ms FROM addresses
          WHERE mac = ? AND family = ? AND addr = ?",
        undef, $mac, $family, $addr
    );
    return {
        found       => 1,
        prev_min    => $was->{min_rtt_ms},
        new_min     => $new_min,
        prev_last   => $was->{last_rtt_ms},
        last_rtt_ms => $rtt,
    };
}

# Update interfaces.link_speed_mbps for a given mac. Returns 1 if a
# row was updated, 0 if there's no such interface yet.
sub update_link_speed {
    my ($self, %f) = @_;
    croak "mac required" unless $f{mac};
    croak "link_speed_mbps required" unless defined $f{link_speed_mbps};
    my $mac = lc $f{mac};
    my $sp  = $f{link_speed_mbps};
    return 0 unless $sp =~ /^-?\d+$/;
    my $rows = $self->{dbh}->do(
        "UPDATE interfaces
            SET link_speed_mbps = ?, last_seen = CURRENT_TIMESTAMP
          WHERE mac = ?",
        undef, $sp + 0, $mac
    );
    return $rows ? 1 : 0;
}

# Manual reset of min_rtt_ms (and last_rtt_ms) so a known-bad
# baseline measurement can be re-learned. Pass mac+addr to clear one
# row, or no args to clear everything. Returns rowcount.
sub reset_rtt {
    my ($self, %f) = @_;
    if ($f{mac} && $f{addr}) {
        return $self->{dbh}->do(
            "UPDATE addresses SET min_rtt_ms = NULL, last_rtt_ms = NULL
              WHERE mac = ? AND family = ? AND addr = ?",
            undef, lc $f{mac}, $f{family} // 'v4', $f{addr}
        );
    }
    if ($f{addr}) {
        return $self->{dbh}->do(
            "UPDATE addresses SET min_rtt_ms = NULL, last_rtt_ms = NULL
              WHERE addr = ?",
            undef, $f{addr}
        );
    }
    return $self->{dbh}->do(
        "UPDATE addresses SET min_rtt_ms = NULL, last_rtt_ms = NULL"
    );
}

# Higher = more authoritative. The exact strings are convention; the suffix
# after the colon classifies the source.
sub _source_priority {
    my ($s) = @_;
    return 0 unless defined $s;
    return 5 if $s =~ /:dhcp\.master$/;
    return 4 if $s =~ /:dhcp\.extra$/;
    return 3 if $s =~ /:DHCP$/i;       # leased from a DHCP server
    return 3 if $s =~ /:ssh$/i;        # direct probe of host (e.g. AP self-report)
    return 1 if $s =~ /:(arp|nmap)$/i; # passive observation
    return 1;
}

sub upsert_machine {
    my ($self, %f) = @_;
    if ($f{id}) {
        my $was = $self->{dbh}->selectrow_hashref(
            "SELECT * FROM machines WHERE id = ?", undef, $f{id});
        return { op => 'noop', was => undef, now => undef } unless $was;
        my @changed;
        my @set;
        my @bind;
        for my $k (qw(primary_name online notes)) {
            next unless exists $f{$k};
            my $old = $was->{$k}; my $new = $f{$k};
            next if (!defined $old && !defined $new);
            next if (defined $old && defined $new && $old eq $new);
            push @changed, $k;
            push @set,  "$k = ?";
            push @bind, $new;
        }
        push @set, "last_seen = CURRENT_TIMESTAMP";
        $self->{dbh}->do(
            "UPDATE machines SET " . join(', ', @set) . " WHERE id = ?",
            undef, @bind, $f{id});
        my $now = $self->{dbh}->selectrow_hashref(
            "SELECT * FROM machines WHERE id = ?", undef, $f{id});
        return {
            op             => @changed ? 'update' : 'noop',
            changed_fields => \@changed,
            was            => $was,
            now            => $now,
        };
    }

    $self->{dbh}->do(
        "INSERT INTO machines (primary_name, online, notes) VALUES (?, ?, ?)",
        undef, $f{primary_name}, ($f{online} // 0), $f{notes}
    );
    my $id  = $self->{dbh}->{mysql_insertid};
    my $now = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM machines WHERE id = ?", undef, $id);
    return { op => 'insert', changed_fields => [keys %$now],
             was => undef, now => $now };
}

sub upsert_hostname {
    my ($self, %f) = @_;
    croak "machine_id, name, source required"
        unless $f{machine_id} && $f{name} && $f{source};
    my $was = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM hostnames
          WHERE machine_id = ? AND name = ? AND source = ?",
        undef, $f{machine_id}, $f{name}, $f{source}
    );
    if ($was) {
        $self->{dbh}->do(
            "UPDATE hostnames SET last_seen = CURRENT_TIMESTAMP
              WHERE machine_id = ? AND name = ? AND source = ?",
            undef, $f{machine_id}, $f{name}, $f{source}
        );
        return { op => 'noop', changed_fields => [],
                 was => $was, now => $was };
    }
    $self->{dbh}->do(
        "INSERT INTO hostnames (machine_id, name, source) VALUES (?, ?, ?)",
        undef, $f{machine_id}, $f{name}, $f{source}
    );
    my $now = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM hostnames
          WHERE machine_id = ? AND name = ? AND source = ?",
        undef, $f{machine_id}, $f{name}, $f{source}
    );
    return { op => 'insert', changed_fields => [qw(machine_id name source)],
             was => undef, now => $now };
}

# Delete one (machine_id, name) tuple (every row regardless of source); return
# the list of rows that existed before, so callers can emit delete events.
sub delete_hostname {
    my ($self, $machine_id, $name) = @_;
    return () unless defined $machine_id && defined $name;
    my $rows = $self->{dbh}->selectall_arrayref(
        "SELECT * FROM hostnames WHERE machine_id = ? AND name = ?",
        { Slice => {} }, $machine_id, $name);
    return () unless $rows && @$rows;
    $self->{dbh}->do(
        "DELETE FROM hostnames WHERE machine_id = ? AND name = ?",
        undef, $machine_id, $name);
    return @$rows;
}

# Resolve a name to the machine row(s) whose primary_name matches. Returns the
# arrayref of full rows (usually one; multiples mean a duplicate-machines bug).
sub find_machines_by_primary_name {
    my ($self, $name) = @_;
    return [] unless defined $name && length $name;
    return $self->{dbh}->selectall_arrayref(
        "SELECT * FROM machines WHERE primary_name = ?",
        { Slice => {} }, $name);
}

sub upsert_port {
    my ($self, %f) = @_;
    croak "mac, port required" unless $f{mac} && defined $f{port};
    $f{mac}   = lc $f{mac};
    $f{proto} //= 'tcp';

    my $was = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM ports WHERE mac = ? AND port = ? AND proto = ?",
        undef, $f{mac}, $f{port}, $f{proto}
    );
    if ($was) {
        my @changed;
        if (exists $f{service} && (($was->{service} // '') ne ($f{service} // ''))) {
            push @changed, 'service';
            $self->{dbh}->do(
                "UPDATE ports SET service = ?, last_seen = CURRENT_TIMESTAMP
                  WHERE mac = ? AND port = ? AND proto = ?",
                undef, $f{service}, $f{mac}, $f{port}, $f{proto}
            );
        } else {
            $self->{dbh}->do(
                "UPDATE ports SET last_seen = CURRENT_TIMESTAMP
                  WHERE mac = ? AND port = ? AND proto = ?",
                undef, $f{mac}, $f{port}, $f{proto}
            );
        }
        my $now = $self->{dbh}->selectrow_hashref(
            "SELECT * FROM ports WHERE mac = ? AND port = ? AND proto = ?",
            undef, $f{mac}, $f{port}, $f{proto}
        );
        return { op => @changed ? 'update' : 'noop',
                 changed_fields => \@changed, was => $was, now => $now };
    }
    $self->{dbh}->do(
        "INSERT INTO ports (mac, port, proto, service) VALUES (?, ?, ?, ?)",
        undef, $f{mac}, $f{port}, $f{proto}, $f{service}
    );
    my $now = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM ports WHERE mac = ? AND port = ? AND proto = ?",
        undef, $f{mac}, $f{port}, $f{proto}
    );
    return { op => 'insert', changed_fields => [qw(port service)],
             was => undef, now => $now };
}

sub upsert_ap {
    my ($self, %f) = @_;
    croak "mac required" unless $f{mac};
    $f{mac} = lc $f{mac};
    my $was = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM aps WHERE mac = ?", undef, $f{mac});
    if ($was) {
        my @changed;
        my @set;
        my @bind;
        for my $k (qw(ssid model board exclude)) {
            next unless exists $f{$k};
            my $old = $was->{$k}; my $new = $f{$k};
            next if (!defined $old && !defined $new);
            next if (defined $old && defined $new && $old eq $new);
            push @changed, $k;
            push @set, "$k = ?";
            push @bind, $new;
        }
        push @set, "last_seen = CURRENT_TIMESTAMP";
        $self->{dbh}->do("UPDATE aps SET " . join(', ', @set) . " WHERE mac = ?",
            undef, @bind, $f{mac});
        my $now = $self->{dbh}->selectrow_hashref(
            "SELECT * FROM aps WHERE mac = ?", undef, $f{mac});
        return { op => @changed ? 'update' : 'noop',
                 changed_fields => \@changed, was => $was, now => $now };
    }
    $self->{dbh}->do(
        "INSERT INTO aps (mac, ssid, model, board, exclude) VALUES (?, ?, ?, ?, ?)",
        undef, $f{mac}, $f{ssid}, $f{model}, $f{board}, $f{exclude}
    );
    my $now = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM aps WHERE mac = ?", undef, $f{mac});
    return { op => 'insert', changed_fields => [qw(ssid model board exclude)],
             was => undef, now => $now };
}

sub upsert_association {
    my ($self, %f) = @_;
    croak "ap_mac, client_mac required" unless $f{ap_mac} && $f{client_mac};
    $f{ap_mac}     = lc $f{ap_mac};
    $f{client_mac} = lc $f{client_mac};
    my $was = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM associations WHERE ap_mac = ? AND client_mac = ?",
        undef, $f{ap_mac}, $f{client_mac}
    );
    if ($was) {
        my @set;
        my @bind;
        my @changed;
        for my $k (qw(signal iface ssid)) {
            next unless exists $f{$k};
            my $old = $was->{$k}; my $new = $f{$k};
            next if (!defined $old && !defined $new);
            next if (defined $old && defined $new && $old eq $new);
            push @changed, $k;
            push @set, ($k eq 'signal' ? "`signal` = ?" : "$k = ?");
            push @bind, $new;
        }
        push @set, "last_seen = CURRENT_TIMESTAMP";
        $self->{dbh}->do(
            "UPDATE associations SET " . join(', ', @set)
            . " WHERE ap_mac = ? AND client_mac = ?",
            undef, @bind, $f{ap_mac}, $f{client_mac}
        );
        my $now = $self->{dbh}->selectrow_hashref(
            "SELECT * FROM associations WHERE ap_mac = ? AND client_mac = ?",
            undef, $f{ap_mac}, $f{client_mac}
        );
        return { op => @changed ? 'update' : 'noop',
                 changed_fields => \@changed, was => $was, now => $now };
    }
    $self->{dbh}->do(
        "INSERT INTO associations (ap_mac, client_mac, `signal`, iface, ssid)
         VALUES (?, ?, ?, ?, ?)", undef,
        $f{ap_mac}, $f{client_mac}, $f{signal}, $f{iface}, $f{ssid}
    );
    my $now = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM associations WHERE ap_mac = ? AND client_mac = ?",
        undef, $f{ap_mac}, $f{client_mac}
    );
    return { op => 'insert',
             changed_fields => [qw(ap_mac client_mac signal iface ssid)],
             was => undef, now => $now };
}

sub upsert_lease {
    my ($self, %f) = @_;
    croak "mac, ip required" unless $f{mac} && $f{ip};
    $f{mac} = lc $f{mac};
    my $exp;
    if (defined $f{expires}) {
        # accept epoch seconds; convert to DATETIME
        if ($f{expires} =~ /^\d+$/) {
            my @t = localtime($f{expires});
            $exp = sprintf "%04d-%02d-%02d %02d:%02d:%02d",
                $t[5]+1900, $t[4]+1, $t[3], $t[2], $t[1], $t[0];
        } else { $exp = $f{expires} }
    }

    my $was = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM dhcp_leases WHERE mac = ? AND ip = ?",
        undef, $f{mac}, $f{ip}
    );
    if ($was) {
        my @changed;
        my @set;
        my @bind;
        for my $k (qw(hostname ap_mac)) {
            next unless exists $f{$k};
            my $old = $was->{$k}; my $new = $f{$k};
            next if (!defined $old && !defined $new);
            next if (defined $old && defined $new && $old eq $new);
            push @changed, $k;
            push @set, "$k = ?";
            push @bind, $new;
        }
        if (defined $exp && (($was->{expires} // '') ne $exp)) {
            push @changed, 'expires';
            push @set, "expires = ?";
            push @bind, $exp;
        }
        push @set, "last_seen = CURRENT_TIMESTAMP";
        $self->{dbh}->do(
            "UPDATE dhcp_leases SET " . join(', ', @set)
            . " WHERE mac = ? AND ip = ?",
            undef, @bind, $f{mac}, $f{ip}
        );
        my $now = $self->{dbh}->selectrow_hashref(
            "SELECT * FROM dhcp_leases WHERE mac = ? AND ip = ?",
            undef, $f{mac}, $f{ip}
        );
        return { op => @changed ? 'update' : 'noop',
                 changed_fields => \@changed, was => $was, now => $now };
    }
    $self->{dbh}->do(
        "INSERT INTO dhcp_leases (mac, ip, hostname, expires, ap_mac)
         VALUES (?, ?, ?, ?, ?)", undef,
        $f{mac}, $f{ip}, $f{hostname}, $exp, $f{ap_mac}
    );
    my $now = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM dhcp_leases WHERE mac = ? AND ip = ?",
        undef, $f{mac}, $f{ip}
    );
    return { op => 'insert', changed_fields => [qw(mac ip hostname expires ap_mac)],
             was => undef, now => $now };
}

sub log_event {
    my ($self, %f) = @_;
    croak "type required" unless $f{type};
    $self->{dbh}->do(
        "INSERT INTO events (type, machine_id, mac, addr, details)
         VALUES (?, ?, ?, ?, ?)", undef,
        $f{type}, $f{machine_id}, ($f{mac} ? lc $f{mac} : undef),
        $f{addr}, $f{details}
    );
    return $self->{dbh}->{mysql_insertid};
}

# ---- reads -------------------------------------------------------------

sub get_interface_by_mac {
    my ($self, $mac) = @_;
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM interfaces WHERE mac = ?", undef, lc $mac
    );
}

sub upsert_alias {
    my ($self, %f) = @_;
    croak "name and machine_id required"
        unless defined $f{name} && defined $f{machine_id};
    my $was = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM aliases WHERE name = ?", undef, $f{name});
    if ($was) {
        my @set; my @bind; my @changed;
        for my $k (qw(machine_id prefer_subnet_cidr source notes)) {
            next unless exists $f{$k};
            my $old = $was->{$k}; my $new = $f{$k};
            next if (!defined $old && !defined $new);
            next if (defined $old && defined $new && $old eq $new);
            push @changed, $k;
            push @set, "$k = ?";
            push @bind, $new;
        }
        return { op => 'noop', changed_fields => [], was => $was, now => $was }
            unless @changed;
        $self->{dbh}->do(
            "UPDATE aliases SET " . join(', ', @set) . " WHERE name = ?",
            undef, @bind, $f{name});
        my $now = $self->{dbh}->selectrow_hashref(
            "SELECT * FROM aliases WHERE name = ?", undef, $f{name});
        return { op => 'update', changed_fields => \@changed,
                 was => $was, now => $now };
    }
    $self->{dbh}->do(
        "INSERT INTO aliases (name, machine_id, prefer_subnet_cidr, source, notes)
         VALUES (?, ?, ?, ?, ?)", undef,
        $f{name}, $f{machine_id}, $f{prefer_subnet_cidr},
        $f{source}, $f{notes});
    my $now = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM aliases WHERE name = ?", undef, $f{name});
    return { op => 'insert',
             changed_fields => [qw(name machine_id prefer_subnet_cidr source notes)],
             was => undef, now => $now };
}

sub delete_alias {
    my ($self, $name) = @_;
    return $self->{dbh}->do("DELETE FROM aliases WHERE name = ?", undef, $name);
}

sub upsert_dhcp_var {
    my ($self, %f) = @_;
    croak "name and value required" unless defined $f{name} && defined $f{value};
    $self->{dbh}->do(
        "INSERT INTO dhcp_vars (name, value, notes) VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE value = VALUES(value), notes = VALUES(notes)",
        undef, $f{name}, $f{value}, $f{notes}
    );
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM dhcp_vars WHERE name = ?", undef, $f{name}
    );
}

sub delete_dhcp_var {
    my ($self, $name) = @_;
    return $self->{dbh}->do("DELETE FROM dhcp_vars WHERE name = ?", undef, $name);
}

# isp_links — public-readable. (machine_id, isp_name) is the PK.
# Empty-string fields normalise to NULL so producers can leave keys
# out without overwriting.
sub upsert_isp_link {
    my ($self, %f) = @_;
    croak "gateway_machine_id required" unless defined $f{gateway_machine_id};
    croak "isp_name required"           unless defined $f{isp_name};
    for my $k (qw(iface mac auth_type auth_user notes)) {
        $f{$k} = undef if defined $f{$k} && $f{$k} eq '';
    }
    $f{status} //= 'active';
    $self->{dbh}->do(<<'SQL', undef,
        INSERT INTO isp_links
            (gateway_machine_id, isp_name, iface, mac,
             auth_type, auth_user, status, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
            iface     = VALUES(iface),
            mac       = VALUES(mac),
            auth_type = VALUES(auth_type),
            auth_user = VALUES(auth_user),
            status    = VALUES(status),
            notes     = VALUES(notes)
SQL
        $f{gateway_machine_id}, $f{isp_name}, $f{iface}, $f{mac},
        $f{auth_type}, $f{auth_user}, $f{status}, $f{notes}
    );
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM isp_links
          WHERE gateway_machine_id = ? AND isp_name = ?",
        undef, $f{gateway_machine_id}, $f{isp_name}
    );
}

sub delete_isp_link {
    my ($self, %f) = @_;
    croak "gateway_machine_id required" unless defined $f{gateway_machine_id};
    croak "isp_name required"           unless defined $f{isp_name};
    return $self->{dbh}->do(
        "DELETE FROM isp_links
          WHERE gateway_machine_id = ? AND isp_name = ?",
        undef, $f{gateway_machine_id}, $f{isp_name}
    );
}

# isp_secrets — restricted. The matching isp_links row must exist
# (FK cascades on delete). Caller is responsible for the auth check
# at the protocol layer; this helper just writes.
sub upsert_isp_secret {
    my ($self, %f) = @_;
    croak "gateway_machine_id required" unless defined $f{gateway_machine_id};
    croak "isp_name required"           unless defined $f{isp_name};
    croak "auth_secret required"        unless defined $f{auth_secret};
    $self->{dbh}->do(<<'SQL', undef,
        INSERT INTO isp_secrets (gateway_machine_id, isp_name, auth_secret)
        VALUES (?, ?, ?)
        ON DUPLICATE KEY UPDATE auth_secret = VALUES(auth_secret)
SQL
        $f{gateway_machine_id}, $f{isp_name}, $f{auth_secret}
    );
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM isp_secrets
          WHERE gateway_machine_id = ? AND isp_name = ?",
        undef, $f{gateway_machine_id}, $f{isp_name}
    );
}

# mesh_tunnels: tunnel/uplink topology, cluster-replicated. Fields can be NULL
# (e.g. provider_id only meaningful for he6in4). owner_node + kind = PK. The
# upsert returns { op, now } so Manager::_upsert can fan out a change event to
# subscribers (replication path).
sub upsert_mesh_tunnel {
    my ($self, %f) = @_;
    croak "owner_node required" unless defined $f{owner_node} && length $f{owner_node};
    croak "kind required"       unless defined $f{kind}       && length $f{kind};
    my $was = $self->get_mesh_tunnel($f{owner_node}, $f{kind});
    $self->{dbh}->do(<<'SQL', undef,
        INSERT INTO mesh_tunnels
            (owner_node, kind, provider_id, server_v4,
             tunnel_prefix, routed_prefix, notes, secret_name,
             replicated_from)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
            provider_id     = COALESCE(VALUES(provider_id),     provider_id),
            server_v4       = COALESCE(VALUES(server_v4),       server_v4),
            tunnel_prefix   = COALESCE(VALUES(tunnel_prefix),   tunnel_prefix),
            routed_prefix   = COALESCE(VALUES(routed_prefix),   routed_prefix),
            notes           = COALESCE(VALUES(notes),           notes),
            secret_name     = COALESCE(VALUES(secret_name),     secret_name),
            replicated_from = VALUES(replicated_from)
SQL
        @f{qw(owner_node kind provider_id server_v4
              tunnel_prefix routed_prefix notes secret_name replicated_from)}
    );
    return { op  => ($was ? 'update' : 'insert'),
             now => $self->get_mesh_tunnel($f{owner_node}, $f{kind}) };
}

# Look up the row for one (owner_node, kind). Returns hashref or undef.
sub get_mesh_tunnel {
    my ($self, $owner_node, $kind) = @_;
    return undef unless defined $owner_node && defined $kind;
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM mesh_tunnels WHERE owner_node = ? AND kind = ?",
        undef, $owner_node, $kind
    );
}

# List every tunnel. Optional kind filter.
sub list_mesh_tunnels {
    my ($self, $kind) = @_;
    my $sql = "SELECT * FROM mesh_tunnels";
    my @args;
    if (defined $kind && length $kind) {
        $sql .= " WHERE kind = ?";
        push @args, $kind;
    }
    $sql .= " ORDER BY owner_node, kind";
    return $self->{dbh}->selectall_arrayref($sql, { Slice => {} }, @args);
}

sub delete_mesh_tunnel {
    my ($self, $owner_node, $kind) = @_;
    return $self->{dbh}->do(
        "DELETE FROM mesh_tunnels WHERE owner_node = ? AND kind = ?",
        undef, $owner_node, $kind
    );
}

sub upsert_wifi_socket {
    my ($self, %f) = @_;
    croak "machine_id and outlet required"
        unless defined $f{machine_id} && defined $f{outlet};
    $self->{dbh}->do(
        "INSERT INTO wifi_sockets (machine_id, outlet, name, state, controller_type)
         VALUES (?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE name = VALUES(name),
                                 state = VALUES(state),
                                 controller_type = VALUES(controller_type)",
        undef, $f{machine_id}, $f{outlet}, $f{name}, $f{state}, $f{controller_type}
    );
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM wifi_sockets WHERE machine_id = ? AND outlet = ?",
        undef, $f{machine_id}, $f{outlet}
    );
}

sub delete_wifi_socket {
    my ($self, %f) = @_;
    if (defined $f{outlet}) {
        return $self->{dbh}->do(
            "DELETE FROM wifi_sockets WHERE machine_id = ? AND outlet = ?",
            undef, $f{machine_id}, $f{outlet});
    }
    return $self->{dbh}->do(
        "DELETE FROM wifi_sockets WHERE machine_id = ?",
        undef, $f{machine_id});
}

sub upsert_friendly_name {
    my ($self, %f) = @_;
    croak "machine_id and name required"
        unless defined $f{machine_id} && defined $f{name};
    $self->{dbh}->do(
        "INSERT INTO friendly_names (machine_id, name, notes) VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE name = VALUES(name), notes = VALUES(notes)",
        undef, $f{machine_id}, $f{name}, $f{notes}
    );
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM friendly_names WHERE machine_id = ?",
        undef, $f{machine_id}
    );
}

sub delete_friendly_name {
    my ($self, $mid) = @_;
    return $self->{dbh}->do(
        "DELETE FROM friendly_names WHERE machine_id = ?", undef, $mid);
}

sub upsert_subnet_router {
    my ($self, %f) = @_;
    croak "subnet_cidr and ap_mac required"
        unless defined $f{subnet_cidr} && defined $f{ap_mac};
    $f{ap_mac} = lc $f{ap_mac};
    $f{rank}  //= 0;
    $self->{dbh}->do(
        "INSERT INTO subnet_routers (subnet_cidr, ap_mac, `rank`, notes)
         VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE `rank` = VALUES(`rank`), notes = VALUES(notes)",
        undef, $f{subnet_cidr}, $f{ap_mac}, $f{rank}, $f{notes}
    );
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM subnet_routers WHERE subnet_cidr = ? AND ap_mac = ?",
        undef, $f{subnet_cidr}, $f{ap_mac}
    );
}

sub upsert_lost_device {
    my ($self, %f) = @_;
    croak "subnet, mac, ip, iface required"
        unless defined $f{subnet} && defined $f{mac}
            && defined $f{ip}     && defined $f{iface};
    $f{mac}    = lc $f{mac};
    $f{status} //= 'no-handler';
    $self->{dbh}->do(
        "INSERT INTO lost_devices
            (iface, subnet, ip, mac, vendor, handler, status, last_attempt, notes)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
            iface        = VALUES(iface),
            ip           = VALUES(ip),
            vendor       = COALESCE(VALUES(vendor), vendor),
            handler      = COALESCE(VALUES(handler), handler),
            status       = VALUES(status),
            last_attempt = COALESCE(VALUES(last_attempt), last_attempt),
            notes        = COALESCE(VALUES(notes), notes)",
        undef,
        $f{iface}, $f{subnet}, $f{ip}, $f{mac},
        $f{vendor}, $f{handler}, $f{status}, $f{last_attempt}, $f{notes},
    );
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM lost_devices WHERE subnet = ? AND mac = ?",
        undef, $f{subnet}, $f{mac}
    );
}

sub delete_lost_device {
    my ($self, %f) = @_;
    return $self->{dbh}->do(
        "DELETE FROM lost_devices WHERE subnet = ? AND mac = ?",
        undef, $f{subnet}, lc $f{mac}
    );
}

sub upsert_uplink {
    my ($self, %f) = @_;
    croak "label required" unless defined $f{label};
    $f{role}       //= 'active';
    $f{interval_s} //= ($f{role} eq 'backup' ? 3600 : 60);
    $self->{dbh}->do(
        "INSERT INTO uplinks
            (label, target, via_iface, role, interval_s,
             last_check, last_ok, last_status, last_rtt_ms,
             consecutive_failures, notes)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
            target               = VALUES(target),
            via_iface            = VALUES(via_iface),
            role                 = VALUES(role),
            interval_s           = VALUES(interval_s),
            last_check           = COALESCE(VALUES(last_check),  last_check),
            last_ok              = COALESCE(VALUES(last_ok),     last_ok),
            last_status          = VALUES(last_status),
            last_rtt_ms          = COALESCE(VALUES(last_rtt_ms), last_rtt_ms),
            consecutive_failures = VALUES(consecutive_failures),
            notes                = COALESCE(VALUES(notes),       notes)",
        undef,
        $f{label}, $f{target}, $f{via_iface}, $f{role}, $f{interval_s},
        $f{last_check}, $f{last_ok}, $f{last_status} // 'unknown', $f{last_rtt_ms},
        $f{consecutive_failures} // 0, $f{notes},
    );
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM uplinks WHERE label = ?", undef, $f{label}
    );
}

# Uplinks whose last_check is older than interval_s seconds ago (or
# was never run). Used by net-uplink-probe to pick what to ping each
# minute.
sub uplinks_due {
    my ($self) = @_;
    return $self->{dbh}->selectall_arrayref(
        "SELECT * FROM uplinks
          WHERE last_check IS NULL
             OR last_check < DATE_SUB(NOW(), INTERVAL interval_s SECOND)",
        { Slice => {} }
    );
}

sub upsert_forwarding_rule {
    my ($self, %f) = @_;
    croak "source required"      unless defined $f{source};
    croak "source_host required" unless defined $f{source_host};
    croak "direction required (L/R/D)"
        unless defined $f{direction} && $f{direction} =~ /^[LRD]$/;
    croak "bind_port required" unless defined $f{bind_port};
    $f{bind_addr} //= '*';
    $f{bind_addr}  =  '*' if $f{bind_addr} eq '';

    # All NULL handling delegated to MySQL; we just pass undef through.
    # ON DUPLICATE updates everything that might have changed plus the
    # auto-touched last_seen.  source_pid moves around between restarts
    # of the same ssh process, so we accept the latest reading.
    $self->{dbh}->do(
        "INSERT INTO forwarding_rules
            (source, source_host, source_pid, direction, bind_addr, bind_port,
             target_host, target_port, ssh_user, ssh_host, ssh_port, notes)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
            source       = VALUES(source),
            source_pid   = VALUES(source_pid),
            target_host  = VALUES(target_host),
            target_port  = VALUES(target_port),
            ssh_user     = COALESCE(VALUES(ssh_user),  ssh_user),
            ssh_host     = COALESCE(VALUES(ssh_host),  ssh_host),
            ssh_port     = COALESCE(VALUES(ssh_port),  ssh_port),
            notes        = COALESCE(VALUES(notes),     notes),
            last_seen    = CURRENT_TIMESTAMP",
        undef,
        $f{source}, $f{source_host}, $f{source_pid}, $f{direction},
        $f{bind_addr}, $f{bind_port}, $f{target_host}, $f{target_port},
        $f{ssh_user}, $f{ssh_host}, $f{ssh_port}, $f{notes},
    );
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM forwarding_rules
          WHERE source_host = ? AND direction = ?
            AND bind_addr   = ? AND bind_port = ?",
        undef, $f{source_host}, $f{direction}, $f{bind_addr}, $f{bind_port}
    );
}

sub delete_forwarding_rule {
    my ($self, %f) = @_;
    return $self->{dbh}->do("DELETE FROM forwarding_rules WHERE id = ?",
        undef, $f{id}) if defined $f{id};
    return $self->{dbh}->do(
        "DELETE FROM forwarding_rules
          WHERE source_host = ? AND direction = ?
            AND bind_addr   = ? AND bind_port = ?",
        undef, $f{source_host}, $f{direction},
        ($f{bind_addr} // '*'), $f{bind_port}
    );
}

sub upsert_peer {
    my ($self, %f) = @_;
    croak "host required" unless defined $f{host};
    $f{port}        //= 7531;
    $f{last_status} //= 'reachable';
    $self->{dbh}->do(
        "INSERT INTO peers
            (host, port, last_status, schema_version, started_at, rtt_ms, notes,
             cluster_member)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
            last_status    = VALUES(last_status),
            schema_version = COALESCE(VALUES(schema_version), schema_version),
            started_at     = COALESCE(VALUES(started_at),     started_at),
            rtt_ms         = COALESCE(VALUES(rtt_ms),         rtt_ms),
            notes          = COALESCE(VALUES(notes),          notes),
            cluster_member = COALESCE(VALUES(cluster_member), cluster_member)",
        undef,
        $f{host}, $f{port}, $f{last_status}, $f{schema_version},
        $f{started_at}, $f{rtt_ms}, $f{notes}, $f{cluster_member},
    );
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM peers WHERE host = ? AND port = ?",
        undef, $f{host}, $f{port}
    );
}

sub delete_subnet_router {
    my ($self, %f) = @_;
    return $self->{dbh}->do(
        "DELETE FROM subnet_routers WHERE subnet_cidr = ? AND ap_mac = ?",
        undef, $f{subnet_cidr}, lc $f{ap_mac}
    );
}

sub upsert_zone_class {
    my ($self, %f) = @_;
    croak "name required" unless defined $f{name} && length $f{name};
    $self->{dbh}->do(
        "INSERT INTO zone_classes (name, sort_order, notes) VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE
            sort_order = VALUES(sort_order),
            notes      = COALESCE(VALUES(notes), notes)",
        undef, $f{name}, ($f{sort_order} // 0), $f{notes}
    );
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM zone_classes WHERE name = ?", undef, $f{name}
    );
}

sub delete_zone_class {
    my ($self, $name) = @_;
    return $self->{dbh}->do("DELETE FROM zone_classes WHERE name = ?",
        undef, $name);
}

sub upsert_interface_zone {
    my ($self, %f) = @_;
    croak "host, iface, cidr, zone_class required"
        unless defined $f{host} && defined $f{iface}
            && defined $f{cidr} && defined $f{zone_class};
    $f{zone_name} //= '';
    $self->{dbh}->do(
        "INSERT INTO interface_zones
            (host, iface, cidr, zone_class, zone_name, notes)
         VALUES (?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
            zone_class = VALUES(zone_class),
            zone_name  = VALUES(zone_name),
            notes      = COALESCE(VALUES(notes), notes)",
        undef, $f{host}, $f{iface}, $f{cidr},
        $f{zone_class}, $f{zone_name}, $f{notes}
    );
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM interface_zones
          WHERE host = ? AND iface = ? AND cidr = ?",
        undef, $f{host}, $f{iface}, $f{cidr}
    );
}

sub delete_interface_zone {
    my ($self, %f) = @_;
    return $self->{dbh}->do(
        "DELETE FROM interface_zones
          WHERE host = ? AND iface = ? AND cidr = ?",
        undef, $f{host}, $f{iface}, $f{cidr}
    );
}

sub upsert_wifi_zone {
    my ($self, %f) = @_;
    croak "ssid, zone_class required"
        unless defined $f{ssid} && defined $f{zone_class};
    $f{zone_name} //= '';
    $self->{dbh}->do(
        "INSERT INTO wifi_zones (ssid, zone_class, zone_name, notes)
         VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
            zone_class = VALUES(zone_class),
            zone_name  = VALUES(zone_name),
            notes      = COALESCE(VALUES(notes), notes)",
        undef, $f{ssid}, $f{zone_class}, $f{zone_name}, $f{notes}
    );
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM wifi_zones WHERE ssid = ?", undef, $f{ssid}
    );
}

sub delete_wifi_zone {
    my ($self, $ssid) = @_;
    return $self->{dbh}->do("DELETE FROM wifi_zones WHERE ssid = ?",
        undef, $ssid);
}

sub upsert_audit_annotation {
    my ($self, %f) = @_;
    croak "kind required" unless defined $f{kind} && length $f{kind};
    croak "port required" unless defined $f{port};
    $f{host} //= '';
    $f{addr} //= '*';
    $f{addr}   = '*' if $f{addr} eq '';
    $self->{dbh}->do(
        "INSERT INTO audit_annotations (kind, host, addr, port, reason)
         VALUES (?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
            reason = COALESCE(VALUES(reason), reason)",
        undef, $f{kind}, $f{host}, $f{addr}, $f{port}, $f{reason}
    );
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM audit_annotations
          WHERE kind = ? AND host = ? AND addr = ? AND port = ?",
        undef, $f{kind}, $f{host}, $f{addr}, $f{port}
    );
}

sub delete_audit_annotation {
    my ($self, %f) = @_;
    croak "kind, port required" unless defined $f{kind} && defined $f{port};
    $f{host} //= '';
    $f{addr} //= '*';
    return $self->{dbh}->do(
        "DELETE FROM audit_annotations
          WHERE kind = ? AND host = ? AND addr = ? AND port = ?",
        undef, $f{kind}, $f{host}, $f{addr}, $f{port}
    );
}

sub upsert_wifi_radio_state {
    my ($self, %f) = @_;
    croak "scanner_mac, scanner_iface required"
        unless defined $f{scanner_mac} && defined $f{scanner_iface};
    $f{scanner_mac} = lc $f{scanner_mac};
    $self->{dbh}->do(
        "INSERT INTO wifi_radio_state
            (scanner_mac, scanner_iface, band, current_channel)
         VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
            band            = COALESCE(VALUES(band),            band),
            current_channel = COALESCE(VALUES(current_channel), current_channel)",
        undef,
        $f{scanner_mac}, $f{scanner_iface},
        $f{band}, $f{current_channel},
    );
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM wifi_radio_state
          WHERE scanner_mac = ? AND scanner_iface = ?",
        undef, $f{scanner_mac}, $f{scanner_iface}
    );
}

sub upsert_wifi_scan_result {
    my ($self, %f) = @_;
    croak "scanner_mac, scanner_iface, bssid required"
        unless defined $f{scanner_mac}
            && defined $f{scanner_iface}
            && defined $f{bssid};
    $f{scanner_mac} = lc $f{scanner_mac};
    $f{bssid}       = lc $f{bssid};
    $self->{dbh}->do(
        "INSERT INTO wifi_scan_results
            (scanner_mac, scanner_iface, bssid, ssid, channel, band,
             rssi_dbm, encryption, bandwidth_mhz)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
            ssid          = COALESCE(VALUES(ssid),          ssid),
            channel       = COALESCE(VALUES(channel),       channel),
            band          = COALESCE(VALUES(band),          band),
            rssi_dbm      = COALESCE(VALUES(rssi_dbm),      rssi_dbm),
            encryption    = COALESCE(VALUES(encryption),    encryption),
            bandwidth_mhz = COALESCE(VALUES(bandwidth_mhz), bandwidth_mhz)",
        undef,
        $f{scanner_mac}, $f{scanner_iface}, $f{bssid},
        $f{ssid}, $f{channel}, $f{band}, $f{rssi_dbm},
        $f{encryption}, $f{bandwidth_mhz},
    );
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM wifi_scan_results
          WHERE scanner_mac = ? AND scanner_iface = ? AND bssid = ?",
        undef, $f{scanner_mac}, $f{scanner_iface}, $f{bssid}
    );
}

# ---- net-chat ---------------------------------------------------------
#
# Session control + message log + ephemeral presence. The UPSERT-style
# methods return the same { op, now } shape the daemon's _emit_change
# expects, so chat rows stream to subscribers exactly like every other
# table.

sub get_chat_session {
    my ($self, $name) = @_;
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM chat_sessions WHERE name = ?", undef, $name);
}

# Create a session. op => 'insert' on success, 'exists' if the name is
# already taken (caller reports ERR). access_mode defaults to 'open'.
sub open_chat_session {
    my ($self, %f) = @_;
    croak "name required"       unless defined $f{name} && length $f{name};
    croak "created_by required" unless defined $f{created_by} && length $f{created_by};
    my $mode = $f{access_mode} // 'open';
    croak "bad access_mode '$mode'" unless $mode =~ /^(open|list|request)$/;
    if (my $was = $self->get_chat_session($f{name})) {
        return { op => 'exists', now => $was };
    }
    $self->{dbh}->do(
        "INSERT INTO chat_sessions (name, topic, created_by, access_mode)
         VALUES (?, ?, ?, ?)",
        undef, $f{name}, $f{topic}, $f{created_by}, $mode);
    return { op => 'insert', now => $self->get_chat_session($f{name}) };
}

# Update topic and/or access_mode on an existing session.
sub set_chat_session {
    my ($self, %f) = @_;
    croak "name required" unless defined $f{name};
    my @set; my @bind;
    if (exists $f{access_mode} && defined $f{access_mode}) {
        croak "bad access_mode '$f{access_mode}'"
            unless $f{access_mode} =~ /^(open|list|request)$/;
        push @set, "access_mode = ?"; push @bind, $f{access_mode};
    }
    if (exists $f{topic}) { push @set, "topic = ?"; push @bind, $f{topic}; }
    return { op => 'noop', now => $self->get_chat_session($f{name}) } unless @set;
    $self->{dbh}->do(
        "UPDATE chat_sessions SET " . join(', ', @set) . " WHERE name = ?",
        undef, @bind, $f{name});
    return { op => 'update', now => $self->get_chat_session($f{name}) };
}

sub close_chat_session {
    my ($self, $name) = @_;
    my $was = $self->get_chat_session($name) or return { op => 'noop' };
    return { op => 'noop', now => $was } if $was->{status} eq 'closed';
    $self->{dbh}->do(
        "UPDATE chat_sessions SET status = 'closed', closed_at = CURRENT_TIMESTAMP
          WHERE name = ?", undef, $name);
    return { op => 'update', now => $self->get_chat_session($name) };
}

# Reopen a closed session: flip status back to 'open', clear closed_at, and
# optionally update access_mode/topic. The inverse of close_chat_session.
sub reopen_chat_session {
    my ($self, $name, %f) = @_;
    croak "name required" unless defined $name && length $name;
    my @set  = ("status = 'open'", "closed_at = NULL");
    my @bind;
    if (exists $f{access_mode} && defined $f{access_mode}) {
        croak "bad access_mode '$f{access_mode}'"
            unless $f{access_mode} =~ /^(open|list|request)$/;
        push @set, "access_mode = ?"; push @bind, $f{access_mode};
    }
    if (exists $f{topic} && defined $f{topic}) {
        push @set, "topic = ?"; push @bind, $f{topic};
    }
    $self->{dbh}->do(
        "UPDATE chat_sessions SET " . join(', ', @set) . " WHERE name = ?",
        undef, @bind, $name);
    return { op => 'reopen', now => $self->get_chat_session($name) };
}

# Delete a session and (via FK ON DELETE CASCADE) its members, messages, and
# presence. Returns the row that was deleted, or undef if it didn't exist.
sub delete_chat_session {
    my ($self, $name) = @_;
    my $was = $self->get_chat_session($name) or return undef;
    $self->{dbh}->do("DELETE FROM chat_sessions WHERE name = ?", undef, $name);
    return $was;
}

sub touch_chat_activity {
    my ($self, $name) = @_;
    $self->{dbh}->do(
        "UPDATE chat_sessions SET last_activity = CURRENT_TIMESTAMP WHERE name = ?",
        undef, $name);
}

sub delete_chat_member {
    my ($self, $session, $principal) = @_;
    return unless defined $session && defined $principal;
    my $n = $self->{dbh}->do(
        "DELETE FROM chat_members WHERE session = ? AND principal = ?",
        undef, $session, $principal);
    return { session => $session, principal => $principal,
             deleted => ($n && $n > 0) ? 1 : 0 };
}

sub get_chat_member {
    my ($self, $session, $principal) = @_;
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM chat_members WHERE session = ? AND principal = ?",
        undef, $session, $principal);
}

# Upsert a membership row. Pass role/state/added_by as wanted; the
# requested_at / joined_at stamps are filled in for the relevant state.
sub set_chat_member {
    my ($self, %f) = @_;
    croak "session + principal required"
        unless defined $f{session} && defined $f{principal};
    my $role  = $f{role}  // 'member';
    my $state = $f{state} // 'member';
    my $req_at  = $state eq 'requested' ? 'CURRENT_TIMESTAMP' : 'NULL';
    my $join_at = $state eq 'member'    ? 'CURRENT_TIMESTAMP' : 'NULL';
    # request_pubkey carries the SSH pubkey supplied with an unverified join
    # request; the request handler stashes it here, the approval handler
    # transfers it to chat_authorized_keys and CLEARs this column (so the
    # ephemeral key sits on the requested row only as long as it's pending).
    $self->{dbh}->do(
        "INSERT INTO chat_members
            (session, principal, role, state, added_by, requested_at, joined_at,
             request_pubkey, requested_from)
         VALUES (?, ?, ?, ?, ?, $req_at, $join_at, ?, ?)
         ON DUPLICATE KEY UPDATE
            role           = VALUES(role),
            state          = VALUES(state),
            added_by       = VALUES(added_by),
            requested_at   = COALESCE(VALUES(requested_at), requested_at),
            joined_at      = COALESCE(VALUES(joined_at),    joined_at),
            request_pubkey = COALESCE(VALUES(request_pubkey), request_pubkey),
            requested_from = COALESCE(VALUES(requested_from), requested_from)",
        undef, $f{session}, $f{principal}, $role, $state, $f{added_by},
        $f{request_pubkey}, $f{requested_from});
    return { op => 'update', now => $self->get_chat_member($f{session}, $f{principal}) };
}

# Clear request_pubkey on a chat_members row (called after the pubkey has been
# moved to chat_authorized_keys at approval time).
sub clear_chat_member_request_pubkey {
    my ($self, $session, $principal) = @_;
    $self->{dbh}->do(
        "UPDATE chat_members SET request_pubkey = NULL
          WHERE session = ? AND principal = ?",
        undef, $session, $principal);
}

# ---- per-chat authorized SSH keys (schema v25) ------------------------

sub get_chat_authorized_key {
    my ($self, $session, $key_id) = @_;
    return undef unless defined $session && defined $key_id;
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM chat_authorized_keys WHERE session = ? AND key_id = ?",
        undef, $session, $key_id);
}

# Authorize (or refresh the metadata of) an SSH key for a chat. Idempotent.
sub add_chat_authorized_key {
    my ($self, %f) = @_;
    croak "session + key_id required"
        unless defined $f{session} && defined $f{key_id};
    # pubkey is the OpenSSH-format public key ("ssh-ed25519 AAAA..." [ comment]),
    # exactly the line ssh-keygen -Y verify reads from an allowed_signers file.
    # When supplied, the chat-key AUTH fallthrough (NetMgr::Auth's signers list)
    # can recognise the key on a future connect without it being in any of the
    # /etc/net-mgr/allowed_* files.
    $self->{dbh}->do(
        "INSERT INTO chat_authorized_keys
            (session, key_id, key_type, label, added_by, pubkey)
         VALUES (?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
            key_type = VALUES(key_type),
            label    = VALUES(label),
            added_by = VALUES(added_by),
            pubkey   = COALESCE(VALUES(pubkey), pubkey)",
        undef, $f{session}, $f{key_id}, ($f{key_type} // ''),
        ($f{label} // ''), $f{added_by}, $f{pubkey});
    return $self->get_chat_authorized_key($f{session}, $f{key_id});
}

# Every chat_authorized_keys row that includes a pubkey — for the chat-key
# AUTH fallthrough. Optional $key_id arg narrows to just the rows for that
# fingerprint, which is what the AUTH handler always wants. Each return
# entry has session, key_id, key_type, pubkey, label.
sub list_chat_authorized_pubkeys {
    my ($self, $key_id) = @_;
    if (defined $key_id && length $key_id) {
        return $self->{dbh}->selectall_arrayref(
            "SELECT session, key_id, key_type, pubkey, label
               FROM chat_authorized_keys
              WHERE pubkey IS NOT NULL AND pubkey <> ''
                AND key_id = ?",
            { Slice => {} }, $key_id
        );
    }
    return $self->{dbh}->selectall_arrayref(
        "SELECT session, key_id, key_type, pubkey, label
           FROM chat_authorized_keys
          WHERE pubkey IS NOT NULL AND pubkey <> ''",
        { Slice => {} }
    );
}

sub remove_chat_authorized_key {
    my ($self, $session, $key_id) = @_;
    $self->{dbh}->do(
        "DELETE FROM chat_authorized_keys WHERE session = ? AND key_id = ?",
        undef, $session, $key_id);
}

sub list_chat_authorized_keys {
    my ($self, $session) = @_;
    return $self->{dbh}->selectall_arrayref(
        "SELECT session, key_id, key_type, label, added_by, added_at
           FROM chat_authorized_keys WHERE session = ? ORDER BY label, key_id",
        { Slice => {} }, $session) || [];
}

# All messages of a session, oldest first — for moving them to the archive.
sub get_chat_messages {
    my ($self, $session) = @_;
    return $self->{dbh}->selectall_arrayref(
        "SELECT id, session, ts, sender, sender_kind, body, in_reply_to
           FROM chat_messages WHERE session = ? ORDER BY id",
        { Slice => {} }, $session);
}

# Delete every message of a session (when moving them out to the archive).
sub delete_chat_messages {
    my ($self, $session) = @_;
    $self->{dbh}->do("DELETE FROM chat_messages WHERE session = ?", undef, $session);
}

# Re-insert an archived message verbatim — preserving id and ts so reply
# chains and ordering survive a close/resurrect round trip.
sub restore_chat_message {
    my ($self, %f) = @_;
    croak "session + sender + body required"
        unless defined $f{session} && defined $f{sender} && defined $f{body};
    $self->{dbh}->do(
        "INSERT INTO chat_messages
            (id, session, ts, sender, sender_kind, body, in_reply_to)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
        undef, $f{id}, $f{session}, $f{ts}, $f{sender},
        ($f{sender_kind} // 'agent'), $f{body}, $f{in_reply_to});
}

# Append a message. Returns the persisted row (with id + ts) so the
# daemon can emit it to subscribers.
sub insert_chat_message {
    my ($self, %f) = @_;
    croak "session + sender + body required"
        unless defined $f{session} && defined $f{sender} && defined $f{body};
    my $kind = $f{sender_kind} // 'agent';
    $self->{dbh}->do(
        "INSERT INTO chat_messages (session, sender, sender_kind, body, in_reply_to)
         VALUES (?, ?, ?, ?, ?)",
        undef, $f{session}, $f{sender}, $kind, $f{body}, $f{in_reply_to});
    my $id = $self->{dbh}->{mysql_insertid};
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM chat_messages WHERE id = ?", undef, $id);
}

# Presence join. op => 'insert' for a new (session, conn) pair, else
# 'noop'. now is the row (for emit).
sub upsert_chat_presence {
    my ($self, %f) = @_;
    croak "session + conn_id + principal required"
        unless defined $f{session} && defined $f{conn_id} && defined $f{principal};
    my $was = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM chat_presence WHERE session = ? AND conn_id = ?",
        undef, $f{session}, $f{conn_id});
    return { op => 'noop', now => $was } if $was;
    $self->{dbh}->do(
        "INSERT INTO chat_presence (session, conn_id, principal) VALUES (?, ?, ?)",
        undef, $f{session}, $f{conn_id}, $f{principal});
    my $now = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM chat_presence WHERE session = ? AND conn_id = ?",
        undef, $f{session}, $f{conn_id});
    return { op => 'insert', now => $now };
}

# Remove one (session, conn) presence row. Returns the removed row (for
# a 'delete' emit) or undef if there was none.
sub delete_chat_presence {
    my ($self, $session, $conn_id) = @_;
    my $row = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM chat_presence WHERE session = ? AND conn_id = ?",
        undef, $session, $conn_id) or return undef;
    $self->{dbh}->do(
        "DELETE FROM chat_presence WHERE session = ? AND conn_id = ?",
        undef, $session, $conn_id);
    return $row;
}

# Remove every presence row for a connection (on disconnect). Returns
# the arrayref of removed rows so the caller can emit one delete each.
sub delete_presence_for_conn {
    my ($self, $conn_id) = @_;
    my $rows = $self->{dbh}->selectall_arrayref(
        "SELECT * FROM chat_presence WHERE conn_id = ?",
        { Slice => {} }, $conn_id);
    if (@$rows) {
        $self->{dbh}->do("DELETE FROM chat_presence WHERE conn_id = ?",
                         undef, $conn_id);
    }
    return $rows;
}

# Wipe all presence (daemon startup — every prior connection is gone).
sub clear_chat_presence {
    my ($self) = @_;
    $self->{dbh}->do("DELETE FROM chat_presence");
}

# ---- DB-native DHCP plan: ranges + reservations (schema v24) ---------
#
# These return the {op, now} shape so the daemon's _upsert/_emit_change
# pipeline streams changes to subscribers (the net-reserve GUI) and the
# cluster relay carries them to peers.

# All dynamic-pool ranges, optionally for one subnet. Oldest-stable order.
sub get_dhcp_ranges {
    my ($self, $subnet) = @_;
    return $self->{dbh}->selectall_arrayref(
        "SELECT * FROM dhcp_ranges"
        . ($subnet ? " WHERE subnet_cidr = ?" : "")
        . " ORDER BY subnet_cidr, INET_ATON(start_ip)",
        { Slice => {} }, ($subnet ? ($subnet) : ()));
}

# Upsert one dynamic range. Keyed by (subnet_cidr, start_ip).
sub upsert_dhcp_range {
    my ($self, %f) = @_;
    croak "subnet_cidr + start_ip + end_ip required"
        unless defined $f{subnet_cidr} && defined $f{start_ip}
            && defined $f{end_ip};
    my $was = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM dhcp_ranges WHERE subnet_cidr = ? AND start_ip = ?",
        undef, $f{subnet_cidr}, $f{start_ip});
    $self->{dbh}->do(
        "INSERT INTO dhcp_ranges (subnet_cidr, start_ip, end_ip, zone, notes)
         VALUES (?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
            end_ip = VALUES(end_ip),
            zone   = VALUES(zone),
            notes  = VALUES(notes)",
        undef, $f{subnet_cidr}, $f{start_ip}, $f{end_ip},
        $f{zone}, $f{notes});
    my $now = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM dhcp_ranges WHERE subnet_cidr = ? AND start_ip = ?",
        undef, $f{subnet_cidr}, $f{start_ip});
    return { op => ($was ? 'update' : 'insert'), now => $now };
}

# Remove one dynamic range. Returns the deleted row (for a delete emit) or undef.
sub delete_dhcp_range {
    my ($self, $subnet, $start) = @_;
    my $row = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM dhcp_ranges WHERE subnet_cidr = ? AND start_ip = ?",
        undef, $subnet, $start) or return undef;
    $self->{dbh}->do(
        "DELETE FROM dhcp_ranges WHERE subnet_cidr = ? AND start_ip = ?",
        undef, $subnet, $start);
    return $row;
}

# All reservations, optionally for one subnet.
sub get_dhcp_reservations {
    my ($self, $subnet) = @_;
    return $self->{dbh}->selectall_arrayref(
        "SELECT * FROM dhcp_reservations"
        . ($subnet ? " WHERE subnet_cidr = ?" : "")
        . " ORDER BY INET_ATON(ip)",
        { Slice => {} }, ($subnet ? ($subnet) : ()));
}

sub get_dhcp_reservation {
    my ($self, $ip) = @_;
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM dhcp_reservations WHERE ip = ?", undef, $ip);
}

# The reservation currently held by $mac (lowest IP if somehow several), or
# undef. Used to enforce one reservation per MAC.
sub dhcp_reservation_for_mac {
    my ($self, $mac) = @_;
    return undef unless defined $mac && length $mac;
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM dhcp_reservations WHERE mac = ? ORDER BY INET_ATON(ip) LIMIT 1",
        undef, lc $mac);
}

# Best host name for a MAC: the primary_name of the machine it's correlated to,
# or undef when the MAC is unknown / uncorrelated. Used to auto-name reservations.
sub name_for_mac {
    my ($self, $mac) = @_;
    return undef unless defined $mac && length $mac;
    my ($name) = $self->{dbh}->selectrow_array(
        "SELECT m.primary_name
           FROM interfaces i JOIN machines m ON m.id = i.machine_id
          WHERE i.mac = ? AND m.primary_name IS NOT NULL AND m.primary_name <> ''
          LIMIT 1", undef, lc $mac);
    return $name;
}

# Upsert one reservation, keyed by IP (one device per address). mac is
# stored lowercased to match interfaces/addresses.
sub upsert_dhcp_reservation {
    my ($self, %f) = @_;
    croak "ip + mac required" unless defined $f{ip} && defined $f{mac};
    my $mac = lc $f{mac};
    my $was = $self->get_dhcp_reservation($f{ip});
    $self->{dbh}->do(
        "INSERT INTO dhcp_reservations
            (ip, mac, name, subnet_cidr, grp, notes, updated_by)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
            mac         = VALUES(mac),
            name        = VALUES(name),
            subnet_cidr = VALUES(subnet_cidr),
            grp         = VALUES(grp),
            notes       = VALUES(notes),
            updated_by  = VALUES(updated_by)",
        undef, $f{ip}, $mac, $f{name}, $f{subnet_cidr},
        $f{grp}, $f{notes}, $f{updated_by});
    return { op => ($was ? 'update' : 'insert'),
             now => $self->get_dhcp_reservation($f{ip}) };
}

# Remove a reservation by IP. Returns the deleted row or undef.
sub delete_dhcp_reservation {
    my ($self, $ip) = @_;
    my $row = $self->get_dhcp_reservation($ip) or return undef;
    $self->{dbh}->do("DELETE FROM dhcp_reservations WHERE ip = ?", undef, $ip);
    return $row;
}

# Move a reservation from $old to $new IP, carrying its mac/name/grp/notes.
# Atomic (the device never has two reservations mid-flight). Returns:
#   undef                          — nothing reserved at $old
#   { error => 'occupied', ... }   — $new already holds a different reservation
#   { old => $oldrow, new => $newrow } — moved
# %opts: subnet_cidr (for the new /24), updated_by.
sub move_dhcp_reservation {
    my ($self, $old, $new, %opts) = @_;
    return undef if $old eq $new;     # no-op handled by caller as success
    my $row = $self->get_dhcp_reservation($old) or return undef;
    my $at_new = $self->get_dhcp_reservation($new);
    return { error => 'occupied', new => $at_new } if $at_new;
    $self->{dbh}->begin_work;
    eval {
        $self->{dbh}->do(
            "INSERT INTO dhcp_reservations
                (ip, mac, name, subnet_cidr, grp, notes, updated_by)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            undef, $new, $row->{mac}, $row->{name},
            ($opts{subnet_cidr} // $row->{subnet_cidr}),
            $row->{grp}, $row->{notes}, ($opts{updated_by} // $row->{updated_by}));
        $self->{dbh}->do("DELETE FROM dhcp_reservations WHERE ip = ?", undef, $old);
        $self->{dbh}->commit;
        1;
    } or do { my $e = $@; eval { $self->{dbh}->rollback }; croak "move failed: $e"; };
    return { old => $row, new => $self->get_dhcp_reservation($new) };
}

sub query_table {
    my ($self, $table, %opts) = @_;
    my %allowed = map { $_ => 1 } qw(
        machines hostnames interfaces addresses ports aps
        associations dhcp_leases events aliases dhcp_vars
        subnet_routers friendly_names wifi_sockets lost_devices
        peers uplinks isp_links isp_secrets forwarding_rules
        zone_classes interface_zones wifi_zones
        audit_annotations wifi_scan_results wifi_radio_state
        chat_sessions chat_members chat_messages chat_presence
        chat_authorized_keys
        host_keys dhcp_ranges dhcp_reservations
        mesh_tunnels node_capabilities
    );
    croak "unknown table '$table'" unless $allowed{$table};
    my $cols = $opts{cols};
    my $sql  = $cols ? "SELECT " . join(', ', @$cols) . " FROM $table"
                     : "SELECT * FROM $table";
    my @bind;
    # since_epoch lets the caller cap a snapshot to recent rows on
    # tables with a 'ts' column (events). Without this, ping logging
    # at ~2/s × 7d = ~1.3M rows would all stream over the socket on
    # every subscribe, blocking net-watch startup for tens of seconds.
    if ($opts{since_epoch} && _has_ts_column($table)) {
        $sql .= " WHERE ts > FROM_UNIXTIME(?)";
        push @bind, $opts{since_epoch};
    }
    return $self->{dbh}->selectall_arrayref($sql, { Slice => {} }, @bind);
}

sub _has_ts_column { $_[0] eq 'events' || $_[0] eq 'chat_messages' }

# Delete events older than $days. Returns rowcount.
sub purge_events {
    my ($self, %f) = @_;
    my $days = $f{days} // 7;
    return $self->{dbh}->do(
        "DELETE FROM events WHERE ts < DATE_SUB(NOW(), INTERVAL ? DAY)",
        undef, $days
    );
}

# Drop DHCP leases past their `expires`. NULL/empty expires (static binding)
# is kept. Returns the count of rows deleted.
sub purge_expired_leases {
    my ($self) = @_;
    my $n = $self->{dbh}->do(
        "DELETE FROM dhcp_leases
          WHERE expires IS NOT NULL AND expires < NOW()"
    );
    return ($n && $n > 0) ? $n + 0 : 0;
}

# Drop hostname rows whose last_seen is older than $days. Returns the count.
# Caller usually pairs this with purge_conflicting_hostnames so a stale row
# that ALSO has a fresher rival on a different machine gets caught even when
# under the age threshold.
sub purge_stale_hostnames {
    my ($self, %f) = @_;
    my $days = $f{days} // 30;
    my $n = $self->{dbh}->do(
        "DELETE FROM hostnames WHERE last_seen < DATE_SUB(NOW(), INTERVAL ? DAY)",
        undef, $days);
    return ($n && $n > 0) ? $n + 0 : 0;
}

# Resolve hostname conflicts: when the SAME name is bound to multiple
# machine_ids, keep the row with the most recent last_seen and drop the rest.
# Exactly the clevo-lx/machine_75 situation. Returns the count of losers
# dropped (zero when there are no conflicts).
sub purge_conflicting_hostnames {
    my ($self) = @_;
    my $rows = $self->{dbh}->selectall_arrayref(
        "SELECT name FROM hostnames
          GROUP BY name HAVING COUNT(DISTINCT machine_id) > 1",
        { Slice => {} });
    return 0 unless $rows && @$rows;
    my $dropped = 0;
    for my $r (@$rows) {
        my $name = $r->{name};
        # Find the latest last_seen for this name.
        my ($keep_mid) = $self->{dbh}->selectrow_array(
            "SELECT machine_id FROM hostnames
              WHERE name = ?
              ORDER BY last_seen DESC, machine_id ASC LIMIT 1",
            undef, $name);
        next unless defined $keep_mid;
        my $n = $self->{dbh}->do(
            "DELETE FROM hostnames WHERE name = ? AND machine_id <> ?",
            undef, $name, $keep_mid);
        $dropped += $n if $n && $n > 0;
    }
    return $dropped;
}

# Drop address rows that haven't been seen in $days days. Requires BOTH
# last_seen old AND (last_observed older or NULL) — last_observed is the
# "live" timestamp; if a producer just touched the row by writing the same
# data, last_seen may bump even though last_observed is months old. Sticky
# manual rows (source='manual') are kept regardless.
sub purge_stale_addresses {
    my ($self, %f) = @_;
    my $days = $f{days} // 30;
    my $n = $self->{dbh}->do(
        "DELETE FROM addresses
          WHERE last_seen < DATE_SUB(NOW(), INTERVAL ? DAY)
            AND (last_observed IS NULL
                 OR last_observed < DATE_SUB(NOW(), INTERVAL ? DAY))
            AND (source IS NULL OR source <> 'manual')",
        undef, $days, $days);
    return ($n && $n > 0) ? $n + 0 : 0;
}

# Dry-run variants: same predicates as the purge_* above, but return a count
# without deleting. Used by net-purge to preview impact before --commit.
sub count_expired_leases {
    my ($self) = @_;
    my ($n) = $self->{dbh}->selectrow_array(
        "SELECT COUNT(*) FROM dhcp_leases
          WHERE expires IS NOT NULL AND expires < NOW()");
    return $n // 0;
}
sub count_stale_hostnames {
    my ($self, %f) = @_;
    my $days = $f{days} // 30;
    my ($n) = $self->{dbh}->selectrow_array(
        "SELECT COUNT(*) FROM hostnames
          WHERE last_seen < DATE_SUB(NOW(), INTERVAL ? DAY)", undef, $days);
    return $n // 0;
}
sub count_conflicting_hostnames {
    my ($self) = @_;
    my $rows = $self->{dbh}->selectall_arrayref(
        "SELECT name, COUNT(DISTINCT machine_id) c FROM hostnames
          GROUP BY name HAVING c > 1", { Slice => {} });
    return 0 unless $rows && @$rows;
    my $n = 0; $n += ($_->{c} - 1) for @$rows;       # losers per name
    return $n;
}
sub count_stale_addresses {
    my ($self, %f) = @_;
    my $days = $f{days} // 30;
    my ($n) = $self->{dbh}->selectrow_array(
        "SELECT COUNT(*) FROM addresses
          WHERE last_seen < DATE_SUB(NOW(), INTERVAL ? DAY)
            AND (last_observed IS NULL
                 OR last_observed < DATE_SUB(NOW(), INTERVAL ? DAY))
            AND (source IS NULL OR source <> 'manual')",
        undef, $days, $days);
    return $n // 0;
}

# ---- node_capabilities (schema v32) ------------------------------------

# Fetch the capability row for one mesh member (returns hashref or undef).
sub get_node_capabilities {
    my ($self, $member) = @_;
    return unless defined $member && length $member;
    return $self->{dbh}->selectrow_hashref(
        "SELECT * FROM node_capabilities WHERE member = ?", undef, $member);
}

# List all known members with their capabilities. Handy for
# net-cluster --capable=<x> and for the STATUS-time render.
sub list_node_capabilities {
    my ($self) = @_;
    return $self->{dbh}->selectall_arrayref(
        "SELECT member, capabilities, updated_at, replicated_from
           FROM node_capabilities
          ORDER BY member", { Slice => {} }) || [];
}

# Upsert one member's capabilities. Writers: the master's _handle_heartbeat
# (member=peer, replicated_from=undef) and REFRESH replication paths
# (replicated_from=source of the copy). caps is a comma-separated string:
#   'ble,ipv6,gateway'
sub set_node_capabilities {
    my ($self, %f) = @_;
    croak "member required" unless defined $f{member} && length $f{member};
    my $caps = $f{capabilities} // '';
    $self->{dbh}->do(
        "INSERT INTO node_capabilities (member, capabilities, replicated_from)
         VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE
            capabilities    = VALUES(capabilities),
            replicated_from = COALESCE(VALUES(replicated_from), replicated_from)",
        undef, $f{member}, $caps, $f{replicated_from});
    return { op => 'update', now => $self->get_node_capabilities($f{member}) };
}

1;
