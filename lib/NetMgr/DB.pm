package NetMgr::DB;
# DBI wrapper for net-mgr. Connects via /root/.my.cnf [<section>],
# bootstraps the schema if absent, and exposes UPSERT helpers that
# return change-info so the daemon can emit transition events.

use strict;
use warnings;
use Carp qw(croak);
use DBI;
use FindBin;

our $SCHEMA_VERSION = 20;

sub new {
    my ($class, %args) = @_;
    my $self = bless {
        defaults_file => $args{defaults_file} // '/root/.my.cnf',
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
    croak "no migration for schema v$v";
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

    $self->{dbh}->do(
        "UPDATE addresses
            SET last_rtt_ms   = ?,
                min_rtt_ms    = LEAST(IFNULL(min_rtt_ms, ?), ?),
                last_observed = CURRENT_TIMESTAMP,
                last_seen     = CURRENT_TIMESTAMP
          WHERE mac = ? AND family = ? AND addr = ?",
        undef, $rtt, $rtt, $rtt, $mac, $family, $addr
    );
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
        for my $k (qw(ssid model board)) {
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
        "INSERT INTO aps (mac, ssid, model, board) VALUES (?, ?, ?, ?)",
        undef, $f{mac}, $f{ssid}, $f{model}, $f{board}
    );
    my $now = $self->{dbh}->selectrow_hashref(
        "SELECT * FROM aps WHERE mac = ?", undef, $f{mac});
    return { op => 'insert', changed_fields => [qw(ssid model board)],
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
            (host, port, last_status, schema_version, started_at, rtt_ms, notes)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
            last_status    = VALUES(last_status),
            schema_version = COALESCE(VALUES(schema_version), schema_version),
            started_at     = COALESCE(VALUES(started_at),     started_at),
            rtt_ms         = COALESCE(VALUES(rtt_ms),         rtt_ms),
            notes          = COALESCE(VALUES(notes),          notes)",
        undef,
        $f{host}, $f{port}, $f{last_status}, $f{schema_version},
        $f{started_at}, $f{rtt_ms}, $f{notes},
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

sub query_table {
    my ($self, $table, %opts) = @_;
    my %allowed = map { $_ => 1 } qw(
        machines hostnames interfaces addresses ports aps
        associations dhcp_leases events aliases dhcp_vars
        subnet_routers friendly_names wifi_sockets lost_devices
        peers uplinks forwarding_rules
        zone_classes interface_zones wifi_zones
        audit_annotations wifi_scan_results wifi_radio_state
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

sub _has_ts_column { $_[0] eq 'events' }

# Delete events older than $days. Returns rowcount.
sub purge_events {
    my ($self, %f) = @_;
    my $days = $f{days} // 7;
    return $self->{dbh}->do(
        "DELETE FROM events WHERE ts < DATE_SUB(NOW(), INTERVAL ? DAY)",
        undef, $days
    );
}

1;
