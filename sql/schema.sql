-- net-mgr MySQL/MariaDB schema (v1)
-- Bootstrapped by NetMgr::DB on first run.
--
-- Conventions:
--   mac:  CHAR(17), lowercase canonical form 'aa:bb:cc:dd:ee:ff'
--   addr: VARCHAR(45), canonical string form for both v4 and v6
--   timestamps: DATETIME UTC; converted to/from epoch in Perl
--   FKs: ON DELETE CASCADE so removing an interface clears its addresses

SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS schema_version (
    version    INT          NOT NULL PRIMARY KEY,
    applied_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS machines (
    id           INT          NOT NULL AUTO_INCREMENT PRIMARY KEY,
    primary_name VARCHAR(128),
    first_seen   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    online       TINYINT      NOT NULL DEFAULT 0,
    notes        TEXT,
    KEY idx_primary_name (primary_name),
    KEY idx_online       (online),
    KEY idx_last_seen    (last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS hostnames (
    machine_id   INT          NOT NULL,
    name         VARCHAR(255) NOT NULL,
    source       VARCHAR(32)  NOT NULL,    -- 'ssh','dns','dhcp','dnsmasq','config','ap'
    last_seen    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (machine_id, name, source),
    KEY idx_name (name),
    CONSTRAINT fk_hostnames_machine
        FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS interfaces (
    mac           CHAR(17)    NOT NULL PRIMARY KEY,
    machine_id    INT         NULL,         -- NULL until correlated to a machine
    vendor        VARCHAR(128),              -- OUI lookup result
    kind          VARCHAR(16) NOT NULL DEFAULT 'unknown',  -- ethernet/wifi/virtual
    first_seen    DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen     DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_observed DATETIME    NULL,           -- last live signal (DHCP/SSH/ARP/nmap/fping)
                                              -- NULL = never observed live (paper-only)
    online        TINYINT     NOT NULL DEFAULT 0,
    KEY idx_machine        (machine_id),
    KEY idx_online         (online),
    KEY idx_last_seen      (last_seen),
    KEY idx_last_observed  (last_observed),
    CONSTRAINT fk_interfaces_machine
        FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS addresses (
    mac           CHAR(17)    NOT NULL,
    family        ENUM('v4','v6') NOT NULL,
    addr          VARCHAR(45) NOT NULL,
    source        VARCHAR(64),                 -- e.g. '192.168.15.151:DHCP',
                                               --      'kestrel:dhcp.master', etc.
    last_seen     DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_observed DATETIME    NULL,            -- last live signal here; NULL = never seen
    min_rtt_ms    FLOAT       NULL,            -- shortest fping RTT ever observed
                                               -- (monotone-decreasing; manual reset only)
    last_rtt_ms   FLOAT       NULL,            -- most-recent fping RTT
    PRIMARY KEY (mac, family, addr),
    KEY idx_addr (addr),
    KEY idx_source (source),
    KEY idx_last_observed (last_observed),
    CONSTRAINT fk_addresses_iface
        FOREIGN KEY (mac) REFERENCES interfaces(mac) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ports (
    mac          CHAR(17)     NOT NULL,
    port         SMALLINT UNSIGNED NOT NULL,
    proto        ENUM('tcp','udp') NOT NULL DEFAULT 'tcp',
    service      VARCHAR(64),
    last_seen    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (mac, port, proto),
    KEY idx_port (port),
    CONSTRAINT fk_ports_iface
        FOREIGN KEY (mac) REFERENCES interfaces(mac) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS aps (
    mac          CHAR(17)     NOT NULL PRIMARY KEY,
    ssid         TEXT,                       -- comma-joined when multiple
    model        VARCHAR(128),
    board        VARCHAR(128),
    last_seen    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_aps_iface
        FOREIGN KEY (mac) REFERENCES interfaces(mac) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS associations (
    ap_mac       CHAR(17)     NOT NULL,
    client_mac   CHAR(17)     NOT NULL,
    `signal`     SMALLINT,                   -- RSSI dBm (negative); reserved word, backticked
    iface        VARCHAR(16),                -- AP-side radio name (eth1, ath0, etc.)
    ssid         VARCHAR(64),                -- live SSID for that radio
    last_seen    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (ap_mac, client_mac),
    KEY idx_client (client_mac),
    KEY idx_last_seen (last_seen),
    CONSTRAINT fk_assoc_ap
        FOREIGN KEY (ap_mac) REFERENCES interfaces(mac) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dhcp_leases (
    mac          CHAR(17)     NOT NULL,
    ip           VARCHAR(45)  NOT NULL,
    hostname     VARCHAR(255),
    expires      DATETIME,
    ap_mac       CHAR(17),                   -- DHCP server (NULL if from another source)
    last_seen    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (mac, ip),
    KEY idx_ip (ip),
    KEY idx_expires (expires)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS events (
    id           BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ts           DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    type         VARCHAR(32)  NOT NULL,
    machine_id   INT          NULL,
    mac          CHAR(17)     NULL,
    addr         VARCHAR(45)  NULL,
    details      JSON         NULL,
    KEY idx_ts        (ts),
    KEY idx_type_ts   (type, ts),
    KEY idx_mac       (mac),
    KEY idx_machine   (machine_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS aliases (
    name               VARCHAR(255) NOT NULL PRIMARY KEY,
    machine_id         INT          NOT NULL,
    prefer_subnet_cidr VARCHAR(45),                -- NULL = any address of the machine
    source             VARCHAR(64),                -- 'manual', 'dhcp.master', etc.
    notes              TEXT,
    created_at         DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_alias_machine (machine_id),
    CONSTRAINT fk_alias_machine
        FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Named placeholder values used when generating config files (e.g. by
-- net-gen-dnsmasq, which substitutes DNSH/ROUTER_223/etc. from this
-- table). Plain key=value; intentionally not tied to machines so it
-- can hold literal IPs, hostnames, or any string the generator needs.
CREATE TABLE IF NOT EXISTS dhcp_vars (
    name        VARCHAR(64)  NOT NULL PRIMARY KEY,
    value       VARCHAR(255) NOT NULL,
    notes       TEXT,
    updated_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                             ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Things plugged into Wi-Fi smart sockets — populated by net-tp-scan.
-- One row per outlet (outlet=0 for single plugs, 1..N for strips).
-- The controller machine is the smart plug/strip itself; this table
-- records what's *plugged into it*. Useful for the web UI to render
-- "Office strip > 3: Soldering iron [on]".
CREATE TABLE IF NOT EXISTS wifi_sockets (
    machine_id      INT          NOT NULL,
    outlet          INT          NOT NULL,
    name            VARCHAR(255),
    state           TINYINT      NULL,        -- 0=off, 1=on, NULL=unknown
    controller_type VARCHAR(64),
    last_seen       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                                 ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (machine_id, outlet),
    CONSTRAINT fk_wifi_socket_machine
        FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- User-supplied display names that override the auto-detected
-- primary_name on the web UI's compact list. Auto-detected names
-- come from DHCP-supplied hostnames and can be ugly; this lets the
-- user pin a nicer label without disturbing what producers report.
CREATE TABLE IF NOT EXISTS friendly_names (
    machine_id  INT          NOT NULL PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    notes       TEXT,
    updated_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                             ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_friendly_machine
        FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Per-subnet AP ranking, used when picking which AP should fill the
-- ROUTER_* placeholders in dhcp.master. Higher `rank` wins; ties broken
-- by AP MAC (deterministic). Auto-detect (net-var auto) consults this
-- before falling back to the host's default route.
CREATE TABLE IF NOT EXISTS subnet_routers (
    subnet_cidr  VARCHAR(45)  NOT NULL,
    ap_mac       CHAR(17)     NOT NULL,
    `rank`       INT          NOT NULL DEFAULT 0,
    notes        TEXT,
    PRIMARY KEY (subnet_cidr, ap_mac),
    KEY idx_subnet (subnet_cidr),
    CONSTRAINT fk_subnet_router_ap
        FOREIGN KEY (ap_mac) REFERENCES interfaces(mac) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Per-host uplink probe state. Each row is one upstream path this
-- gateway has (e.g. 'comcast' via eth0, 'wifi' via wlan0). Populated
-- by net-uplink-probe based on [uplinks] in /etc/net-mgr/config.
CREATE TABLE IF NOT EXISTS uplinks (
    label                VARCHAR(64)  NOT NULL PRIMARY KEY,
    target               VARCHAR(64)  NOT NULL,
    via_iface            VARCHAR(32)  NULL,
    role                 VARCHAR(16)  NOT NULL DEFAULT 'active',
    interval_s           INT          NOT NULL DEFAULT 60,
    last_check           DATETIME     NULL,
    last_ok              DATETIME     NULL,
    last_status          VARCHAR(16)  NOT NULL DEFAULT 'unknown',
    last_rtt_ms          FLOAT        NULL,
    consecutive_failures INT          NOT NULL DEFAULT 0,
    notes                TEXT,
    KEY idx_role       (role),
    KEY idx_last_check (last_check)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Peer net-mgr instances discovered on the LAN by net-find-peers.
-- Upserted on (host, port). schema_version, started_at and rtt_ms
-- come from the peer's STATUS reply.
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Devices found by net-find-lost on a vendor-default subnet but not
-- (yet) recovered. Upserted by (subnet, mac); status reflects what
-- net-find-lost knew at the time of the most recent sighting.
CREATE TABLE IF NOT EXISTS lost_devices (
    id           INT          NOT NULL AUTO_INCREMENT PRIMARY KEY,
    first_seen   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                              ON UPDATE CURRENT_TIMESTAMP,
    iface        VARCHAR(16)  NOT NULL,
    subnet       VARCHAR(45)  NOT NULL,        -- e.g. 192.168.0.0/24
    ip           VARCHAR(45)  NOT NULL,        -- IP at time of sighting
    mac          CHAR(17)     NOT NULL,
    vendor       VARCHAR(128),                 -- OUI lookup result
    handler      VARCHAR(64),                  -- recovery handler name (if any)
    status       VARCHAR(32)  NOT NULL DEFAULT 'no-handler',
                                                -- no-handler / pending /
                                                -- attempted / failed / recovered
    last_attempt DATETIME     NULL,             -- when --recover was invoked
    notes        TEXT,
    UNIQUE KEY uniq_subnet_mac (subnet, mac),
    KEY idx_status    (status),
    KEY idx_last_seen (last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Port-forwarding rules harvested from running ssh processes (and
-- manual additions).  Each row describes one -L / -R / -D forward as
-- it would appear on the ssh command line.  source_host names the
-- machine running the ssh process (a firewall, gateway, etc.) so the
-- same rule discovered on two boxes shows up as two rows.
--
-- Uniqueness on (source_host, direction, bind_addr, bind_port) means
-- restarting the ssh process updates the existing row rather than
-- piling on duplicates; bind_addr defaults to '*' so the wildcard case
-- (-L:port:host:port) doesn't NULL out the unique check.
CREATE TABLE IF NOT EXISTS forwarding_rules (
    id           INT          NOT NULL AUTO_INCREMENT PRIMARY KEY,
    source       VARCHAR(32)  NOT NULL,         -- 'ssh' | 'manual'
    source_host  VARCHAR(64)  NOT NULL,         -- host running the ssh
    source_pid   INT          NULL,             -- ssh pid (NULL for manual)
    direction    CHAR(1)      NOT NULL,         -- 'L' | 'R' | 'D'
    bind_addr    VARCHAR(64)  NOT NULL DEFAULT '*',
    bind_port    INT          NOT NULL,
    target_host  VARCHAR(64)  NULL,             -- NULL for direction='D'
    target_port  INT          NULL,
    ssh_user     VARCHAR(64)  NULL,             -- user@host of the ssh cmd
    ssh_host     VARCHAR(64)  NULL,             -- ssh destination host
    ssh_port     INT          NULL,             -- ssh -p value
    notes        TEXT,
    first_seen   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                              ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_rule (source_host, direction, bind_addr, bind_port),
    KEY idx_source_host (source_host),
    KEY idx_target      (target_host, target_port)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Zone classification.  zone_classes is the flat enumeration of broad
-- categories (Internet, DMZ, Private, future: VLAN-tagged ones, …).
-- Concrete (class, zone_name) tuples — '{DMZ,"scorpius"}', '{Private,""}'
-- — are derived from network signals: interface_zones for ip-on-iface,
-- wifi_zones for ssid-on-association.  An empty zone_name means
-- 'belongs to the class but no further refinement' (e.g. the wired
-- Private network is just '{Private,""}').
--
-- Future derivation tables (vlan_zones etc.) will hang off the same
-- zone_classes registry.
CREATE TABLE IF NOT EXISTS zone_classes (
    name        VARCHAR(32) NOT NULL PRIMARY KEY,
    sort_order  INT         NOT NULL DEFAULT 0,
    notes       TEXT,
    created_at  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO zone_classes (name, sort_order) VALUES
    ('Internet',  0),
    ('DMZ',      10),
    ('Private',  20);

CREATE TABLE IF NOT EXISTS interface_zones (
    host        VARCHAR(64) NOT NULL,
    iface       VARCHAR(32) NOT NULL,
    cidr        VARCHAR(45) NOT NULL,     -- e.g. 192.168.223.0/24
    zone_class  VARCHAR(32) NOT NULL,
    zone_name   VARCHAR(64) NOT NULL DEFAULT '',
    notes       TEXT,
    updated_at  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
                            ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (host, iface, cidr),
    KEY idx_zone (zone_class, zone_name),
    CONSTRAINT fk_iz_class FOREIGN KEY (zone_class)
        REFERENCES zone_classes(name) ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO schema_version (version) VALUES (1);
INSERT IGNORE INTO schema_version (version) VALUES (2);
INSERT IGNORE INTO schema_version (version) VALUES (3);
INSERT IGNORE INTO schema_version (version) VALUES (4);
INSERT IGNORE INTO schema_version (version) VALUES (5);
INSERT IGNORE INTO schema_version (version) VALUES (6);
INSERT IGNORE INTO schema_version (version) VALUES (7);
INSERT IGNORE INTO schema_version (version) VALUES (8);
INSERT IGNORE INTO schema_version (version) VALUES (9);
INSERT IGNORE INTO schema_version (version) VALUES (10);
INSERT IGNORE INTO schema_version (version) VALUES (11);
INSERT IGNORE INTO schema_version (version) VALUES (12);
INSERT IGNORE INTO schema_version (version) VALUES (13);
INSERT IGNORE INTO schema_version (version) VALUES (14);
-- Audit annotations.  Mark a forward observed by net-audit as a known
-- sink (target_host:target_port absorbs stray traffic, e.g. an SMTP
-- catcher on a dead-end host) or as an intentional Internet-facing
-- forward (so it's not re-flagged on each audit run).  Keyed on
-- (kind, host, addr, port); host='' means "any host" — useful for
-- sink-target where the sink is a property of the destination IP
-- regardless of which firewall is pointing at it.
CREATE TABLE IF NOT EXISTS audit_annotations (
    kind       VARCHAR(32) NOT NULL,           -- 'sink-target' | 'intentional-forward'
    host       VARCHAR(64) NOT NULL DEFAULT '',
    addr       VARCHAR(64) NOT NULL DEFAULT '*',
    port       INT         NOT NULL,
    reason     TEXT,
    created_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
                           ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (kind, host, addr, port),
    KEY idx_target (addr, port)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO schema_version (version) VALUES (15);
-- WiFi survey snapshots — one row per (scanner, scanner_iface, bssid).
-- Populated by net-wifi-survey, which ssh's to each known AP and runs
-- `wl scan` + `wl scanresults`.  Upsert-style: latest observation per
-- (scanner, foreign-bssid) tuple wins.  last_seen lets stale neighbours
-- age out (or be purged) over time.
CREATE TABLE IF NOT EXISTS wifi_scan_results (
    scanner_mac    CHAR(17)    NOT NULL,
    scanner_iface  VARCHAR(16) NOT NULL,
    bssid          CHAR(17)    NOT NULL,
    ssid           VARCHAR(64),
    channel        INT,
    band           VARCHAR(8),       -- '2.4GHz' | '5GHz' | '6GHz'
    rssi_dbm       INT,
    encryption     VARCHAR(64),
    bandwidth_mhz  INT,              -- 20 / 40 / 80 / 160
    first_seen     DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen      DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
                               ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (scanner_mac, scanner_iface, bssid),
    KEY idx_bssid     (bssid),
    KEY idx_channel   (channel),
    KEY idx_last_seen (last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO schema_version (version) VALUES (16);
INSERT IGNORE INTO schema_version (version) VALUES (17);
