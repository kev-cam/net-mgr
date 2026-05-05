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
    last_observed DATETIME    NULL,           -- last live signal (DHCP/SSH/ARP/nmap/fping);
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
    min_rtt_ms    FLOAT       NULL,            -- shortest fping RTT ever observed;
                                               -- monotone-decreasing, manual reset only
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
