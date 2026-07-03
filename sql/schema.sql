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
    exclude      TEXT,                        -- globs of hosts NOT to push to this AP (net-push-ap)
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
-- Current radio-channel state per AP / per radio.  Populated by
-- net-wifi-survey alongside the foreign-AP scan results.  Lets the
-- web view (and any other consumer) compute 'current ch X vs
-- recommended ch Y' verdicts without reading nvram live.
CREATE TABLE IF NOT EXISTS wifi_radio_state (
    scanner_mac     CHAR(17)    NOT NULL,
    scanner_iface   VARCHAR(16) NOT NULL,
    band            VARCHAR(8),
    current_channel INT,
    updated_at      DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
                                ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (scanner_mac, scanner_iface)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO schema_version (version) VALUES (17);
INSERT IGNORE INTO schema_version (version) VALUES (18);

-- ISP-link bookkeeping. Failover decisions need to know which gateway
-- machine can reach which ISP, with what credentials. isp_links is
-- public-readable; the actual secret material lives in isp_secrets,
-- which the daemon gates to AUTH'd peers only.
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS isp_secrets (
    gateway_machine_id INT          NOT NULL,
    isp_name           VARCHAR(64)  NOT NULL,
    auth_secret        VARCHAR(255),
    last_changed       DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
                                   ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (gateway_machine_id, isp_name),
    CONSTRAINT fk_isp_secrets_link
        FOREIGN KEY (gateway_machine_id, isp_name)
            REFERENCES isp_links(gateway_machine_id, isp_name)
            ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
INSERT IGNORE INTO schema_version (version) VALUES (19);

-- Link-speed + per-destination packet-loss tracking (schema 20).
-- Populated by producers (ethtool/iw for link_speed_mbps,
-- fping for loss_pct); used by net-lookup for wired/wifi
-- preference and quality-aware scoring. Both NULL until
-- producers populate.
ALTER TABLE interfaces ADD COLUMN link_speed_mbps INT NULL;
ALTER TABLE addresses  ADD COLUMN loss_pct        FLOAT NULL;
INSERT IGNORE INTO schema_version (version) VALUES (20);

-- replicated_from: which cluster master a row came from, NULL = local.
-- Stamped on every row written by net-mgr-relay; left alone by local
-- OBSERVE writes. Master's periodic replication keeps overwriting,
-- so "master's info takes precedence" is enforced by the cycle
-- rather than runtime errors. Audit / debug column too.
ALTER TABLE machines     ADD COLUMN replicated_from VARCHAR(64) NULL;
ALTER TABLE machines     ADD KEY idx_replicated_from (replicated_from);
ALTER TABLE hostnames    ADD COLUMN replicated_from VARCHAR(64) NULL;
ALTER TABLE hostnames    ADD KEY idx_replicated_from (replicated_from);
ALTER TABLE interfaces   ADD COLUMN replicated_from VARCHAR(64) NULL;
ALTER TABLE interfaces   ADD KEY idx_replicated_from (replicated_from);
ALTER TABLE addresses    ADD COLUMN replicated_from VARCHAR(64) NULL;
ALTER TABLE addresses    ADD KEY idx_replicated_from (replicated_from);
ALTER TABLE ports        ADD COLUMN replicated_from VARCHAR(64) NULL;
ALTER TABLE ports        ADD KEY idx_replicated_from (replicated_from);
ALTER TABLE aps          ADD COLUMN replicated_from VARCHAR(64) NULL;
ALTER TABLE aps          ADD KEY idx_replicated_from (replicated_from);
ALTER TABLE associations ADD COLUMN replicated_from VARCHAR(64) NULL;
ALTER TABLE associations ADD KEY idx_replicated_from (replicated_from);
ALTER TABLE dhcp_leases  ADD COLUMN replicated_from VARCHAR(64) NULL;
ALTER TABLE dhcp_leases  ADD KEY idx_replicated_from (replicated_from);
ALTER TABLE aliases      ADD COLUMN replicated_from VARCHAR(64) NULL;
ALTER TABLE aliases      ADD KEY idx_replicated_from (replicated_from);
INSERT IGNORE INTO schema_version (version) VALUES (21);

-- net-chat: named chat sessions hosted by the daemon (schema 22).
-- Agents (SSH-key-identified over the socket) and humans (web GUI) talk
-- in named sessions; the server records every message. The session
-- creator picks an access_mode: 'open' (any authorized client),
-- 'list' (only chat_members.state='member'), or 'request' (others
-- join state='requested' and an owner APPROVEs them).
CREATE TABLE IF NOT EXISTS chat_sessions (
    name          VARCHAR(64)  NOT NULL PRIMARY KEY,
    topic         TEXT,
    created_by    VARCHAR(128) NOT NULL,            -- verified key_id / 'local'
    access_mode   ENUM('open','list','request') NOT NULL DEFAULT 'open',
    status        ENUM('open','closed')         NOT NULL DEFAULT 'open',
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_activity DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_at     DATETIME     NULL,
    KEY idx_status        (status),
    KEY idx_last_activity (last_activity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Persistent membership + ACL. 'owner' is the creator (and anyone they
-- promote). state drives the access_mode gate: 'member' may post,
-- 'requested' is awaiting approval, 'invited' is pre-authorised on a
-- 'list' session, 'denied' was rejected.
CREATE TABLE IF NOT EXISTS chat_members (
    session        VARCHAR(64)  NOT NULL,
    principal      VARCHAR(128) NOT NULL,
    role           ENUM('owner','member')                        NOT NULL DEFAULT 'member',
    state          ENUM('member','requested','invited','denied') NOT NULL DEFAULT 'member',
    added_by       VARCHAR(128),
    requested_at   DATETIME     NULL,
    joined_at      DATETIME     NULL,
    -- request_pubkey carries the SSH pubkey supplied with an unverified
    -- join request; cleared on approval (key moves to chat_authorized_keys).
    request_pubkey TEXT         NULL,
    -- requested_from: peer IP/host the join request came in on, so an
    -- approver sees WHERE the request originated, not just the
    -- (potentially self-asserted) principal. Set when state=requested.
    requested_from VARCHAR(64)  NULL,
    PRIMARY KEY (session, principal),
    KEY idx_member_state (state),
    CONSTRAINT fk_chat_members_session
        FOREIGN KEY (session) REFERENCES chat_sessions(name) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Append-only message log. ts is microsecond-resolution so a windowed
-- snapshot (ts > ago(N)) and strict ordering both work. sender is
-- server-stamped from the verified identity; clients cannot spoof it.
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Live roster (ephemeral). One row per connection currently joined to
-- a session; the daemon clears it on startup and deletes a connection's
-- rows on disconnect. The same principal on two connections is deduped
-- by the consumer.
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO schema_version (version) VALUES (22);

-- SSH host keys. A host key (fingerprint) is stable across IP and even MAC
-- changes, so it identifies a machine on a floating IP. Recorded on demand by
-- `net-lookup --probe` and by net-ssh (which knows the target's alias). A
-- known key resolves an otherwise-uncorrelated IP straight to its machine.
CREATE TABLE IF NOT EXISTS host_keys (
    key_id     VARCHAR(80)  NOT NULL PRIMARY KEY,   -- "SHA256:..." fingerprint
    key_type   VARCHAR(20)  NOT NULL DEFAULT '',    -- ed25519 / rsa / ecdsa
    machine_id INT          NULL,                   -- owning machine (NULL = orphan)
    first_seen DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_host_keys_machine (machine_id),
    CONSTRAINT fk_host_keys_machine
        FOREIGN KEY (machine_id) REFERENCES machines(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- DB-native DHCP plan (schema v24) — moves the dynamic-pool bounds and the
-- static reservations out of the hand-edited /etc/net-mgr/dhcp.master and into
-- the (cluster-replicated) DB, so net-reserve(1) can manage them from any host
-- and net-gen-dnsmasq can generate straight from the DB. Seeded once from the
-- existing dhcp.master by net-import-dhcp.

-- dhcp_ranges: the address ranges the DHCP server hands out automatically.
-- These are exactly the IPs net-reserve must NOT offer as a static. One row
-- per `range A B;` directive; a subnet may have several.
CREATE TABLE IF NOT EXISTS dhcp_ranges (
    subnet_cidr  VARCHAR(45)  NOT NULL,        -- e.g. 192.168.15.0/24
    start_ip     VARCHAR(45)  NOT NULL,        -- first auto-assigned address
    end_ip       VARCHAR(45)  NOT NULL,        -- last auto-assigned address
    zone         VARCHAR(64)  NULL,            -- subnet `# zone=` annotation
    notes        TEXT         NULL,
    updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                              ON UPDATE CURRENT_TIMESTAMP,
    replicated_from VARCHAR(64) NULL,          -- cluster master, NULL = local
    PRIMARY KEY (subnet_cidr, start_ip),
    KEY idx_dhcp_ranges_subnet (subnet_cidr),
    KEY idx_dhcp_ranges_replicated (replicated_from)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- dhcp_reservations: permanent (MAC -> fixed IP) assignments — the DB-native
-- replacement for `host { hardware ethernet ..; fixed-address ..; }` blocks.
-- One reservation per IP (uniq); a device (mac) may hold more than one across
-- subnets. `grp` is the user's group label (was a dhcp.master comment).
CREATE TABLE IF NOT EXISTS dhcp_reservations (
    ip           VARCHAR(45)  NOT NULL PRIMARY KEY,
    mac          CHAR(17)     NOT NULL,
    name         VARCHAR(255) NULL,            -- dnsmasq host name / label
    subnet_cidr  VARCHAR(45)  NULL,            -- owning subnet (for grouping)
    grp          VARCHAR(64)  NULL,            -- user group, e.g. 'cameras'
    notes        TEXT         NULL,
    updated_by   VARCHAR(128) NULL,            -- who last set it
    updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                              ON UPDATE CURRENT_TIMESTAMP,
    replicated_from VARCHAR(64) NULL,
    KEY idx_resv_mac    (mac),
    KEY idx_resv_subnet (subnet_cidr),
    KEY idx_resv_grp    (grp),
    KEY idx_resv_replicated (replicated_from)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO schema_version (version) VALUES (24);

-- Per-chat authorized SSH keys (schema v25). When a chat owner approves a join
-- request, the requester's SSH key is recorded here so the authorization is
-- durable (independent of the live chat_members roster) and can be inspected,
-- exported, or pre-loaded. A key on this list joins its chat without prompting;
-- denying/rejecting removes it. label is a friendly name (the machine that owns
-- the key, resolved from host_keys at approval time).
CREATE TABLE IF NOT EXISTS chat_authorized_keys (
    session    VARCHAR(64)  NOT NULL,
    key_id     VARCHAR(80)  NOT NULL,            -- "SHA256:..." fingerprint
    key_type   VARCHAR(20)  NOT NULL DEFAULT '', -- ed25519 / rsa / ecdsa
    label      VARCHAR(128) NOT NULL DEFAULT '', -- friendly name (machine)
    added_by   VARCHAR(128) NULL,                -- principal who authorized it
    added_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (session, key_id),
    KEY idx_cak_key (key_id),
    CONSTRAINT fk_cak_session
        FOREIGN KEY (session) REFERENCES chat_sessions(name) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO schema_version (version) VALUES (25);

-- mesh_tunnels (schema v27): tunnel/uplink metadata replicated cluster-wide.
-- Source of truth for net-mgr's "overlay" tunnels: the row says "this kind of
-- tunnel, terminated on this owner_node, has these endpoints/prefixes." Any
-- node reading the table can decide what to do (a relay leaf reads the routed
-- prefix; the owner reads the server/tunnel prefix; the cluster master fires
-- the provider DDNS update with its local secret). A node's [ipv6_vlan] config
-- OVERRIDES the columns when set (config files are for overrides only). See
-- Manager::_he_net_startup_net for the consumer.
--   kind: 'he6in4' (extensible — 'wireguard', 'gre', ... later)
--   provider_id: provider-specific tunnel id (HE: numeric tid)
--   server_v4: the remote endpoint we tunnel TO
--   tunnel_prefix: /64 used FOR the tunnel itself (HE: server=::1, client=::2)
--   routed_prefix: /64 routed via the tunnel for LAN clients (relay prefix)
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO schema_version (version) VALUES (27);

-- Schema v28: durable chat-key auth for unverified-then-approved users.
-- The unverified see-and-request flow now persists the requester's SSH public
-- key when they send one with the join request; on approval the pubkey moves
-- to chat_authorized_keys keyed by its fingerprint. A future AUTH from that
-- key (Tier 6 chat-key in NetMgr::Auth) recognises it via chat_authorized_keys
-- and the user re-joins the chats they were approved for, no second ask.
--   chat_members.request_pubkey: pubkey supplied with a join request, NULL when
--     the request was nameless. Cleared on approve/reject (moves to authd_keys).
--   chat_authorized_keys.pubkey: the OpenSSH-format public key
--     ("ssh-ed25519 AAAA... comment"), the line ssh-keygen -Y verify reads.
--     Existing rows have NULL (no chat-key auth possible until refreshed).
ALTER TABLE chat_members         ADD COLUMN request_pubkey TEXT NULL;
ALTER TABLE chat_authorized_keys ADD COLUMN pubkey         TEXT NULL;

INSERT IGNORE INTO schema_version (version) VALUES (28);

-- Schema v29: mesh_tunnels.secret_name — the per-tunnel pointer to the
-- credential needed for provider-side updates (HE tunnelbroker DDNS). Lives in
-- the row so the cluster master can resolve the secret on behalf of any node
-- without anyone else holding it. See project_net-mgr-vision: "Secrets live on
-- the cluster master."
ALTER TABLE mesh_tunnels ADD COLUMN secret_name VARCHAR(64) NULL;

INSERT IGNORE INTO schema_version (version) VALUES (29);

-- Schema v30: peers.cluster_member — the discovered peer's self-reported
-- cluster name (from its STATUS reply). Lets a fresh follower run
-- AutoDiscover without needing machines/interfaces/addresses populated
-- first (chicken-and-egg: those tables fill via replication, but
-- replication can't start until election finds a master). PTR fallback
-- is fine but unreliable when reverse DNS is unconfigured.
ALTER TABLE peers ADD COLUMN cluster_member VARCHAR(64) NULL;

INSERT IGNORE INTO schema_version (version) VALUES (30);

-- Schema v34: wan-failover data model. Three cluster-replicated tables
-- carry the state the failover orchestrator (commit C) needs, ahead of
-- the OBSERVE verbs (commit B) that write to them.
--
--   wan_services            — one named "WAN service" (e.g. 'primary').
--                              active_member points at whichever candidate is
--                              currently promoted; last_status is the rolling
--                              health verdict; orchestrator_mode is 'auto' or
--                              'manual' (pinned by an operator).
--   wan_service_candidates  — (service_name, member) tuples: the ordered set
--                              of members eligible to serve this service. The
--                              orchestrator promotes the healthy candidate with
--                              the LOWEST priority number. apply/teardown hooks
--                              are cluster-visible so any node can see how a
--                              given candidate is brought up on the owning host.
--   wan_service_health      — per-(service, member, target) probe rollup.
--                              wan-probe (commit C) writes; the master reads to
--                              decide promotions. Not replicated back to the
--                              origin, so each site sees the failover it drove.
--
-- All three carry replicated_from so cluster-master takes precedence per the
-- v21 convention. Fresh installs get the tables here; upgrades pick them up
-- via _apply_migration(v=34) in NetMgr::DB.
CREATE TABLE IF NOT EXISTS wan_services (
    name                   VARCHAR(64)  NOT NULL PRIMARY KEY,
    active_member          VARCHAR(64)  NULL,
    last_status            VARCHAR(16)  NOT NULL DEFAULT 'unknown',
    last_status_reason     VARCHAR(255) NULL,
    last_promotion_at      DATETIME     NULL,
    last_working_at        DATETIME     NULL,
    orchestrator_mode      VARCHAR(16)  NOT NULL DEFAULT 'auto',
    probe_targets          VARCHAR(255) NOT NULL DEFAULT '1.1.1.1,8.8.8.8',
    probe_interval_s       INT          NOT NULL DEFAULT 3,
    fail_streak_threshold  INT          NOT NULL DEFAULT 3,
    min_promotion_secs     INT          NOT NULL DEFAULT 30,
    quarantine_secs        INT          NOT NULL DEFAULT 300,
    antiflap_freeze_secs   INT          NOT NULL DEFAULT 120,
    notes                  TEXT,
    last_modified          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                                        ON UPDATE CURRENT_TIMESTAMP,
    replicated_from        VARCHAR(64)  NULL,
    KEY idx_ws_replicated (replicated_from)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS wan_service_candidates (
    service_name        VARCHAR(64)  NOT NULL,
    member              VARCHAR(64)  NOT NULL,
    priority            INT          NOT NULL DEFAULT 100,
    iface               VARCHAR(32)  NULL,
    mac                 CHAR(17)     NULL,
    isp_name            VARCHAR(64)  NULL,
    apply_hook          VARCHAR(255) NULL,
    teardown_hook       VARCHAR(255) NULL,
    probe_when_standby  TINYINT      NOT NULL DEFAULT 1,
    last_apply_result   VARCHAR(16)  NULL,
    last_apply_at       DATETIME     NULL,
    last_apply_note     VARCHAR(255) NULL,
    last_working_at     DATETIME     NULL,
    notes               TEXT,
    last_modified       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                                     ON UPDATE CURRENT_TIMESTAMP,
    replicated_from     VARCHAR(64)  NULL,
    PRIMARY KEY (service_name, member),
    KEY idx_wsc_svc_prio (service_name, priority),
    KEY idx_wsc_replicated (replicated_from)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS wan_service_health (
    service_name         VARCHAR(64)  NOT NULL,
    member               VARCHAR(64)  NOT NULL,
    target               VARCHAR(64)  NOT NULL,
    last_check           DATETIME     NULL,
    last_ok              DATETIME     NULL,
    last_status          VARCHAR(16)  NOT NULL DEFAULT 'unknown',
    last_rtt_ms          FLOAT        NULL,
    consecutive_failures INT          NOT NULL DEFAULT 0,
    replicated_from      VARCHAR(64)  NULL,
    PRIMARY KEY (service_name, member, target),
    KEY idx_wsh_svc (service_name),
    KEY idx_wsh_replicated (replicated_from)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO schema_version (version) VALUES (34);
