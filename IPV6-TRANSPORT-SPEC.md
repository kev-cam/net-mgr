# Spec (for review): IPv6 transport migration — control-VLAN ready

**Goal:** make net-mgr's listener and mesh transport IPv6-capable so the cluster
control plane can run over a dedicated IPv6 control VLAN. **Dual-stack** — IPv4
keeps working; IPv6 is added alongside, then the roster can be cut over.

**Not in this spec** (separate follow-ups): the VLAN / RA / DHCPv6 network setup,
cutting the cluster to v6-only, and the general-comms "node query" verbs.

## Current state

- **`NetMgr::Client`** already uses `IO::Socket::IP` and parses IPv6 listen
  literals (`split_hostport`/`join_hostport`: `[v6]:port`, bare v6, name). Client
  → node over IPv6 already works.
- **`NetMgr::Manager`** listener (`lib/NetMgr/Manager.pm` ~261) and
  **`NetMgr::Mesh`** connector (`lib/NetMgr/Mesh.pm` ~301) still use
  `IO::Socket::INET` — **IPv4-only**.
- Two parsers mishandle v6 today:
  - `_resolve_listen_spec` (Manager): `$tok =~ /^(.+):(\d+)$/` greedily splits an
    IPv6 literal at the wrong colon.
  - `_self_connect_addr` (Manager): returns `host:port` without bracketing v6.
- `'auto'` listen resolves via `_local_192_168_ips()` — IPv4 192.168.x only.

## Changes

### 1. NEW `lib/NetMgr/Addr.pm` (factor + extend)
Move Client's inline `split_hostport`/`join_hostport` here, add
`local_addrs($family, $prefix?)` (enumerate this host's bound v4/v6 addresses,
optionally filtered to a prefix). Client refactored to use it (no behavior
change). Single home for all host:port / v6-literal handling — avoids three
copies.

### 2. `lib/NetMgr/Manager.pm`
- **Listener**: `IO::Socket::INET->new(...)` → `IO::Socket::IP->new(...)` (same
  `LocalAddr`/`LocalPort`/`Listen`/`ReuseAddr`; add `V6Only => 1` on v6 binds —
  see decision 2). `use IO::Socket::IP`.
- **`_resolve_listen_spec`**: use `Addr::split_hostport` (bracket-aware);
  `'auto'` adds local v6 control addresses via `Addr::local_addrs('v6', $control_prefix)`
  in addition to today's v4 autos + loopback.
- **`_self_connect_addr`**: `Addr::join_hostport` (brackets v6); treat `::`/`::1`
  as loopback like `0.0.0.0`/`127.`.

### 3. `lib/NetMgr/Mesh.pm`
- `_try_connect`: `IO::Socket::INET` → `IO::Socket::IP` (`PeerAddr`/`PeerPort`).
  `use IO::Socket::IP`. Member specs that carry a v6 address connect bracket-aware
  via `Addr::split_hostport`.

### 4. `lib/NetMgr/Config.pm`
- Document IPv6 in `[manager] listen` (comma list may mix v4 + `[v6]:port`).
- `[cluster] members` entries may be `[v6]` / `[v6]:port` / name.
- NEW (optional) `[cluster] control_prefix = fd…::/64` — scopes which v6 `'auto'`
  binds + which address a node advertises as its control-plane address.

## Config model (proposed)

```
[manager]
listen = auto, [fd12:3456:789a:1::10]:7531   # v4 autos + the control-VLAN v6

[cluster]
control_prefix = fd12:3456:789a:1::/64        # scopes 'auto' v6 + advertised addr
members        = nas3, [fd12:3456:789a:1::10], [fd12:3456:789a:1::20]
```

## Dual-stack / rollout

- v6 binds are **added** to the existing v4 binds; nothing is removed.
- Migrate node-by-node: each node listens v4 **and** v6; mesh peers connect over
  whatever address the roster gives (v4 now → v6 once members are v6).
- Cut `[cluster] members` to the control-VLAN v6 addresses only after every node
  binds v6.

## Test plan (no real VLAN required)

1. **Unit** — `Addr` round-trip table: v4, `[v6]`, `[v6]:port`, bare v6, name, `::1`.
2. **Loopback v6** — `listen = [::1]:7531`; Manager binds; `--listen [::1]:7531`
   client snapshot works.
3. **ULA on a dummy/lo addr** — `ip addr add fd12::1/128 dev lo`; bind + client
   connect + mesh `_try_connect [fd12::1]` over it.
4. **Dual-stack** — `listen = auto, [::1]:7531`; both listeners up; v4 and v6
   clients both work.
5. **Regression** — existing v4-only config unchanged (auto → 192.168.x +
   127.0.0.1; mesh v4 connects).
6. **Live (zmc1, I have root)** — add a ULA to zmc1, bind, connect a client over
   it, mesh-connect — all without a real VLAN.

## Decisions for you (before I code)

1. **'auto' v6 scope** — bind *all* global v6 a node has, or only addresses in a
   configured `control_prefix`? (Recommend: `control_prefix`, for isolation.)
2. **V6Only** — separate v4/v6 sockets (`V6Only=1`, recommend) vs dual-stack
   v4-mapped (`V6Only=0`)?
3. **Mesh port** — keep the single `7531` on v6, or a distinct control port?
4. **Member spec** — `[v6]:port` brackets (consistent with Client) — confirm.
5. **Naming** — `Addr` vs folding into an existing util module; `control_prefix`
   vs `control_listen` — preference?

## Estimated blast radius

~4 files (1 new), no schema/DB change, no protocol-wire change (still line TCP).
Reversible (dual-stack; v4 path untouched). Risk concentrated in the two socket
swaps + the listen parser; covered by the test plan.
