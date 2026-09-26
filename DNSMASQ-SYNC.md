# dnsmasq sync — per-node config & deploy

net-mgr's `dhcp_reservations` table (authored on the **nas3 master** via
`net-reserve`, replicated to every node) is the source of truth for DHCP
reservations. This doc covers turning that into live dnsmasq config on the
gateways and DD-WRT APs.

## Flow

1. A reservation is created/edited in `net-reserve` (Reserve / Release / Move)
   → written to `dhcp_reservations` on nas3 → replicated to every node.
2. Each **gateway** node (runs dnsmasq, includes `/usr/local/sgy/conf.d`)
   regenerates its own `dnsmasq-<zone>` / `hosts-<zone>` from its replica and
   SIGHUPs dnsmasq — automatically (`[dnsmasq] mode = auto`) or when told
   (`net-cluster regen`).
3. The **master** (nas3) also pushes DD-WRT **AP** static leases
   (`net-push-ap`), because the APs aren't net-mgr nodes.

The "Push" button in net-reserve is unrelated — it records a `kind=host`
identity record (so `net-lookup` resolves the name). The propagation above
fires on the **reservation** change, not that button.

## 1. Deploy the code (every net-mgr node)

Preferred (after committing): on each node
```
git -C /usr/local/src/net-mgr pull
make -C /usr/local/src/net-mgr install
```
No-commit alternative — rsync the changed files from a working checkout:
```
rsync -aR lib/ bin/ sql/ root@<node>:/usr/local/src/net-mgr/
make -C /usr/local/src/net-mgr install
```
- Use **`make -C <repo> install`**, *not* a bare `make install` over ssh (that
  runs in `~`, which has no Makefile).
- `make install` rewrites paths, copies to `/usr/local/{bin,sbin,share/perl5}`,
  and restarts `net-mgr` / `net-mgr-relay` / `net-dns`.
- On restart each node's DB runs **schema migration v26**
  (`ALTER TABLE aps ADD COLUMN exclude`) — additive, safe.
- Mixed versions replicate fine, so roll node-by-node.

## 2. Per-node config (`/etc/net-mgr/config`)

### Gateway nodes (run dnsmasq, include `/usr/local/sgy/conf.d`)
```
[dnsmasq]
mode    = auto                    # regenerate on every reservation change
out_dir = /usr/local/sgy/conf.d   # the dir this node's dnsmasq includes from
```
- `mode = command` instead of `auto` → regen only when told (`net-cluster regen`).
- `mode = off` (default) → ignore. Optional: `[scheduling] push-dnsmasq = 30s`
  tunes the auto poll cadence (default 30 s when opted in).

### Upstream resolvers (any node that forwards DNS)

dnsmasq sends a query to **one** upstream by default and only tries another
after that one times out, so a single dead resolver costs every query a
timeout. `all_servers` sends each query to every upstream and returns whichever
answers first, which makes a dead resolver cost nothing.

```
[dnsmasq]
upstreams       = 75.75.75.75 75.75.76.76 1.1.1.1
all_servers     = 1
no_resolv       = 1
dns_loop_detect = 1
```

- `no_resolv` is the half that does the real work. Without it dnsmasq inherits
  `/etc/resolv.conf`, and on a systemd-resolved box that is `127.0.0.53` — a
  **single** upstream which is resolved itself, so there is nothing for
  `all_servers` to race. Verify with
  `dig +short chaos txt servers.bind @<node>`: one entry means one upstream.
- `no_resolv` with no usable upstreams is refused outright — it would leave
  dnsmasq with nowhere to forward.
- A malformed `server=` makes dnsmasq refuse to **start**, which on a gateway
  is a DNS *and* DHCP outage, so unusable entries are dropped with a warning
  rather than written.
- Empty `upstreams` (the default) generates nothing, so nodes nobody has
  configured are untouched. Clearing the knobs later neutralises the generated
  file rather than leaving stale upstreams in force.

Costs, and they are not all obvious:

- **`all_servers` switches OFF dnsmasq's broken-server failover.** The
  retry-on-another-server path is gated on `forward->forwardall == 0`
  (`src/forward.c:1136-1139`), and `all_servers` sets `forwardall = 1`
  (`forward.c:340-341`). Only REFUSED defers to another reply
  (`forward.c:1219`), so a fast SERVFAIL wins the race with no fallback.
  It therefore protects against a **silent** upstream, and makes a
  **fast-failing** one worse than the default. `no_resolv` + several
  `server=` lines is the part that buys redundancy; `all_servers` is the
  optional latency half. Land them in that order and measure between.
- Every upstream sees every query, and volume multiplies by the number of
  upstreams.
- First-answer-wins means the fastest **liar** wins, so keep the race
  policy-homogeneous: do not mix a filtering resolver (Quad9) with
  non-filtering ones (Comcast, Cloudflare), or blocked verdicts and NODATA
  will beat slower honest NOERROR answers and get cached.
- Internal names are safe: `is_local_answer()` runs before any server is
  chosen, so local/authoritative and DHCP-fed names never enter the race, and
  `filter_servers()` (`src/domain-match.c:268-282`) confines the race to the
  longest-match `server=/domain/` group, so split-horizon still works.
- DNSSEC: `--trust-anchor` only *stores* anchors; validation needs `--dnssec`
  (`src/option.c:366,570` — `OPT_DNSSEC_VALID` has exactly one setter). With
  validation off there is nothing for `all_servers` to collide with. If it is
  ever enabled, DS/DNSKEY sub-queries are pinned to the race winner rather
  than raced (`forward.c:991-996`), and each `server=` must be verified
  DO-capable individually first.

### Listener scope — set this BEFORE restarting a gateway's dnsmasq

A restart is when the bound address set is recomputed, so it is the moment
exposure can change. With no explicit scope dnsmasq binds every address of
every non-excluded interface, and on a WAN edge that includes the public ones.

`--local-service` does **not** protect you. The man page: it *"only has effect
if there are no --interface, --except-interface, --listen-address or
--auth-server options"* — so one `except-interface` line silently disables it.
That is the live state on gateway3: `--local-service` in its argv is inert, it
has no `interface=`/`listen-address=` at all, and its two `except-interface`
lines name `enp3s0` and `he-ipv6`, **neither of which exists there** (the real
ones are `enp1s0` and `he_net`). A filter naming nothing filters nothing.

```
[dnsmasq]
listen_interfaces = enx00e04c680869     # the DMZ/LAN legs, nothing else
listen_addresses  = 127.0.0.1           # optional extras
bind_interfaces   = 1                   # default when a scope is set
```

- Prefer `listen_interfaces` on a DHCP server: DHCP is interface-oriented, and
  an address list goes stale when a LAN address changes.
- Interface names are checked against `/sys/class/net` and an unknown one is
  **refused**, because that is precisely how the existing filter came to do
  nothing while looking correct. This check only means anything when generating
  **on the target node**.
- `bind_interfaces` binds only the scoped addresses, so nothing listens on the
  WAN at all. Without it dnsmasq binds the wildcard and filters on arrival —
  queries are refused, but the port is open to everyone, which on a
  firewall-less edge is the actual problem. Cost: interfaces appearing later
  are not picked up, so each must exist with its address at start.
- Scope may be set on its own, with no `upstreams`, when tightening exposure is
  all you want.

Before anything is written, the generated file is checked with
`dnsmasq --test -C` using the **patched** binary when present (its option set
is not the distro's), and a rejection aborts the write — a gateway that cannot
start dnsmasq has no DNS *and* no DHCP. This catches what the knob's own
validation cannot: a bad `listen_addresses` value, for instance. If no dnsmasq
binary is present the check is skipped **with a warning**, because silence
would read as a pass.

**These are dnsmasq.conf directives, so a SIGHUP will not apply them** —
dnsmasq re-reads hosts data and `resolv-file` on HUP but not its config.
`net-gen-dnsmasq` prints a restart notice when the file changes. `mode = auto`
and `net-cluster regen` only SIGHUP, so the first activation needs a restart.

The block is written to `<out_dir>/dnsmasq-upstream`, and wired in by a marked
one-line `conf-file=` block appended to `<out_dir>/dnsmasq` — a file gateway
`dnsmasq.conf` already names and the generator never regenerates (its glob is
`dnsmasq-*`). If this node includes a different file, set `upstream_include`
to it. Do **not** assume `/etc/net-mgr/dnsmasq.conf` is read: it appears once
in this repo, in `sbin/net-mgr-dnsmasq-install` appending `netmgr=`, and
nothing makes dnsmasq read it — the same "file nothing reads" trap as
`layout`.

### Master (nas3)
```
[dnsmasq]
push_aps = 1                      # push DD-WRT AP static_leases on changes
```
- `push_aps` acts only on the elected master.
- nas3 must hold the SSH key the DD-WRT APs accept (the daemon's identity — the
  one that already scans them). Login user is `root`.
- If nas3 also serves dnsmasq, add `mode = auto` + `out_dir` like a gateway.

### Other followers (zmc1, bigsony — not dnsmasq servers)
Nothing — `[dnsmasq] mode` defaults to `off`.

## 3. AP host blacklist (what NOT to push to APs)

Servers / VMs / gateways / virtual interfaces aren't AP DHCP clients.
- **Global** (every AP): built-in `dkcw95* nas3* gateway* usb*`, plus
  `/etc/net-mgr/ap-exclude` (one glob per line, `#` comments) and `--exclude`.
- **Per-AP** (in the DB, replicated):
  ```
  net-push-ap --set-exclude 'glob1 glob2' <ap-name>
  net-push-ap --clear-exclude <ap-name>
  ```
- net-push-ap **skips DNS-only APs** (no `dhcp-range`) automatically (`--force`
  to override).

## 4. First-run review (before enabling on a live gateway)

The first regen **replaces** hand-maintained `dnsmasq-*` / `hosts-*` with
DB-generated versions, which differ: the DB is more complete (e.g. KP200), MACs
come out lowercase, and some `hosts-*` names show `nas3` instead of `nas3-up`
where the `.15` machine lacks the `-up` suffix in the DB. Preview first on the
gateway:
```
net-gen-dnsmasq --from-db --diff
net-gen-dnsmasq --from-db --test      # or write <file>.new and dnsmasq --test
```
Fix the machine-name suffixes in the DB (or accept the diff) before `mode = auto`.

## 5. Manual / ops commands
```
net-cluster regen                     # tell all members to regen now
net-cluster --peers gateway3 regen    # just one node
net-gen-dnsmasq --from-db --reload     # regen THIS node now
net-push-ap --auto                     # dry-run AP push (all APs)
net-push-ap --apply --auto             # apply AP push (runs on nas3)
```

## Caveats

- **DD-WRT NVRAM values cap at 4 KB.** The AP *DNS* list (`dnsmasq_options`)
  can overflow it and crash dnsmasq (this is what took spica down). The static-
  lease push doesn't approach the cap, but if net-mgr ever manages AP DNS, the
  blacklist + 4 KB awareness is mandatory.
- `net-push-ap --apply` runs `restart_dns` on each AP — a brief DHCP/DNS blip.
  Always dry-run first.
- DNS-only APs (no `dhcp-range`, e.g. spica) are correctly skipped — their
  reservations are served by the gateway, not the AP.
