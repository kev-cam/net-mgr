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
