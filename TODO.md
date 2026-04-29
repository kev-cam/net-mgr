# net-roam: per-client deauth on DD-WRT v3.0-r56119

bin/net-roam can identify weak mobile clients but cannot actually kick
them on our current APs. Investigated 2026-04-29 against R6700 v3 and
R6400 v1 running DD-WRT v3.0-r56119 (build dated 2024-05-01).

## What's broken

The per-client deauth IOVARs are not registered in this firmware's
`wl` binary:

- `deauthenticate`, `scb_deauthenticate_for_reason`, `deauthenticate_mac`,
  `deauthorize`, `wnm_btm`, and ~15 other plausible names all fail with
  `set: error parsing value <MAC> as an integer for set of <name>`.
- That error is `wl`'s generic IOVAR-set fallback — confirmed by passing
  obvious nonsense names and getting the same error. The IOVARs are
  genuinely absent, not just type-mismatched.
- `wl cmds` lists only `disassoc` (kicks the AP off its own BSS — not
  per-client). No `wl ioctl` / `iovar` passthrough. No `hostapd_cli`,
  no `iw`. nas runs the auth path.

## Options when we come back to this

1. **MAC-filter trick (no firmware flash).** Set `wlN_macmode=deny` and
   `wlN_maclist=<mac>` via nvram, restart wireless to enforce, remove
   the entry. Driver deauths anything in the deny list. Cost: ~3-5s
   outage on the whole radio per kick, affects all clients on that
   radio. Probably acceptable for occasional roams; bad if invoked
   often.

2. **Reflash to firmware with `iw`.** OpenWRT, FreshTomato, or older
   DD-WRT builds with mac80211 support `iw dev <if> station del <mac>`
   — clean single-command kick. Cleanest fix; cost is the firmware
   migration itself.

3. **Stay passive.** Drop the kick code, keep net-roam as a reporting
   tool (`--list`, `--list-all`, `--mac`, RSSI tracking via Producer/AP).
   Useful even without the kick — surfaces edge-of-cell phones for
   manual handling.

## Current state in tree

- `lib/NetMgr/Producer/AP.pm` captures `wl rssi <mac>` per client and
  emits `signal` on each association observation. Working.
- `bin/net-roam --list` / `--list-all` / `--mac` work. Useful as-is.
- `bin/net-roam` (no flags) and `--kick <MAC>` will SSH and run a
  fallback chain of `scb_deauthenticate_for_reason` →
  `deauthenticate_mac` → `deauthenticate`. All three fail on this
  firmware. Code is harmless (no AP state changes) but produces noisy
  `wifi_deauth` events with rc!=0. Consider gating kicks behind a
  per-AP capability check or just deleting the kick path until we pick
  option 1 or 2.
