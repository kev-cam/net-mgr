# netan — portable network analyzer core

Board-agnostic network-analysis tools that run on any Linux. Plug a machine into
a network drop and each cycle it reports what that drop gives you: lease/address,
gateway reachability, Internet + captive-portal state, DNS, visible peers, and
(in iperf mode) throughput — to the console, a log, optional net-chat, and (where
present) status LEDs and an LCD.

This is the single source of truth for the analyzer logic. The SoCKit buildroot
appliance (`../sockit-netan/`) consumes these same three scripts via its
`post-build.sh`; nothing here is SoCKit-specific.

## Two models

| model | what it does | use it on |
| --- | --- | --- |
| **guest** (default) | Observe the host's **existing** connection each cycle. Never touches the interface — no MAC change, no DHCP, no lease release. Reads address/route/DNS from the live system. | a machine you're **using** (laptop, server, the DE2i-150) |
| **appliance** | **Own** the interface: force a MAC, run its own `udhcpc`, DHCP release/renew every cycle, arp-scan, then release. | a **dedicated** box (the SoCKit appliance) |

Guest is the default precisely because it's safe to run anywhere — it can't knock
the host off the network. Appliance is opt-in.

## The tools

- `bin/net-analyzer` — the probe daemon (the loop). Sources `/etc/netan.conf`.
- `bin/netan-iperf` — discover an iperf3 server and run an up/down throughput test.
- `bin/netan-mode` — get/set/toggle the per-cycle mode (`dhcp` probe vs `iperf`).

All are POSIX `/bin/sh` (busybox ash compatible). Everything board- or
site-specific is in `/etc/netan.conf`; see `netan.conf.sample` for every knob.
With no config file at all they auto-detect an interface and run in guest model.

## Install on any Linux

```sh
sudo ./install.sh                       # guest model, auto-detect iface
sudo ./install.sh --model guest --start # ...and run it in the foreground now
sudo ./install.sh --service             # install + enable a systemd service
sudo ./install.sh --service --display   # ...also show the dashboard on a monitor
sudo ./install.sh --model appliance --iface eth1   # dedicated box owning eth1
sudo ./install.sh --uninstall
```

`--display [VT]` adds a second service (`netan-display.service`) that renders the
full-screen dashboard (`netan-display`) on a Linux console VT (default 8) with a
large console font, so a monitor plugged into the box becomes a live wall
display. It coexists with a desktop — the GUI keeps its own VT (usually 7), and
`chvt <n>` switches the monitor between them. Proven on the DE2i-150's HDMI
(gma500 framebuffer, 1080p).

`install.sh` copies the three scripts to `<prefix>/bin` (default `/usr/local/bin`),
writes `/etc/netan.conf` (only if absent — it never clobbers yours), warns about
missing optional tools (`arp-scan`, `iperf3`, …), and can register a
`netan.service` systemd unit. Dependencies it looks for: `ip`, `ping`,
`nslookup`, `wget`, `arp-scan`, and `iperf3` for iperf mode. It degrades if some
are missing (e.g. no `arp-scan` → `peers=0`).

## Runtime files

- `/tmp/netan-status` — current cycle state (for an LCD/status reader)
- `/tmp/netan-peers` — sorted list of peer IPs seen this cycle
- `/tmp/netan-mode` — active mode; `/tmp/netan-hold` pauses the loop (appliance)
- `/var/log/net-analyzer.log` — per-cycle log
