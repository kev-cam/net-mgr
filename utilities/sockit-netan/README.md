# SoCKit network analyzer (`sockit-netan`)

A Terasic SoCKit (Cyclone V SX, Rev D) turned into a self-contained, portable
network-analysis appliance. Plug it into any Ethernet drop and it reports what
that drop actually gives you — lease, gateway, DNS, Internet reachability,
captive portal, visible peers, and (in `iperf` mode) throughput — over four HPS
LEDs, the on-board LCD, the serial console, and single-line `net-chat` posts
back to net-mgr.

This is an HPS-only appliance: the FPGA fabric is left unconfigured.

## What it does

Each cycle, on Ethernet link-up:

1. fresh `udhcpc` lease
2. probe gateway ping / `8.8.8.8` / DNS query / `detectportal` HTTP
3. bounded `arp-scan` (never wider than a `/24`, wrapped in `timeout 30`)
4. report
5. explicit DHCPRELEASE (`udhcpc -f -R` + SIGTERM)

so the box is a good citizen and does not hoard leases.

A typical cycle line:

```
[SoCKit-netan] cycle=311 ip=192.168.15.180 gw=192.168.15.252(yes)
  dns=192.168.15.252(q:yes) inet=ping:yes/http:yes peers=68
  lease=86400s dhcp=1s state=held
```

### Modes

| mode | what a cycle does |
| --- | --- |
| `dhcp` (default) | the release/renew probe above |
| `iperf` | take a lease, then run `netan-iperf`: find an iperf3 server (nas3 `192.168.15.104` first, then arp-scan of the `/24` TCP-probing 5201/5001), run up+down, report `iperf srv=.. up/down Mbps` |

Selectable three ways:

- `/etc/netan-mode` — the boot default (ships `dhcp`)
- `netan-mode {dhcp|iperf|toggle|get}` — on-box CLI
- **front-panel KEY4** — toggles mode (repurposed from LCD redraw)

Only iperf3 ships. Classic iperf (port 5001) needs a C++ toolchain this build
omits, so `netan-iperf` guards on `command -v` and will not advertise a 5001
server it cannot actually test. An optional `/etc/netan-iperf-servers`
(`host[:port]` per line) bypasses discovery entirely.

### Reporting

- **LEDs** — `led0` link, `led1` lease (blink = hold), `led2` inet (blink =
  captive portal), `led3` peers
- **LCD** — 5 pages (page 5 = iperf), buttons via `evkeys`
- **console** — `ttyS0` and `/var/log/net-analyzer.log`
- **net-chat** — single-line posts, `OBSERVE as=dkc kind=chat_msg
  session=Net-Mgr` to `192.168.15.104:7531` (fallback `.223.220`). Off-net
  reports spool to `/tmp/netan-chat.spool` (50-line cap) and flush after the
  next lease.

## Layout

```
utilities/sockit-netan/
├── external/                    BR2_EXTERNAL tree (name: SOCKIT_NETAN)
│   ├── configs/sockit_netan_defconfig
│   ├── board/sockit_netan/
│   │   ├── *.fragment           kernel / busybox / u-boot config deltas
│   │   ├── genimage.cfg         SD layout
│   │   ├── extlinux.conf
│   │   ├── post-build.sh
│   │   ├── evkeys.c             evdev buttons -> text lines for netan-lcd
│   │   └── overlay/             appliance rootfs (scripts, init, udhcpc hook)
│   └── patches/{linux,uboot}/
└── tools/
    ├── sockit-flash-fork.sh     write sdcard-fork.img to /dev/mmcblk0 + verify
    └── sockit-serial-cap.sh     90s ttyUSB0 capture across a power-cycle
```

The buildroot source tree and the `O=` build directory are **not** tracked (they
are ~160 MB of generated output). They live at `/home/dkc/sockit-netan/`, whose
`external/` is a symlink back to this directory — so this repo is the single
source of truth and the existing build dir keeps working unchanged.

## Prerequisites

**You must supply your own SSH key.** `overlay/root/.ssh/authorized_keys` is
deliberately **not** committed (this repo is public). Before building:

```sh
mkdir -p external/board/sockit_netan/overlay/root/.ssh
cp ~/.ssh/id_rsa.pub \
   external/board/sockit_netan/overlay/root/.ssh/authorized_keys
```

`post-build.sh` re-chmods it to 700/600 (buildroot's overlay copy normalizes
modes). Without it the image still boots, but root ssh will not work —
`post-build.sh` warns rather than failing.

The appliance root password is `BR2_TARGET_GENERIC_ROOT_PASSWD="netan"` in the
defconfig, in plaintext, in this public repo. It is only reachable by someone
already on the same LAN as the board. Change it if that is not an acceptable
trade for you.

Also needed, outside this tree:

- buildroot **2026.05.1** (pristine)
- the **socfpga_v2021.07 fork U-Boot** for a working SPL — see below.
  Currently at `/home/dkc/sockit-fork/socfpga_v2021_07/u-boot-with-spl.sfp`.

## Build

```sh
cd /home/dkc/sockit-netan/build && make
```

### ⚠ The one gotcha that will bite you

A plain `make` bakes the **mainline** U-Boot SPL into `images/sdcard.img`, and
**mainline SPL hangs this board** (silent — no console output at all; see
*Boot chain* below). The deploy artifact is `images/sdcard-fork.img`: the same
image with the fork 2021.07 SPL swapped into p1.

```sh
dd if=/home/dkc/sockit-fork/socfpga_v2021_07/u-boot-with-spl.sfp \
   of=images/sdcard-fork.img bs=512 seek=1 conv=notrunc
```

`seek=1` because p1 is type 0xA2 with **no offset** — it starts right after the
MBR (see the comment block in `genimage.cfg`; an explicit 1M offset was tried
and the BootROM stayed silent — do not reintroduce it).

Both `sdcard.img` and `sdcard-fork.img` sit side by side in `images/` with the
same timestamp. Flashing the wrong one gives you a board that does nothing at
all. `tools/sockit-flash-fork.sh` verifies the `U-Boot SPL 2021.07` banner is
physically on the card after writing, and refuses to report success otherwise.

## Flash and boot

```sh
sudo tools/sockit-flash-fork.sh          # writes /dev/mmcblk0, verifies SPL banner
tools/sockit-serial-cap.sh               # then power-cycle within 90s
```

`sockit-flash-fork.sh` hard-codes `IMG=/home/dkc/sockit-netan/build/images/sdcard-fork.img`
and `DEV=/dev/mmcblk0` — check both before running it on a different host.

Board requirements: **SW6 all-ON** to boot, SD inserted, BSEL = SD.

### Boot chain

```
BootROM -> fork U-Boot SPL 2021.07 (p1, 0xA2) -> fork U-Boot
        -> extlinux (p2, FAT) -> Linux 7.0.11 -> ext4 rootfs (p3) -> appliance
```

Mainline U-Boot 2026.04's gen5 SPL hangs on this board in early `cm_basic_init`,
*before* it writes the PLL VCO config — JTAG DAP reads confirmed
`mainpll.vco` NUMER still at its reset default while CPU0 was running. It is a
genuine post-2024.07 `spl_early_init` DM-init regression, **not** a stale qts
handoff. PLL/handoff edits were tried and did not help; the patch from that
attempt is kept at `patches/uboot/0001-sockit-pll-925mhz-main-vco-1850.patch`
for the record. Do not re-litigate the handoff.

## Operating it

Identity: fixed MAC `02:53:4f:43:4b:49` ("SOCKI"), DHCP hostname `sockit-netan`.
Resolve it with `net-lookup sockit-netan`.

```sh
ssh root@$(net-lookup sockit-netan)      # passwordless from bigsony
```

**An inbound ssh connection HOLDS the lease loop** (the daemon checks for an
ESTABLISHED :22 and pauses before release, so ssh'ing in never strands the
box). Run one-shot commands and exit to let cycles resume:

```sh
ssh root@<ip> netan-mode iperf
ssh root@<ip> netan-iperf
```

`touch /tmp/netan-hold` does the same thing manually. `S99netanalyzer stop`
uses `killall -9 udhcpc` deliberately — it skips RELEASE/deconfig so stopping
the service over ssh does not drop the network out from under you.

Power is a Kasa smart plug: `zcu104-power cycle`. That plug powers the
**SoCKit**, despite its stale `Zcu104` alias.

## Known rough edges

- kernel warns `fb_uc1701 has no spi_device_id for UltraChip,uc1701` — binds
  fine, cosmetic.
- native mainline SPL boot remains unfixed (worked around, see above).
- `tools/` scripts hard-code host paths and `/dev/mmcblk0`.
