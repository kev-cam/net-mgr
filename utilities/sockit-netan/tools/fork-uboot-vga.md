# Fork U-Boot VGA bootcmd (reproducibility)

The SoCKit's VGA is FPGA-driven, and Linux can't program the fabric at runtime.
So the fabric is loaded by the **fork** U-Boot (`socfpga_v2021.07`, the only SPL
that boots this board) *before* the kernel, via a custom `bootcmd`. Mainline
U-Boot — which buildroot builds — hangs on this board, so this change canNOT go
in `uboot.fragment`; it lives in the fork tree at
`/home/dkc/sockit-fork/socfpga_v2021_07`.

## The change

Added to the fork's `.config` (backup: `.config.pre-vga`):

```
CONFIG_USE_BOOTCOMMAND=y
CONFIG_BOOTCOMMAND="fatload mmc 0:2 0x2000000 vga_hps.rbf && fpga load 0 0x2000000 ${filesize} && bridge enable; run distro_bootcmd"
```

- `${filesize}` is **literal** — U-Boot's hush shell expands it at runtime from
  the preceding `fatload` (do NOT hardcode; the actual rbf is 7,007,204 B =
  0x6AEBE4, and a wrong size silently fails).
- `mmc 0:2` = the FAT boot partition (p1=SPL/0xA2, **p2=FAT**, p3=ext4). Confirm
  on console with `part list mmc 0` if VGA stays dark.
- `;` (not `&&`) before `run distro_bootcmd` — any load/fpga/bridge failure still
  boots the kernel, so WiFi/BLE/eth0 are never endangered.

## Rebuild

```sh
cd /home/dkc/sockit-fork/socfpga_v2021_07
CC=/home/dkc/sockit-netan/build/host/bin/arm-buildroot-linux-gnueabihf-
make ARCH=arm CROSS_COMPILE="$CC" olddefconfig
make ARCH=arm CROSS_COMPILE="$CC" -j"$(nproc)"     # -> u-boot-with-spl.sfp
```

Then dd `u-boot-with-spl.sfp` into p1 of the SD image (seek=1, the fork-SPL swap):

```sh
dd if=u-boot-with-spl.sfp of=<sdcard-fork.img or /dev/sdX> bs=512 seek=1 conv=notrunc
```

## rbf provenance caveat

`vga_hps.rbf` must be an HPS passive-parallel (FPP/MSEL=PP16) raw `.rbf` from
`quartus_cpf`, NOT a JTAG `.sof`-derived image. If VGA stays dark but the board
boots normally, regenerate the rbf for the HPS scheme and just swap the file on
the FAT partition — no rebuild.
