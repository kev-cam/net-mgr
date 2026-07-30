/* netan-vga — push an 80x30 text screen to the FPGA VGA character buffer.
 *
 * Maps the char buffer at the lwh2f base and fills 80 cols x 30 rows from
 * stdin (one line per row, clipped/space-padded), 4 chars per 32-bit word
 * (byte 0 = leftmost) to match the FPGA character generator's 8x16 font.
 *
 * The HPS->FPGA bridges are enabled and the fabric is configured AT BOOT by
 * the fork U-Boot bootcmd (fpga load + bridge enable), so this deliberately
 * does NOT poke rstmgr.brgmodrst / the NIC-301 L3 remap — those pokes on a
 * blank fabric are what warm-reset the board historically. Just map + write.
 *
 * Usage:  netan-vga-render | netan-vga        (loop it for a live dashboard)
 */
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#define LWH2F_BASE 0xFF200000UL     /* charbuf window base (offset 0) */
#define WIN        0x1000UL          /* 4 KiB: 600 words = 80*30/4, fits */
#define COLS 80
#define ROWS 30

int main(void)
{
    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) { perror("/dev/mem"); return 1; }

    unsigned long page = LWH2F_BASE & ~0xFFFUL, off = LWH2F_BASE & 0xFFFUL;
    void *m = mmap(0, WIN + off, PROT_READ | PROT_WRITE, MAP_SHARED, fd, page);
    if (m == MAP_FAILED) { perror("mmap lwh2f"); return 1; }
    volatile uint32_t *buf = (volatile uint32_t *)((unsigned char *)m + off);

    unsigned char scr[COLS * ROWS];
    memset(scr, ' ', sizeof scr);

    char line[256];
    int row = 0;
    while (row < ROWS && fgets(line, sizeof line, stdin)) {
        size_t n = strcspn(line, "\n");
        if (n > COLS) n = COLS;
        memcpy(&scr[row * COLS], line, n);
        row++;
    }

    for (int i = 0; i < COLS * ROWS; i += 4) {
        buf[i / 4] = (uint32_t)scr[i]
                   | ((uint32_t)scr[i + 1] << 8)
                   | ((uint32_t)scr[i + 2] << 16)
                   | ((uint32_t)scr[i + 3] << 24);
    }
    return 0;
}
