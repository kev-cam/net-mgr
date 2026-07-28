/* evkeys — stream gpio-keys events as text lines for the netan-lcd script.
 *
 * Output: "K <code> <value>" for key press/release (value 1/0, repeats
 * dropped), "S <code> <value>" for switch changes. On startup the current
 * switch states are emitted so the shell side needs no sysfs parsing.
 * The evdev record is 16 bytes on 32-bit ARM regardless of userspace
 * time_t width: two 32-bit time words, then u16 type, u16 code, s32 value.
 */
#include <fcntl.h>
#include <linux/input.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    struct pollfd pfd[8];
    int n = 0;

    if (argc < 2) {
        fprintf(stderr, "usage: evkeys /dev/input/eventN...\n");
        return 2;
    }
    for (int i = 1; i < argc && n < 8; i++) {
        int fd = open(argv[i], O_RDONLY);
        if (fd < 0) { perror(argv[i]); continue; }
        pfd[n].fd = fd;
        pfd[n].events = POLLIN;
        n++;

        unsigned long sw[(SW_MAX / (8 * sizeof(long))) + 1] = {0};
        if (ioctl(fd, EVIOCGSW(sizeof(sw)), &sw) >= 0)
            for (int b = 0; b <= SW_MAX; b++)
                printf("S %d %d\n", b,
                       (int)((sw[b / (8 * sizeof(long))] >> (b % (8 * sizeof(long)))) & 1));
    }
    if (n == 0)
        return 1;
    fflush(stdout);
    setvbuf(stdout, NULL, _IOLBF, 0);

    for (;;) {
        if (poll(pfd, n, -1) < 0)
            continue;
        for (int i = 0; i < n; i++) {
            if (pfd[i].revents & (POLLERR | POLLHUP | POLLNVAL))
                return 1;   /* device unregistered — exit (init restarts us) */
            if (!(pfd[i].revents & POLLIN))
                continue;
            struct input_event ev;
            if (read(pfd[i].fd, &ev, sizeof(ev)) != sizeof(ev))
                return 1;   /* device gone */
            if (ev.type == EV_KEY && ev.value <= 1)
                printf("K %u %d\n", ev.code, ev.value);
            else if (ev.type == EV_SW)
                printf("S %u %d\n", ev.code, ev.value);
        }
    }
}
