#include <fcntl.h>
#include <termios.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "yubico/error.h"
#include "yubico/piv.h"

#include "safe_mem.h"

static struct termios termios_old;
static int tty_fd;

static void sigint_termios(int sa)
{
    tcsetattr(tty_fd, TCSAFLUSH, &termios_old);
    exit(sa);
}

/* simplified read_passphrase from tcplay */
static int read_passphrase(const char *prompt, char *pass, size_t bufsz)
{
    struct termios termios_new;
    ssize_t n = 0;
    int fd = STDIN_FILENO;
    struct sigaction act, old_act;
    int is_tty = isatty(fd);

    if (!pass) return 0;
    if (bufsz == 0) return 0;
    if (is_tty == 0) errno = 0;

    fprintf(stderr, "%s", prompt);
    fflush(stdout);

    if (is_tty) {
        tcgetattr(fd, &termios_old);
        memcpy(&termios_new, &termios_old, sizeof(termios_new));
        termios_new.c_lflag &= ~ECHO;

        act.sa_handler = sigint_termios;
        act.sa_flags   = SA_RESETHAND;
        sigemptyset(&act.sa_mask);

        tty_fd = fd;
        sigaction(SIGINT, &act, &old_act);
        tcsetattr(fd, TCSAFLUSH, &termios_new);
    }

    n = read(fd, pass, bufsz);
    if (n > 0) {
        pass[n-1] = 0; 
    } else if (n == 0) {
        pass[0] = 0;
    }

    if (is_tty) {
        tcsetattr(fd, TCSAFLUSH, &termios_old);
        fputc('\n', stderr);
        sigaction(SIGINT, &old_act, NULL);
    }

    return n - 1;
}

int tc_ykpiv_getpin(char *pin, char *errmsg) {
    int rv = 0;
    int r = read_passphrase("Yubikey PIN:", pin, YKPIV_PIN_BUF_SIZE);

    if (r < 6 || r > 8) {
        CERROR(-1, "PIN must be 6-8 characters long.");
    }

err:
    return rv;
}
