
#include <unistd.h>
#include <getopt.h>
#include <ykpiv.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "yubico/piv.h"
#include "yubico/error.h"
#include "safe_mem.h"

#define MAX_PASSSZ      64

struct _ykey_options {
    int slot;
    const char *pin;
};

static void print_hex(unsigned char *buf, size_t len) {
    size_t i;
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);

    printf("\n");
}

static void usage() {
    printf("usage: yubico-keyfile -s slot [-p pin] [-o keyfile]\n\n"
            "-s, --slot=<slot>\n"
                "\t If slot=list lists available slots\n"
            "-p, --pin=<pin>"
                "\t PIV pin\n"
            "-o, --out=<file path>"
                "\t FILE write secret to keyfile\n"
            );
}

static void print_slots() {
printf(
"Slots available:\n"
"   AUTHENTICATION 0x9a\n"
"   SIGNATURE      0x9c\n"
"   KEYMGM         0x9d\n"
"   CARDAUTH       0x9e\n"
"\n"
"Slots only available on the YubiKey 4 and 5:\n"
"   RETIRED-01 0x82\n"
"   RETIRED-02 0x83\n"
"   RETIRED-03 0x84\n"
"   RETIRED-04 0x85\n"
"   RETIRED-05 0x86\n"
"   RETIRED-06 0x87\n"
"   RETIRED-07 0x88\n"
"   RETIRED-08 0x89\n"
"   RETIRED-09 0x8a\n"
"   RETIRED-10 0x8b\n"
"   RETIRED-11 0x8c\n"
"   RETIRED-12 0x8d\n"
"   RETIRED-13 0x8e\n"
"   RETIRED-14 0x8f\n"
"   RETIRED-15 0x90\n"
"   RETIRED-16 0x91\n"
"   RETIRED-17 0x92\n"
"   RETIRED-18 0x93\n"
"   RETIRED-19 0x94\n"
"   RETIRED-20 0x95\n"
);
}

int main(int argc, char **argv) {
    int option_index = 0;
    int c, rv = 0, len;


    const char *keyfile = NULL;
    unsigned char *secret = NULL;
    int fd = -1;
    char *pinbuf = NULL;
    char errmsg[ERR_MESSAGE_LEN];
    struct _ykey_options o;
    unsigned char *pass = NULL;

    if (argc == 1) {
        usage();
        return 1;
    }

    memset(&o, 0, sizeof(o));
    atexit(check_and_purge_safe_mem);

    for (;;) {
        static struct option long_options[] = {
            { "slot", required_argument, 0, 's' },
            { "pin", optional_argument, 0, 'p' },
            { "out", optional_argument, 0, 'o' },
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "hs:p:o:", long_options, &option_index);
        if (c == -1) break;
        switch (c) {
            case 's':
                if (strcmp(optarg, "list") == 0) {
                    print_slots();
                    return 1;
                }
                if (strlen(optarg) > 2 && optarg[0] == '0' && optarg[0] == 'x') {
                    o.slot = strtol(optarg + 2, NULL, 16);
                } else {
                    o.slot = strtol(optarg, NULL, 16);
                }
                break;
            case 'p':
                o.pin = optarg;
                break;
            case 'o':
                keyfile = optarg;
                break;
            case 'h':
                usage();
                return 1;
            default:
                CERROR(ERR_YK_ARGS, "Unknown option\n");
        }
    }

    if (enable_safe_mem_global_lock() != 0) {
        fprintf(stderr, "WARNING: can't enable memory global mlock!\n");
    }

    pinbuf = alloc_safe_mem(YKPIV_PIN_BUF_SIZE);

    if (!pinbuf) CERROR(ERR_YK_GENERAL, "Can't allocate memory for bin buffer!");

    memset(pinbuf, 0, YKPIV_PIN_BUF_SIZE);
    secret = alloc_safe_mem(YKPIV_SECRET_LEN);
    if (!secret) CERROR(ERR_YK_GENERAL, "Can't allocate memory for secret!");

    memset(secret, 0, YKPIV_SECRET_LEN);

    len = 0;
    if (!o.pin) {
        if (tc_ykpiv_getpin(pinbuf) != 0) {
            CERROR(ERR_YK_ARGS, "PIN must be 6-8 characters long!");
        }
        o.pin = pinbuf;
    } else {
        len = strlen(o.pin);
        if (len < YKPIV_PIN_MIN_SIZE || len > YKPIV_PIN_MAX_SIZE) {
            CERROR(ERR_YK_ARGS, "PIN must be 6-8 characters long!");
        }
    }

    struct tc_ykpiv_args args;
    memset(&args, 0, sizeof(args));

    pass = alloc_safe_mem(MAX_PASSSZ);
    if (!pass) {
        CERROR(ERR_YK_GENERAL, "can't allocate memory");
    }
    memset(pass, 0, MAX_PASSSZ);

    char *pw = getpass("Password:");
    len = strlen(pw);
    if (len > 64) len = 64;
    memcpy(pass, pw, len);

    args.pass = pass;
    args.pass_len = MAX_PASSSZ;

    rv = tc_ykpiv_fetch_secret(o.slot, o.pin, secret, YKPIV_SECRET_LEN, errmsg, &args);
    if (rv != 0) goto err;

    print_hex(secret, YKPIV_SECRET_LEN);
    if (keyfile) {
        fd = open(keyfile, O_CREAT | O_WRONLY, 0644);
        if (fd < 0) {
            CERROR(ERR_YK_ARGS, "Can't open keyfile!");
        }
        if (write(fd, secret, YKPIV_SECRET_LEN) != YKPIV_SECRET_LEN) {
            CERROR(ERR_YK_ARGS, "Can't write keyfile!");
        }
    }

err:
    if (rv) {
        fprintf(stderr, "error: %s; [error-code=%d]\n", errmsg, rv);
    }

    free_safe_mem(secret);
    free_safe_mem(pinbuf);
    free_safe_mem(pass);
    if (fd >= 0) close(fd);

    check_and_purge_safe_mem();
    return rv;
}
