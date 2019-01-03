
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

#include "yubico/tc-common.h"
#include "yubico/piv.h"
#include "yubico/error.h"
#include "safe_mem.h"



static void print_hex(unsigned char *buf, size_t len) {
    size_t i;
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);

    printf("\n");
}

static void usage() {
    printf("usage: yubico-keyfile -s slot [-p pin] [-o keyfile]\n\n"
            "-s, --yubikey-path=<yubikey path>\n"
                "\t If slot=list lists available slots\n"
            "-p, --pin=<pin>"
                "\t PIV pin\n"
            "-o, --out=<file path>"
                "\t FILE write secret to keyfile\n"
            );
}

static void print_slots() {
printf(
"CHL slots\n"
"   //yubikey/chl/1\n"
"   //yubikey/chl/2\n"
"\n"
"PIV slots available:\n"
"   AUTHENTICATION //yubikey/piv/9a\n"
"   SIGNATURE      //yubikey/piv/9c\n"
"   KEYMGM         //yubikey/piv/9d\n"
"   CARDAUTH       //yubikey/piv/9e\n"
"\n"
"PIV slots only available on the YubiKey 4 and 5:\n"
"   RETIRED-01 //yubikey/piv/82\n"
"   RETIRED-02 //yubikey/piv/83\n"
"   RETIRED-03 //yubikey/piv/84\n"
"   RETIRED-04 //yubikey/piv/85\n"
"   RETIRED-05 //yubikey/piv/86\n"
"   RETIRED-06 //yubikey/piv/87\n"
"   RETIRED-07 //yubikey/piv/88\n"
"   RETIRED-08 //yubikey/piv/89\n"
"   RETIRED-09 //yubikey/piv/8a\n"
"   RETIRED-10 //yubikey/piv/8b\n"
"   RETIRED-11 //yubikey/piv/8c\n"
"   RETIRED-12 //yubikey/piv/8d\n"
"   RETIRED-13 //yubikey/piv/8e\n"
"   RETIRED-14 //yubikey/piv/8f\n"
"   RETIRED-15 //yubikey/piv/90\n"
"   RETIRED-16 //yubikey/piv/91\n"
"   RETIRED-17 //yubikey/piv/92\n"
"   RETIRED-18 //yubikey/piv/93\n"
"   RETIRED-19 //yubikey/piv/94\n"
"   RETIRED-20 //yubikey/piv/95\n"
);
}


static int self_test() {
    char errmsg[ERR_MESSAGE_LEN];
    struct tc_yubico_key k;

    memset(&k, 0, sizeof(k));
    tc_parse_yubikey_path("//yubikey/piv/82/x", &k, errmsg);
    if (k.secret_len != 1) return __LINE__;

    memset(&k, 0, sizeof(k));
    tc_parse_yubikey_path("//yubikey/piv/82/xx", &k, errmsg);
    if (k.secret_len != 2) return __LINE__;
    if (k.type != 2) return __LINE__;

    memset(&k, 0, sizeof(k));
    tc_parse_yubikey_path("//yubikey/chl/1/xx", &k, errmsg);
    if (k.secret_len != 2) return __LINE__;
    if (k.type != 1) return __LINE__;

    memset(&k, 0, sizeof(k));
    tc_parse_yubikey_path("//yubikey/chl/3/xx", &k, errmsg);
    if (k.type != -1) return __LINE__;

    memset(&k, 0, sizeof(k));
    tc_parse_yubikey_path("//yubikey/piv/82/", &k, errmsg);
    if (k.secret_len != 0) return __LINE__;

    memset(&k, 0, sizeof(k));
    tc_parse_yubikey_path("//yubikey/pi/82/", &k, errmsg);
    if (k.secret_len != 0) return __LINE__;
    if (k.type != -1) return __LINE__;

    return 0;
}

int main(int argc, char **argv) {
    int option_index = 0;
    int c, rv = 0, len;


    const char *keyfile = NULL;
    unsigned char *secret = NULL;
    int fd = -1;
    const char *pin = NULL;
    char *pinbuf = NULL;
    char errmsg[ERR_MESSAGE_LEN];
    unsigned char *pass = NULL;
    struct tc_yubico_key key;

    if (argc == 1) {
        usage();
        return 1;
    }

    atexit(check_and_purge_safe_mem);

    memset(&key, 0, sizeof(key));

    for (;;) {
        static struct option long_options[] = {
            { "yubikey-path", required_argument, 0, 's' },
            { "pin", optional_argument, 0, 'p' },
            { "out", optional_argument, 0, 'o' },
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "hs:p:o:t", long_options, &option_index);
        if (c == -1) break;
        switch (c) {
            case 's':
                if (strcmp(optarg, "list") == 0) {
                    print_slots();
                    return 1;
                }
                if (tc_parse_yubikey_path(optarg, &key, errmsg) <= 0) {
                    CERROR(ERR_YK_ARGS, "Invalid yubikey path");
                }
                break;
            case 'p':
                pin = optarg;
                break;
            case 'o':
                keyfile = optarg;
                break;
            case 'h':
                usage();
                return 1;
            case 't':
                printf("%d\n", self_test());
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
    if (!pin) {
        if (tc_ykpiv_getpin(pinbuf) != 0) {
            CERROR(ERR_YK_ARGS, "PIN must be 6-8 characters long!");
        }
        pin = pinbuf;
    } else {
        len = strlen(pin);
        if (len < YKPIV_PIN_MIN_SIZE || len > YKPIV_PIN_MAX_SIZE) {
            CERROR(ERR_YK_ARGS, "PIN must be 6-8 characters long!");
        }
    }

    pass = alloc_safe_mem(MAX_PASSSZ);
    if (!pass) CERROR(ERR_YK_GENERAL, "can't allocate memory");
    memset(pass, 0, MAX_PASSSZ);

    if (key.secret_len > 0) {
        memcpy(pass, key.secret, key.secret_len);
    } else {
        char *pw = getpass("Password:");
        len = strlen(pw);
        if (len > 64) len = 64;
        memcpy(pass, pw, len);
    }

    switch(key.type) {
        case YUBIKEY_METHOD_PIV:
            rv = tc_ykpiv_fetch_secret(key.slot, pin, secret,
                    YKPIV_SECRET_LEN, pass, MAX_PASSSZ, errmsg);
            if (rv != 0) goto err;
            break;
        default:
            CERROR(ERR_YK_ARGS, "not implemented for the yubikey path");
            break;
    }

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
