
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "yubico/error.h"
#include "yubico/tc-common.h"

#ifdef HAVE_YK_PIV
#include <ykpiv.h>
#include "yubico/piv.h"
#endif

#ifdef HAVE_YK_CHL
#include "yubico/chalresp.h"
#endif

#include "safe_mem.h"

#include "config.h"

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
#ifdef HAVE_YK_CHL
"CHL slots\n"
"   //yubikey/chl/1/[nonce]\n"
"   //yubikey/chl/2/[nonce]\n"
"\n"
#endif
#ifdef HAVE_YK_PIV
"PIV slots available:\n"
"   AUTHENTICATION //yubikey/piv/9a/[nonce]\n"
"   SIGNATURE      //yubikey/piv/9c/[nonce]\n"
"   KEYMGM         //yubikey/piv/9d/[nonce]\n"
"   CARDAUTH       //yubikey/piv/9e/[nonce]\n"
"\n"
"PIV slots only available on the YubiKey 4 and 5:\n"
"   RETIRED_01 //yubikey/piv/82/[nonce]\n"
"   RETIRED_02 //yubikey/piv/83/[nonce]\n"
"   RETIRED_03 //yubikey/piv/84/[nonce]\n"
"   RETIRED_04 //yubikey/piv/85/[nonce]\n"
"   RETIRED_05 //yubikey/piv/86/[nonce]\n"
"   RETIRED_06 //yubikey/piv/87/[nonce]\n"
"   RETIRED_07 //yubikey/piv/88/[nonce]\n"
"   RETIRED_08 //yubikey/piv/89/[nonce]\n"
"   RETIRED_09 //yubikey/piv/8a/[nonce]\n"
"   RETIRED_10 //yubikey/piv/8b/[nonce]\n"
"   RETIRED_11 //yubikey/piv/8c/[nonce]\n"
"   RETIRED_12 //yubikey/piv/8d/[nonce]\n"
"   RETIRED_13 //yubikey/piv/8e/[nonce]\n"
"   RETIRED_14 //yubikey/piv/8f/[nonce]\n"
"   RETIRED_15 //yubikey/piv/90/[nonce]\n"
"   RETIRED_16 //yubikey/piv/91/[nonce]\n"
"   RETIRED_17 //yubikey/piv/92/[nonce]\n"
"   RETIRED_18 //yubikey/piv/93/[nonce]\n"
"   RETIRED_19 //yubikey/piv/94/[nonce]\n"
"   RETIRED_20 //yubikey/piv/95/[nonce]\n"
);

const struct tc_ykpiv_protected_object_t *o = tc_ykpiv_get_protected_objects();
printf("\nPIV protected objects:\n");
for (;o->id;++o) {
    printf("   0x%x\t//yubikey/obj/%s\n", o->id, o->name);
}

#endif

}


static int self_test() {
    char errmsg[ERR_MESSAGE_LEN];
    struct tc_yubico_key k;
#ifdef HAVE_YK_PIV
    memset(&k, 0, sizeof(k));
    tc_parse_yubikey_path("//yubikey/piv/82/x", &k, errmsg);
    if (k.secret_len != 1) return __LINE__;

    memset(&k, 0, sizeof(k));
    tc_parse_yubikey_path("//yubikey/piv/82/xx", &k, errmsg);
    if (k.secret_len != 2) return __LINE__;
    if (k.type != 2) return __LINE__;


    memset(&k, 0, sizeof(k));
    tc_parse_yubikey_path("//yubikey/piv/82/", &k, errmsg);
    if (k.secret_len != 0) return __LINE__;

    memset(&k, 0, sizeof(k));
    tc_parse_yubikey_path("//yubikey/pi/82/", &k, errmsg);
    if (k.secret_len != 0) return __LINE__;
    if (k.type != -1) return __LINE__;
#endif
#ifdef HAVE_YK_CHL
    memset(&k, 0, sizeof(k));
    tc_parse_yubikey_path("//yubikey/chl/1/xx", &k, errmsg);
    if (k.secret_len != 2) return __LINE__;
    if (k.type != 1) return __LINE__;

    memset(&k, 0, sizeof(k));
    tc_parse_yubikey_path("//yubikey/chl/3/xx", &k, errmsg);
    if (k.type != -1) return __LINE__;
#endif
    return 0;
}

int write_keyfile(const char *keyfile, unsigned char *secret, int len, char *errmsg) {
    int rv = 0;

    if (!keyfile) return 0;

    int fd = open(keyfile, O_CREAT | O_WRONLY, 0644);

    if (fd < 0) CERROR(ERR_YK_ARGS, "Can't open keyfile!");
    if (write(fd, secret, len) != len) {
        CERROR(ERR_YK_ARGS, "Can't write keyfile!");
    }
err:
    if (fd >= 0) close(fd);
    return rv;
}


#ifdef HAVE_YK_CHL
int handle_chl(struct tc_yubico_key *key, const char *keyfile, char *errmsg) {
    int fd = -1;
    int rv = 0;
    int len;
    unsigned char *pass = NULL;
    unsigned char *secret = NULL;

    pass = alloc_safe_mem(MAX_PASSSZ);
    if (!pass) CERROR(ERR_YK_GENERAL, "can't allocate memory");
    memset(pass, 0, MAX_PASSSZ);

    secret = alloc_safe_mem(YKCHL_RESPONSE_LENGTH);
    if (!secret) CERROR(ERR_YK_GENERAL, "Can't allocate memory for secret!");

    if (key->secret_len > 0) {
        memcpy(pass, key->secret, key->secret_len);
    } else {
        char *pw = getpass("Password:");
        len = strlen(pw);
        if (len > 64) len = 64;
        memcpy(pass, pw, len);
    }

    if ((rv = tc_ykchl_hmac(key->slot, pass, MAX_PASSSZ, secret, errmsg)) != 0) goto err;

    print_hex(secret, YKCHL_RESPONSE_LENGTH);
    if ((rv = write_keyfile(keyfile, secret, YKCHL_RESPONSE_LENGTH, errmsg)) != 0) goto err;
err:
    free_safe_mem(secret);
    free_safe_mem(pass);
    if (fd >= 0) close(fd);
    return rv;
}
#endif

#ifdef HAVE_YK_PIV
int handle_piv(const char *pin, struct tc_yubico_key *key, const char *keyfile, char *errmsg) {
    int rv = 0;
    unsigned char *secret = NULL;
    char *pinbuf = NULL;
    int len;
    unsigned char *pass = NULL;

    secret = alloc_safe_mem(YKPIV_SECRET_LEN);
    if (!secret) CERROR(ERR_YK_GENERAL, "Can't allocate memory for secret!");
    memset(secret, 0, YKPIV_SECRET_LEN);

    len = 0;
    if (!pin) {
        pinbuf = alloc_safe_mem(YKPIV_PIN_BUF_SIZE);
        if (!pinbuf) CERROR(ERR_YK_GENERAL, "Can't allocate memory for bin buffer!");

        if ((rv = tc_ykpiv_getpin(pinbuf, errmsg)) != 0) goto err;
        pin = pinbuf;
    }

    pass = calloc_safe_mem(MAX_PASSSZ);
    if (!pass) CERROR(ERR_YK_GENERAL, "can't allocate memory");

    if (key->secret_len > 0) {
        memcpy(pass, key->secret, key->secret_len);
    } else {
        char *pw = getpass("Password:");
        len = strlen(pw);
        if (len > 64) len = 64;
        memcpy(pass, pw, len);
    }

    rv = tc_ykpiv_fetch_secret(key->slot, pin, secret,
            YKPIV_SECRET_LEN, pass, MAX_PASSSZ, errmsg);

    if (rv != 0) goto err;

    print_hex(secret, YKPIV_SECRET_LEN);
    if ((rv = write_keyfile(keyfile, secret, YKPIV_SECRET_LEN, errmsg)) != 0) goto err;

err:
    free_safe_mem(secret);
    free_safe_mem(pinbuf);
    free_safe_mem(pass);
    return rv;
}


int handle_obj(const char *pin, struct tc_yubico_key *key, const char *keyfile, char *errmsg) {
    int rv = 0;
    unsigned char *secret = NULL;
    char *pinbuf = NULL;
    unsigned long len = 3072;

    secret = alloc_safe_mem(len);

    if (!secret) CERROR(ERR_YK_GENERAL, "Can't allocate memory for secret!");
    memset(secret, 0, YKPIV_SECRET_LEN);

    if (!pin) {
        pinbuf = alloc_safe_mem(YKPIV_PIN_BUF_SIZE);
        if (!pinbuf) CERROR(ERR_YK_GENERAL, "Can't allocate memory for bin buffer!");

        if ((rv = tc_ykpiv_getpin(pinbuf, errmsg)) != 0) goto err;
        pin = pinbuf;
    }

    rv = tc_fetch_object(pin, key->slot, secret, &len, errmsg);
    if (rv != 0) goto err;

    print_hex(secret, len);
    if ((rv = write_keyfile(keyfile, secret, len, errmsg)) != 0) goto err;

err:
    free_safe_mem(secret);
    free_safe_mem(pinbuf);
    return rv;
}
#endif

int main(int argc, char **argv) {
    int option_index = 0;
    int c, rv = 0;
    const char *keyfile = NULL;
#ifdef HAVE_YK_PIV
    const char *pin = NULL;
#endif
    char errmsg[ERR_MESSAGE_LEN];
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
                if (strcmp(optarg, "list") == 0 || strcmp(optarg, "help") == 0) {
                    print_slots();
                    return 1;
                }
                if (tc_parse_yubikey_path(optarg, &key, errmsg) <= 0) {
                    CERROR(ERR_YK_ARGS, "Invalid yubikey path");
                }
                break;
#ifdef HAVE_YK_PIV
            case 'p':
                pin = optarg;
                break;
#endif
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
                CERROR(ERR_YK_ARGS, "Unknown option");
                break;
        }
    }

    if (enable_safe_mem_global_lock() != 0) {
        fprintf(stderr, "WARNING: can't enable memory global mlock!\n");
    }

    switch(key.type) {
#ifdef HAVE_YK_PIV
        case YUBIKEY_METHOD_PIV:
            rv = handle_piv(pin, &key, keyfile, errmsg);
            break;
        case YUBIKEY_METHOD_OBJ:
            rv = handle_obj(pin, &key, keyfile, errmsg);
            break;
#endif
#ifdef HAVE_YK_CHL
        case YUBIKEY_METHOD_CHL:
            rv = handle_chl(&key, keyfile, errmsg);
            break;
#endif
        default:
            CERROR(ERR_YK_ARGS, "not a yubikey path");
            break;
    }

err:
    if (rv) {
        fprintf(stderr, "error: %s; [error-code=%d]\n", errmsg, rv);
    }

    check_and_purge_safe_mem();
    return rv;
}
