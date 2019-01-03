#ifndef YUBICO_TC_COMMON_H
#define YUBICO_TC_COMMON_H

#include "config.h"

#define MAX_PASSSZ      64

struct tc_yubico_key {
    int type;
    int slot;
    int secret_len;
    unsigned char secret[MAX_PASSSZ];
};

#define YUBIKEY_METHOD_INVALID 0
#define YUBIKEY_METHOD_CHL  1
#define YUBIKEY_METHOD_PIV  2

#define ERR_MESSAGE_LEN 1024
#define YUBIKEY_PATH_PREFIX "//yubikey/"

int tc_parse_yubikey_path(const char *path, struct tc_yubico_key *yk, char *errmsg);

#endif
