#ifndef YUBICO_TC_COMMON_H
#define YUBICO_TC_COMMON_H

#include "config.h"

struct tc_yubico_key {
    int type;
    int slot;
};

#define YUBIKEY_METHOD_INVALID 0
#define YUBIKEY_METHOD_CHL  1
#define YUBIKEY_METHOD_PIV  2

#define ERR_MESSAGE_LEN 1024
#define YUBIKEY_PATH_PREFIX "//yubikey/"

int tc_parse_yubikey_path(const char *path, struct tc_yubico_key *yk, char *errmsg);

#endif
