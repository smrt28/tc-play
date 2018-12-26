#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>

#include "config.h"
#include "yubico/error.h"
#include "yubico/tc-common.h"
#include "yubico/piv.h"

static int is_number(const char *s) {
    if (!s || !*s) return 0;
    while (*s) {
        if (!isdigit(*s)) return 0;
        ++s;
    }
    return 1;
}


/*
 * YubiKey keyfile path format is:
 *
 * //yubikey/(piv|chl)/(slot number)
 *
 *
 * Example:
 *
 * //yubikey/piv/[1-20]  -  use ubikey retired slot [1-20] according to retired_keys and
      *                     retired_objects defined in piv.c
 *
 * //yubikey/chl/[1-2]  -  use chal-resp method, slot 1-2
 *
 */

int tc_parse_yubikey_path(const char *path, struct tc_yubico_key *yk) {
    const char *prefix = YUBIKEY_PATH_PREFIX;
    int type = 0;
    int slot;

    while (*prefix) {
        if (*path != *prefix) return 0;
        ++path; ++prefix;
    }

    if (*path == 'c') { // chl
        prefix = "chl/";
        type = YUBIKEY_METHOD_CHL;

    } else if (*path == 'p') { // piv
        prefix = "piv/";
        type = YUBIKEY_METHOD_PIV;
    } else {
        return 0;
    }

    while (*prefix) {
        if (*path != *prefix) return 0;
        ++path; ++prefix;
    }

    if (!is_number(path)) return 0;

    slot = atoi(path);

    if (type == YUBIKEY_METHOD_CHL && (slot < 1 || slot > 2)) {
        return 0;
    }

    if (type == YUBIKEY_METHOD_PIV && (slot < 1 || slot > YKPIV_SLOTS)) {
        return 0;
    }

    yk->type = type;
    yk->slot = slot;

    return type;
}
