#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>

#include "config.h"
#include "yubico/error.h"
#include "yubico/tc-common.h"
#include "yubico/piv.h"

/*
static int is_number(const char *s) {
    if (!s || !*s) return 0;
    while (*s) {
        if (!isdigit(*s)) return 0;
        ++s;
    }
    return 1;
}
*/

/*
 * YubiKey keyfile path format is:
 *
 * //yubikey/(piv|chl)/(slot number)
 *
 *
 * Example:
 *
 * //yubikey/piv/[piv-slot]/[secret]
 *
 * //yubikey/chl/[1-2]/[secret]
 *
 */

int tc_parse_yubikey_path(const char *path, struct tc_yubico_key *yk,
        char *errmsg)
{
    const char *prefix = YUBIKEY_PATH_PREFIX;
    size_t len;
    int type = 0;
    int slot = 0, rv = 0;

    memset(yk, 0, sizeof(struct tc_yubico_key));

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
        CERROR(-1, "Invalit Yubikey path. Should be: "
                "//yubikey/chl/[1,2] or //yubikey/piv/[slot]");

    }

    while (*prefix) {
        if (*path != *prefix) {
            CERROR(-1, "Invalit Yubikey path. Should be: "
                    "//yubikey/chl/[1,2] or //yubikey/piv/[slot]");
        }
        ++path; ++prefix;
    }

    if (*path == 0) CERROR(-1, "Slot number's missing in Yubikey path");


    switch(type) {
#ifdef HAVE_YK_CHL
        case YUBIKEY_METHOD_CHL:
            slot = atoi(path);
            if (slot < 1 || slot > 2)
                CERROR(-1, "Invalid slot number. "
                        "Should be: //yubikey/chl/[1,2]");
            break;
#endif
#ifdef HAVE_YK_PIV
        case YUBIKEY_METHOD_PIV:
            slot = strtol(path, NULL, 16);
            break;
#endif
    }

    if (slot == 0) CERROR(-1, "Invalid slot");

    yk->type = type;
    yk->slot = slot;

    while (*path != '/') {
        ++path;
        if (*path == 0) return type;
    }
    ++path;

    len = strlen(path);
    if (len > sizeof(yk->secret)) CERROR(-1, "Yubikey path is too long");
    memcpy(yk->secret, path, len);
    yk->secret_len = len;
    return type;

err:
    yk->type = -1;
    return rv;
}
