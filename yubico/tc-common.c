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

static int objname2id(const char *obj_name) {
    const struct tc_ykpiv_protected_object_t *o = tc_ykpiv_get_protected_objects();
    for (;o->id; ++o) {
        if (strcmp(o->name, obj_name) == 0) return o->id;
    }
    return 0;
}


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
    } else if (*path == 'o') {
        prefix = "obj/";
        type = YUBIKEY_METHOD_OBJ;
    } else {
        GERROR("Invalit Yubikey path. Should be: "
                "//yubikey/chl/[1,2] or //yubikey/piv/[slot]");
    }

    while (*prefix) {
        if (*path != *prefix) {
            GERROR("Invalit Yubikey path. Should be: "
                    "//yubikey/chl/[1,2] or //yubikey/piv/[slot]");
        }
        ++path; ++prefix;
    }

    if (*path == 0) GERROR("Slot number's missing in Yubikey path");


    switch(type) {
#ifdef HAVE_YK_CHL
        case YUBIKEY_METHOD_CHL:
            slot = atoi(path);
            if (slot < 1 || slot > 2)
                GERROR("Invalid slot number. "
                        "Should be: //yubikey/chl/[1,2]");
            break;
#endif
#ifdef HAVE_YK_PIV
        case YUBIKEY_METHOD_OBJ:
            slot = objname2id(path);
            if (slot == 0) {
                GERROR("Unknown object: %s", path);
            }
            break;
        case YUBIKEY_METHOD_PIV:
            slot = strtol(path, NULL, 16);
            break;
#endif
    }

    if (slot == 0) GERROR("Invalid slot");

    yk->type = type;
    yk->slot = slot;


    if (type != YUBIKEY_METHOD_OBJ) {
        while (*path != '/') {
            ++path;
            if (*path == 0) return type;
        }
        ++path;

        len = strlen(path);
        if (len > sizeof(yk->secret)) GERROR("Yubikey path is too long");
        memcpy(yk->secret, path, len);
        yk->secret_len = len;
    }


    return type;

err:
    yk->type = -1;
    return rv;
}
