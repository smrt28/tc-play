#include <stdio.h>

#include <yubikey.h>
#include <ykdef.h>
#include <ykcore.h>
#include <ykstatus.h>

#include "yubico/error.h"
#include "yubico/chalresp.h"

int tc_ykchl_hmac(int slot, unsigned char *pass, int passlen,
        unsigned char * result, char *errmsg)
{
    int rv = 0;
    YK_KEY *yk = 0;

    if (!yk_init()) CERROR(-1, "Yubikey chl. init failed");

    if (!(yk = yk_open_key(0))) CERROR(-1, "Yubikey chl. init failed");

    unsigned char response[SHA1_MAX_BLOCK_SIZE];
    memset(response, 0, sizeof(response));

    int yk_cmd;

    if (slot == 1)  {
       yk_cmd = SLOT_CHAL_HMAC1;
    } else if (slot == 2) {
       yk_cmd = SLOT_CHAL_HMAC2;
    } else {
        CERROR(-2, "Yubikey chl. wrong slot number");
    }

    if (!yk_challenge_response(yk, yk_cmd, true, passlen,
                pass, sizeof(response), response))
    {
        CERROR(-3, "Yubikey yk_challenge_response failed");
    }

    memcpy(result, response, YKCHL_RESPONSE_LENGTH);
    memset(response, 0, sizeof(response));

err:
    if (yk) yk_close_key(yk);

    return rv;
}
