#include <stdio.h>

#include <yubikey.h>
#include <ykdef.h>
#include <ykcore.h>
#include <ykstatus.h>

#include "yubico/error.h"
#include "yubico/chalresp.h"
#include "safe_mem.h"


int tc_ykchl_hmac(int slot, unsigned char *pass, int passlen,
        unsigned char * result, char *errmsg)
{
    int rv = 0;
    unsigned char *response = NULL;
    YK_KEY *yk = 0;

    if (!yk_init()) CERROR(-1, "Yubikey chl. init failed");

    if (!(yk = yk_open_key(0))) CERROR(-1, "Yubikey chl. init failed");

    response = alloc_safe_mem(SHA1_MAX_BLOCK_SIZE);

    if (!response) CERROR(-1, "Error allocating memory for "
            "Yubikey response");

    int yk_cmd;

    if (slot == 1)  {
       yk_cmd = SLOT_CHAL_HMAC1;
    } else if (slot == 2) {
       yk_cmd = SLOT_CHAL_HMAC2;
    } else {
        CERROR(-2, "Yubikey chl. wrong slot number");
    }

    if (!yk_challenge_response(yk, yk_cmd, true, passlen,
                pass, SHA1_MAX_BLOCK_SIZE, response))
    {
        CERROR(-3, "Yubikey yk_challenge_response failed");
    }

    memcpy(result, response, YKCHL_RESPONSE_LENGTH);

err:
    if (yk) yk_close_key(yk);
    free_safe_mem(response);

    return rv;
}
