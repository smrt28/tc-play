#ifndef YUBICO_CHALRESP_H
#define YUBICO_CHALRESP_H

#define YKCHL_RESPONSE_LENGTH 20

int tc_ykchl_hmac(int slot, unsigned char *pass, int passlen,
        unsigned char * result, char *errmsg);

#endif
