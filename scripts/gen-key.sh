#!/bin/bash

KEY_PATH=/dev/shm
PRI_KEY_FILE=$KEY_PATH/private-key.pem
PUB_KEY_FILE=$KEY_PATH/public-key.pem



openssl genrsa -out $PRI_KEY_FILE 2048
openssl rsa -in $PRI_KEY_FILE -outform PEM -pubout -out $PUB_KEY_FILE

exit

cat /dev/shm/private-key.pem | yubico-piv-tool -a import-key -s 83

openssl rsa -noout -text -inform PEM  -pubin < /dev/shm/public-key.pem

#define YKPIV_KEY_RETIRED1 0x82
#define YKPIV_KEY_RETIRED2 0x83
#define YKPIV_KEY_RETIRED3 0x84
#define YKPIV_KEY_RETIRED4 0x85
#define YKPIV_KEY_RETIRED5 0x86
#define YKPIV_KEY_RETIRED6 0x87
#define YKPIV_KEY_RETIRED7 0x88
#define YKPIV_KEY_RETIRED8 0x89
#define YKPIV_KEY_RETIRED9 0x8a
#define YKPIV_KEY_RETIRED10 0x8b
#define YKPIV_KEY_RETIRED11 0x8c
#define YKPIV_KEY_RETIRED12 0x8d
#define YKPIV_KEY_RETIRED13 0x8e
#define YKPIV_KEY_RETIRED14 0x8f
#define YKPIV_KEY_RETIRED15 0x90
#define YKPIV_KEY_RETIRED16 0x91
#define YKPIV_KEY_RETIRED17 0x92
#define YKPIV_KEY_RETIRED18 0x93
#define YKPIV_KEY_RETIRED19 0x94
#define YKPIV_KEY_RETIRED20 0x95
