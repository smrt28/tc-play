#ifndef ARGON2_HASH_H
#define ARGON2_HASH_H


#ifndef HAVE_ARGON2
#error can compile only --with-argon2
#endif

int argon2(const char *pass_, int passlen,
        const unsigned char *salt, int saltlen,
        unsigned char *hash, size_t hash_len,
        int cost);


#endif
