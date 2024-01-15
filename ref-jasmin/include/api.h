#ifndef JADE_SIGN_sphincsplus_amd64_ref_API_H
#define JADE_SIGN_sphincsplus_amd64_ref_API_H

#define JADE_SIGN_sphincsplus_amd64_ref_SECRETKEYBYTES SPX_SK_BYTES
#define JADE_SIGN_sphincsplus_amd64_ref_PUBLICKEYBYTES SPX_PK_BYTES
#define JADE_SIGN_sphincsplus_amd64_ref_BYTES          SPX_BYTES

#define JADE_SIGN_sphincsplus_amd64_ref_ALGNAME        "Sphincs+"
#define JADE_SIGN_sphincsplus_amd64_ref_ARCH           "amd64"
#define JADE_SIGN_sphincsplus_amd64_ref_IMPL           "ref"

#include <stddef.h>
#include <stdint.h>

#include <params.h>

int crypto_sign_keypair_jazz(uint8_t *pk, uint8_t *sk);

int crypto_sign_jazz(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *sk);

int crypto_sign_open_jazz(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *pk);

#endif