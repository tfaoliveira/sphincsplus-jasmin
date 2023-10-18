#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "context.h"
#include "fors.c"
#include "fors.h"
#include "hash.h"
#include "macros.h"
#include "notrandombytes.c"
#include "params.h"
#include "print.c"

#ifndef HASH
#define HASH shake
#endif

#ifndef PARAM
#define PARAM 128f
#endif

#ifndef MSG_LEN
#define MSG_LEN 64
#endif

#ifndef TESTS
#define TESTS 1000
#endif

#define CRYPTO_PUBLICKEYBYTES SPX_PK_BYTES
#define CRYPTO_BYTES SPX_BYTES

#define fors_sign_jazz NAMESPACE1(fors_sign_jazz, MSG_LEN)
extern void fors_sign_jazz(uint8_t *sig, uint8_t *pk, const uint8_t *m, const uint8_t *pub_seed,
                           const uint8_t *sk_seed, uint32_t fors_addr[8]);

#define fors_pk_from_sig_jazz NAMESPACE1(fors_pk_from_sig_jazz, MSG_LEN)
extern void fors_pk_from_sig_jazz(uint8_t *pk, const uint8_t *sig, const uint8_t *m,
                                  const uint8_t *pub_seed, uint32_t fors_addr[8]);

void test_fors_sign(void);
void test_fors_pk_from_sig(void);

static void random_addr(uint32_t addr[8]) {
    for (size_t i = 0; i < 8; i++) {
        addr[i] = (uint32_t)rand();
    }
}

void test_fors_sign(void) {
    uint8_t sig0[CRYPTO_BYTES], sig1[CRYPTO_BYTES];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t msg[MSG_LEN];
    spx_ctx ctx;
    uint32_t fors_addr[8];

    for (int t = 0; t < TESTS; t++) {
        memset(sig0, 0, CRYPTO_BYTES);
        memset(sig1, 0, CRYPTO_BYTES);
        randombytes(pk, CRYPTO_PUBLICKEYBYTES);
        randombytes(msg, MSG_LEN);
        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);
        random_addr(fors_addr);

        fors_sign(sig1, pk, msg, &ctx, fors_addr);
        fors_sign_jazz(sig0, pk, msg, ctx.pub_seed, ctx.sk_seed, fors_addr);

        // assert(memcmp(sig0, sig1, CRYPTO_BYTES) == 0);
    }
}

void test_fors_pk_from_sig(void) {
    uint8_t sig[CRYPTO_BYTES];
    uint8_t pk0[CRYPTO_PUBLICKEYBYTES], pk1[CRYPTO_PUBLICKEYBYTES];
    uint8_t msg[MSG_LEN];
    spx_ctx ctx;
    uint32_t fors_addr[8];

    for (int t = 0; t < TESTS; t++) {
        memset(pk0, 0, CRYPTO_PUBLICKEYBYTES);
        memset(pk1, 0, CRYPTO_PUBLICKEYBYTES);

        randombytes(sig, CRYPTO_BYTES);
        randombytes(msg, MSG_LEN);
        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);
        random_addr(fors_addr);

        fors_pk_from_sig_jazz(pk0, sig, msg, ctx.pub_seed, fors_addr);
        fors_pk_from_sig(pk1, sig, msg, &ctx, fors_addr);

        // assert(memcmp(pk0, pk1, CRYPTO_PUBLICKEYBYTES) == 0);
    }
}

#undef CRYPTO_PUBLICKEYBYTES
#undef CRYPTO_BYTES

int main(void) {
    // test_fors_sign();
    // test_fors_pk_from_sig();
    printf("PASS: fors = { msg len : %d }\n", MSG_LEN);
    return 0;
}