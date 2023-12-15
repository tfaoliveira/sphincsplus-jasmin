#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "context.h"
#include "macros.h"
#include "notrandombytes.c"
#include "params.h"
#include "print.c"
#include "merkle.h"

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
#define TESTS 100
#endif

extern void merkle_gen_root_jazz(uint8_t *root, const uint8_t *pub_seed, const uint8_t *sk_seed);

void test_treehash(void) {
#define MESSAGE_LENGTH 32

    uint8_t secret_key[CRYPTO_SECRETKEYBYTES];
    uint8_t public_key[CRYPTO_PUBLICKEYBYTES];

    uint8_t signature[CRYPTO_BYTES];
    size_t signature_length;

    uint8_t message[MESSAGE_LENGTH];
    size_t message_length = MESSAGE_LENGTH;

    for (int i = 0; i < 100; i++) {
        // note: the 'real' test is in merkle.c file and it is activated when DTEST_WOTSX1 is
        // defined

        // The test is in merkle.c because that is where the wots_gen_leaf function is called
        randombytes(message, MESSAGE_LENGTH);

        crypto_sign_keypair(public_key, secret_key);
        crypto_sign_signature(signature, &signature_length, message, message_length, secret_key);
        crypto_sign_verify(signature, signature_length, message, message_length, public_key);
    }

#undef MESSAGE_LENGTH
}

void test_merkle_gen_root(void) {
    unsigned char root_ref[SPX_N];
    uint8_t root_jazz[SPX_N];

    spx_ctx ctx;

    for (int i = 0; i < TESTS; i++) {
        memset(root_ref, 0, SPX_N);
        memset(root_jazz, 0, SPX_N);

        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);

        merkle_gen_root(root_ref, &ctx);
        merkle_gen_root_jazz(root_jazz, ctx.pub_seed, ctx.sk_seed);

        assert(memcmp(root_ref, root_jazz, SPX_N) == 0);
    }
}

int main(void) {
    test_treehash();
    test_merkle_gen_root();
    puts("Pass merkle");
    return 0;
}
