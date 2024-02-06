#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "context.h"
#include "macros.h"
#include "merkle.h"
#include "notrandombytes.c"
#include "params.h"
#include "print.c"
#include "wrappers.h"
#include "wotsx1.h"


#ifndef HASH
#define HASH shake
#endif

#ifndef PARAM
#define PARAM 128f
#endif

#ifndef THASH
#define THASH simple
#endif

#ifndef TESTS
#define TESTS 1000
#endif

void test_treehash(void);
void test_wotsx1(void);

void test_treehash(void) {
    bool debug = true;

    uint8_t sig_ref[SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N];
    uint8_t sig_jazz[SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N];

    uint32_t steps_ref[SPX_WOTS_LEN];
    uint32_t steps_jazz[SPX_WOTS_LEN];

    uint8_t root_jazz[SPX_N];
    uint8_t root_ref[SPX_N];

    spx_ctx ctx;
    uint32_t idx_leaf;

    uint32_t tree_addr_jazz[8];
    uint32_t tree_addr_ref[8];

    struct leaf_info_x1 info_jazz = {0};
    struct leaf_info_x1 info_ref = {0};

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("[%s]: treehash wots Test %d/%d\n", xstr(PARAMS), i, TESTS);
        }

        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);
        randombytes((uint8_t *)&idx_leaf, sizeof(uint32_t));

        randombytes(root_ref, SPX_N);
        memcpy(root_jazz, root_ref, SPX_N);

        randombytes((uint8_t *)tree_addr_ref, 8 * sizeof(uint32_t));
        memcpy(tree_addr_jazz, tree_addr_ref, 8 * sizeof(uint32_t));

        randombytes(sig_ref, SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES);
        memcpy(sig_jazz, sig_ref, SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES);
        info_ref.wots_sig = sig_ref;
        info_jazz.wots_sig = sig_jazz;

        randombytes((uint8_t *)steps_ref, SPX_WOTS_LEN * sizeof(uint32_t));
        memcpy(steps_jazz, steps_ref, SPX_WOTS_LEN * sizeof(uint32_t));
        info_ref.wots_steps = steps_ref;
        info_jazz.wots_steps = steps_jazz;

        info_ref.wots_sign_leaf = idx_leaf;
        info_jazz.wots_sign_leaf = idx_leaf;

        randombytes(info_ref.leaf_addr, 8 * sizeof(uint32_t));
        memcpy(info_jazz.leaf_addr, info_ref.leaf_addr, 8 * sizeof(uint32_t));

        randombytes(info_ref.pk_addr, 8 * sizeof(uint32_t));
        memcpy(info_jazz.pk_addr, info_ref.pk_addr, 8 * sizeof(uint32_t));

        assert(memcmp(root_jazz, root_ref, SPX_N) == 0);
        assert(memcmp(tree_addr_jazz, tree_addr_ref, 8 * sizeof(uint32_t)) == 0);
        assert(memcmp(info_ref.wots_sig, info_jazz.wots_sig, SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES) == 0);
        assert(memcmp(info_ref.wots_steps, info_jazz.wots_steps, SPX_WOTS_LEN * sizeof(uint32_t)) == 0);
        assert(memcmp(info_ref.leaf_addr, info_jazz.leaf_addr, 8 * sizeof(uint32_t)) == 0);
        assert(memcmp(info_ref.pk_addr, info_jazz.pk_addr, 8 * sizeof(uint32_t)) == 0);

        treehashx1_wots(root_ref, &ctx, idx_leaf, tree_addr_ref, &info_ref);
        treehashx1_wots_jasmin(root_jazz, &ctx, idx_leaf, tree_addr_jazz, &info_jazz);

        assert(memcmp(root_jazz, root_ref, SPX_N) == 0);
        assert(memcmp(tree_addr_jazz, tree_addr_ref, 8 * sizeof(uint32_t)) == 0);
        assert(memcmp(info_ref.wots_sig, info_jazz.wots_sig, SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES) == 0);
        assert(memcmp(info_ref.wots_steps, info_jazz.wots_steps, SPX_WOTS_LEN * sizeof(uint32_t)) == 0);
        assert(memcmp(info_ref.leaf_addr, info_jazz.leaf_addr, 8 * sizeof(uint32_t)) == 0);
        assert(memcmp(info_ref.pk_addr, info_jazz.pk_addr, 8 * sizeof(uint32_t)) == 0);
    }
}

void test_wotsx1(void) {
    bool debug = true;

#define MAX_MESSAGE_LENGTH 1024
#define TESTS 100

    uint8_t secret_key[CRYPTO_SECRETKEYBYTES];
    uint8_t public_key[CRYPTO_PUBLICKEYBYTES];

    uint8_t signature[CRYPTO_BYTES];
    size_t signature_length;

    uint8_t message[MAX_MESSAGE_LENGTH];

    for (int i = 0; i < TESTS; i++) {
        for (size_t message_length = 1; message_length < MAX_MESSAGE_LENGTH; message_length++) {
            if (debug) {
                printf("[%s]: Test %d/%d [Len=%ld]\n", xstr(PARAMS), i, TESTS, message_length);
            }

            randombytes(message, message_length);
            crypto_sign_keypair(public_key, secret_key);
            crypto_sign_signature(signature, &signature_length, message, message_length, secret_key);
            assert(crypto_sign_verify(signature, signature_length, message, message_length, public_key) == 0);
        }
    }

#undef MESSAGE_LENGTH
}

int main(void) {
    test_treehash();
    test_wotsx1();
    printf("Pass treehash_wots : { params : %s ; thash : %s }\n", xstr(PARAMS), xstr(THASH));
    return 0;
}
