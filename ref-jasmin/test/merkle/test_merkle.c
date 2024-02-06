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
#include "randombytes.h"

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

extern void merkle_sign_jazz(uint8_t *sig, uint8_t *root, const spx_ctx *ctx, uint32_t wots_addr[8],
                             uint32_t tree_addr[8], uint32_t idx_leaf);
extern void merkle_gen_root_jazz(uint8_t *root, const uint8_t *pub_seed, const uint8_t *sk_seed);

void test_merkle_sign(void) {
    uint8_t sig_ref[SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES] = {0};
    uint8_t sig_jazz[SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES] = {0};

    uint8_t root_ref[SPX_N] = {0};
    uint8_t root_jazz[SPX_N] = {0};

    spx_ctx ctx;

    uint32_t wots_addr_ref[8], wots_addr_jazz[8];
    uint32_t tree_addr_ref[8], tree_addr_jazz[8];

    uint32_t idx_leaf;

    bool debug = true;

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("[%s]: Test merkle sign %d/%d\n", xstr(PARAMS), i, TESTS);
        }

        randombytes(sig_ref, SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES);
        memcpy(sig_jazz, sig_ref, SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES);

        randombytes(root_ref, SPX_N);
        memcpy(root_jazz, root_ref, SPX_N);

        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);

        randombytes((uint8_t *)wots_addr_ref, 8 * sizeof(uint32_t));
        memcpy(wots_addr_jazz, wots_addr_ref, 8 * sizeof(uint32_t));

        randombytes((uint8_t *)tree_addr_ref, 8 * sizeof(uint32_t));
        memcpy(tree_addr_jazz, tree_addr_ref, 8 * sizeof(uint32_t));

        randombytes((uint8_t *)&idx_leaf, sizeof(uint32_t));

        assert(memcmp(sig_ref, sig_jazz, SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES) == 0);
        assert(memcmp(root_ref, root_jazz, SPX_N) == 0);
        assert(memcmp(wots_addr_ref, wots_addr_jazz, 8 * sizeof(uint32_t)) == 0);
        assert(memcmp(tree_addr_ref, tree_addr_jazz, 8 * sizeof(uint32_t)) == 0);

        merkle_sign_jazz(sig_jazz, root_jazz, &ctx, wots_addr_jazz, tree_addr_jazz, idx_leaf);
        merkle_sign(sig_ref, root_ref, &ctx, wots_addr_ref, tree_addr_ref, idx_leaf);

        assert(memcmp(sig_ref, sig_jazz, SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES) == 0); 
        assert(memcmp(root_ref, root_jazz, SPX_N) == 0);
        assert(memcmp(wots_addr_ref, wots_addr_jazz, 8 * sizeof(uint32_t)) == 0); 
        assert(memcmp(tree_addr_ref, tree_addr_jazz, 8 * sizeof(uint32_t)) == 0); 
    }
}

void test_merkle_gen_root(void) {
    bool debug = true;

    unsigned char root_ref[SPX_N];
    uint8_t root_jazz[SPX_N];
    spx_ctx ctx;

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("[%s]: Test gen root %d/%d\n", xstr(PARAMS), i, TESTS);
        }

        memset(root_ref, 0, SPX_N);
        memset(root_jazz, 0, SPX_N);

        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);

        merkle_gen_root(root_ref, &ctx);
        merkle_gen_root_jazz(root_jazz, ctx.pub_seed, ctx.sk_seed);

        if (memcmp(root_ref, root_jazz, SPX_N) != 0) {
            print_str_u8("ref", root_ref, SPX_N);
            print_str_u8("jazz", root_jazz, SPX_N);
            puts("\n");
        }

        assert(memcmp(root_ref, root_jazz, SPX_N) == 0);
    }
}

void test_merkle(void) {
    bool debug = true;

#define TESTS 100
#define MAX_MESSAGE_LENGTH 1024

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
    test_merkle_sign();
    // test_merkle_gen_root();
    test_merkle();
    printf("Pass merkle : { params : %s ; thash : %s }\n", xstr(PARAMS), xstr(THASH));
    return 0;
}
