#include <assert.h>
#include <inttypes.h>
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
#define TESTS 100
#endif

extern void merkle_sign_jazz(uint8_t *sig, uint8_t *root, const spx_ctx *ctx, uint32_t wots_addr[8],
                             uint32_t tree_addr[8], uint32_t idx_leaf);
extern void merkle_gen_root_jazz(uint8_t *root, const uint8_t *pub_seed, const uint8_t *sk_seed);

static void random_addr(uint32_t *addr) { randombytes((uint8_t *)addr, 8 * sizeof(uint32_t)); }

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

void test_merkle_sign(void) {
    uint8_t sig_ref[SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES],
        sig_jazz[SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES];
    uint8_t root_ref[SPX_N], root_jazz[SPX_N];
    spx_ctx ctx;
    uint32_t wots_addr_ref[8], wots_addr_jazz[8];
    uint32_t tree_addr_ref[8], tree_addr_jazz[8];
    uint32_t idx_leaf;

    for (int i = 0; i < TESTS; i++) {
        memset(sig_ref, 0, SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES);
        memset(sig_jazz, 0, SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES);

        randombytes(root_ref, SPX_N);
        memcpy(root_jazz, root_ref, SPX_N);

        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);

        random_addr(wots_addr_ref);
        memcpy(wots_addr_jazz, wots_addr_ref, 8 * sizeof(uint32_t));

        random_addr(tree_addr_ref);
        memcpy(tree_addr_jazz, tree_addr_ref, 8 * sizeof(uint32_t));

        randombytes((uint8_t *)&idx_leaf, sizeof(uint32_t));

        assert(memcmp(sig_ref, sig_jazz, SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES) == 0);
        assert(memcmp(root_ref, root_jazz, SPX_N) == 0);
        assert(memcmp(wots_addr_ref, wots_addr_jazz, 8 * sizeof(uint32_t)) == 0);  // FAILS (?)
        assert(memcmp(tree_addr_ref, tree_addr_jazz, 8 * sizeof(uint32_t)) == 0);

        merkle_sign(sig_ref, root_ref, &ctx, wots_addr_ref, tree_addr_ref, idx_leaf);
        merkle_sign_jazz(sig_jazz, root_jazz, &ctx, wots_addr_jazz, tree_addr_jazz, idx_leaf);

        assert(memcmp(sig_ref, sig_jazz, SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES) == 0);
        assert(memcmp(root_ref, root_jazz, SPX_N) == 0);
        assert(memcmp(wots_addr_ref, wots_addr_jazz, 8 * sizeof(uint32_t)) == 0);  // FAILS (?)
        assert(memcmp(tree_addr_ref, tree_addr_jazz, 8 * sizeof(uint32_t)) == 0);
    }
}

void test_merkle_gen_root_1(void) {
    // this also tests merkle sign
#define MESSAGE_LENGTH 32

    uint8_t secret_key[CRYPTO_SECRETKEYBYTES];
    uint8_t public_key[CRYPTO_PUBLICKEYBYTES];

    uint8_t signature[CRYPTO_BYTES];
    size_t signature_length;

    uint8_t message[MESSAGE_LENGTH];
    size_t message_length = MESSAGE_LENGTH;

    for (int i = 0; i < 100; i++) {
        // note: the 'real' test is in sign.c file and it is activated when TEST_MERKLE is
        // defined
        randombytes(message, MESSAGE_LENGTH);

        crypto_sign_keypair(public_key, secret_key);
        crypto_sign_signature(signature, &signature_length, message, message_length, secret_key);
        crypto_sign_verify(signature, signature_length, message, message_length, public_key);
    }

#undef MESSAGE_LENGTH
}

void test_merkle_gen_root_2(void) {
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

        if (memcmp(root_ref, root_jazz, SPX_N) != 0) {
            print_str_u8("ref", root_ref, SPX_N);
            print_str_u8("jazz", root_jazz, SPX_N);
            puts("\n");
        }

        assert(memcmp(root_ref, root_jazz, SPX_N) == 0);
    }
}

int main(void) {
    test_treehash();
    test_merkle_sign(); // This uses random bytes
    test_merkle_gen_root_1();  // test in sign.c (also tests merkle sign)
    test_merkle_gen_root_2();  // test with randombytes
    printf("Pass merkle : { params : %s ; thash : %s }\n", xstr(PARAMS), xstr(THASH));
    return 0;
}
