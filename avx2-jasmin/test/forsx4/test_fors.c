#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "api.h"
#include "context.h"
#include "fors.h"
#include "hash.h"
#include "hashx4.h"
#include "print.h"
#include "utils.h"
#include "utilsx4.h"

#ifndef TESTS
#define TESTS 10000
#endif

extern void fors_gen_sk_jazz(uint8_t *, const uint8_t *, const uint8_t *, const uint32_t *);
extern void fors_gen_sk_x4_jazz(const void *);
extern void fors_sk_to_leafx4_jazz(const void *);
extern void fors_gen_leafx4_jazz(uint8_t *leaf, const uint8_t *pub_seed, const uint8_t *sk_seed,
                                 const uint32_t *addr_idx, uint32_t *info);

extern void treehashx4_fors_jazz(const void *);

extern void fors_pk_from_sig_jazz(uint8_t *pk, const uint8_t *sig, const uint8_t *m, const uint8_t *pub_seed,
                                  const uint32_t fors_addr[8]);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct fors_gen_leaf_info {
    uint32_t leaf_addrx[4 * 8];
};

void treehashx4_jazz_wrapper(unsigned char *root, unsigned char *auth_path, const spx_ctx *ctx, uint32_t leaf_idx,
                             uint32_t idx_offset, uint32_t tree_addrx4[4 * 8], void *info) {
    void *args[8];

    args[0] = (void *)root;
    args[1] = (void *)auth_path;
    args[2] = (void *)ctx->pub_seed;
    args[3] = (void *)ctx->sk_seed;
    args[4] = (void *)&leaf_idx;
    args[5] = (void *)&idx_offset;
    args[6] = (void *)tree_addrx4;
    args[7] = (void *)info;

    treehashx4_fors_jazz(args);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void fors_gen_sk_x4_wrapper(uint8_t *sk0, uint8_t *sk1, uint8_t *sk2, uint8_t *sk3, const spx_ctx *ctx,
                            const uint32_t *addrx4) {
    void *args[7];

    args[0] = (void *)sk0;
    args[1] = (void *)sk1;
    args[2] = (void *)sk2;
    args[3] = (void *)sk3;
    args[4] = (void *)ctx->pub_seed;
    args[5] = (void *)ctx->sk_seed;
    args[6] = (void *)addrx4;

    fors_gen_sk_x4_jazz(args);
}

void fors_sk_to_leafx4_jazz_wrapper(uint8_t *leaf0, uint8_t *leaf1, uint8_t *leaf2, uint8_t *leaf3, const uint8_t *sk0,
                                    const uint8_t *sk1, const uint8_t *sk2, const uint8_t *sk3, const spx_ctx *ctx,
                                    uint32_t fors_leaf_addrx4[4 * 8]) {
    void *args[10];

    args[0] = (void *)leaf0;
    args[1] = (void *)leaf1;
    args[2] = (void *)leaf2;
    args[3] = (void *)leaf3;
    args[4] = (void *)sk0;
    args[5] = (void *)sk1;
    args[6] = (void *)sk2;
    args[7] = (void *)sk3;
    args[8] = (void *)ctx->pub_seed;
    args[9] = (void *)fors_leaf_addrx4;

    fors_sk_to_leafx4_jazz(args);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void test_fors_gen_sk() {
    uint8_t sk_ref[SPX_N] = {0};
    uint8_t sk_jazz[SPX_N] = {0};

    spx_ctx ctx;
    uint32_t addr[8];

    for (int i = 0; i < TESTS; i++) {
        memset(sk_jazz, 0, SPX_N);
        memset(sk_ref, 0, SPX_N);

        randombytes((uint8_t *)&ctx, 2 * SPX_N);
        randombytes((uint8_t *)addr, 8 * sizeof(uint32_t));

        fors_gen_sk_jazz(sk_jazz, ctx.pub_seed, ctx.sk_seed, addr);
        fors_gen_sk(sk_ref, &ctx, addr);

        assert(memcmp(sk_ref, sk_jazz, SPX_N) == 0);
    }
}

void test_fors_gen_sk_x4() {
    uint8_t sk0_ref[SPX_N] = {0};
    uint8_t sk1_ref[SPX_N] = {0};
    uint8_t sk2_ref[SPX_N] = {0};
    uint8_t sk3_ref[SPX_N] = {0};

    uint8_t sk0_jazz[SPX_N] = {0};
    uint8_t sk1_jazz[SPX_N] = {0};
    uint8_t sk2_jazz[SPX_N] = {0};
    uint8_t sk3_jazz[SPX_N] = {0};

    spx_ctx ctx;
    uint32_t addrx4[4 * 8];

    for (int i = 0; i < TESTS; i++) {
        memset(sk0_jazz, 0, SPX_N);
        memset(sk1_jazz, 0, SPX_N);
        memset(sk2_jazz, 0, SPX_N);
        memset(sk3_jazz, 0, SPX_N);

        memset(sk0_ref, 0, SPX_N);
        memset(sk1_ref, 0, SPX_N);
        memset(sk2_ref, 0, SPX_N);
        memset(sk3_ref, 0, SPX_N);

        randombytes((uint8_t *)&ctx, 2 * SPX_N);
        randombytes((uint8_t *)addrx4, 4 * 8 * sizeof(uint32_t));

        fors_gen_sk_x4_wrapper(sk0_jazz, sk1_jazz, sk2_jazz, sk3_jazz, &ctx, addrx4);
        fors_gen_skx4(sk0_ref, sk1_ref, sk2_ref, sk3_ref, &ctx, addrx4);

        assert(memcmp(sk0_ref, sk0_jazz, SPX_N) == 0);
        assert(memcmp(sk1_ref, sk1_jazz, SPX_N) == 0);
        assert(memcmp(sk2_ref, sk2_jazz, SPX_N) == 0);
        assert(memcmp(sk3_ref, sk3_jazz, SPX_N) == 0);
    }
}

void test_fors_sk_to_leaf(void) {
    bool debug = true;

    uint8_t leaf_ref[SPX_N], leaf_jazz[SPX_N];
    uint8_t sk[SPX_N];
    spx_ctx ctx;
    uint32_t addr[8];

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("[%s]: fors_sk_to_leaf Test %d/%d\n", xstr(PARAMS), i, TESTS);
        }

        memset(leaf_jazz, 0, SPX_N);
        memset(leaf_ref, 0, SPX_N);

        randombytes(sk, SPX_N);
        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);
        randombytes((uint8_t *)addr, 8 * sizeof(uint32_t));

        fors_sk_to_leaf_jazz(leaf_jazz, sk, ctx.pub_seed, addr);
        fors_sk_to_leaf(leaf_ref, sk, &ctx, addr);

        assert(memcmp(leaf_ref, leaf_jazz, SPX_N) == 0);
    }
}

void test_fors_sk_to_leafx4() {
    bool debug = true;

    uint8_t leaf0_ref[SPX_N], leaf1_ref[SPX_N], leaf2_ref[SPX_N], leaf3_ref[SPX_N];
    uint8_t leaf0_jazz[SPX_N], leaf1_jazz[SPX_N], leaf2_jazz[SPX_N], leaf3_jazz[SPX_N];
    uint8_t sk0[SPX_N], sk1[SPX_N], sk2[SPX_N], sk3[SPX_N];
    spx_ctx ctx;
    uint32_t addrx4[4 * 8];

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("[%s]: fors_sk_to_leafx4 Test %d/%d\n", xstr(PARAMS), i, TESTS);
        }

        memset(leaf0_jazz, 0, SPX_N);
        memset(leaf1_jazz, 0, SPX_N);
        memset(leaf2_jazz, 0, SPX_N);
        memset(leaf3_jazz, 0, SPX_N);

        memset(leaf0_ref, 0, SPX_N);
        memset(leaf1_ref, 0, SPX_N);
        memset(leaf2_ref, 0, SPX_N);
        memset(leaf3_ref, 0, SPX_N);

        randombytes(sk0, SPX_N);
        randombytes(sk1, SPX_N);
        randombytes(sk2, SPX_N);
        randombytes(sk3, SPX_N);

        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);
        randombytes((uint8_t *)addrx4, 4 * 8 * sizeof(uint32_t));

        fors_sk_to_leafx4_jazz_wrapper(leaf0_jazz, leaf1_jazz, leaf2_jazz, leaf3_jazz, sk0, sk1, sk2, sk3, ctx.pub_seed,
                                       addrx4);
        fors_sk_to_leafx4(leaf0_ref, leaf1_ref, leaf2_ref, leaf3_ref, sk0, sk1, sk2, sk3, &ctx, addrx4);

        assert(memcmp(leaf0_ref, leaf0_jazz, SPX_N) == 0);
        assert(memcmp(leaf1_ref, leaf1_jazz, SPX_N) == 0);
        assert(memcmp(leaf2_ref, leaf2_jazz, SPX_N) == 0);
        assert(memcmp(leaf3_ref, leaf3_jazz, SPX_N) == 0);
    }
}

void test_fors_gen_leafx4(void) {
    uint8_t leaf_buf_ref[4 * SPX_N];
    uint8_t leaf_buf_jazz[4 * SPX_N];

    uint32_t addr_idx;

    spx_ctx ctx;

    struct fors_gen_leaf_info info_ref;
    uint32_t leaf_addrx_jazz[8 * 4];

    for (int i = 0; i < TESTS; i++) {
        memset(leaf_buf_ref, 0, 4 * SPX_N);
        memset(leaf_buf_jazz, 0, 4 * SPX_N);

        randombytes((uint8_t *)&addr_idx, sizeof(uint32_t));
        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);

        randombytes((uint8_t *)info_ref.leaf_addrx, 4 * 8 * sizeof(uint32_t));
        memcpy(leaf_addrx_jazz, info_ref.leaf_addrx, 4 * 8 * sizeof(uint32_t));

        assert(memcmp(info_ref.leaf_addrx, leaf_addrx_jazz, 4 * 8 * sizeof(uint32_t)) == 0);
        assert(memcmp(leaf_buf_ref, leaf_buf_jazz, 4 * SPX_N) == 0);

        fors_gen_leafx4(leaf_buf_ref, &ctx, addr_idx, (void *)&info_ref);
        fors_gen_leafx4_jazz(leaf_buf_jazz, ctx.pub_seed, ctx.sk_seed, &addr_idx, leaf_addrx_jazz);

        if (memcmp(leaf_buf_ref, leaf_buf_jazz, 4 * SPX_N) != 0) {
            print_str_u8("Leaf Ref", leaf_buf_ref, 4 * SPX_N);
            print_str_u8("Leaf Jasmin", leaf_buf_jazz, 4 * SPX_N);
        }

        if (memcmp(info_ref.leaf_addrx, leaf_addrx_jazz, 4 * 8 * sizeof(uint32_t)) != 0) {
            print_str_u8("info ref", (uint8_t *)info_ref.leaf_addrx, 4 * 8 * sizeof(uint32_t));
            print_str_u8("jasmin ref", (uint8_t *)leaf_addrx_jazz, 4 * 8 * sizeof(uint32_t));
        }

        assert(memcmp(info_ref.leaf_addrx, leaf_addrx_jazz, 4 * 8 * sizeof(uint32_t)) == 0);
        assert(memcmp(leaf_buf_ref, leaf_buf_jazz, 4 * SPX_N) == 0);
    }
}

void test_pk_from_sig(void) {
    bool debug = true;

    uint8_t pk_ref[SPX_N];
    uint8_t pk_jazz[SPX_N];
    uint8_t sig[SPX_BYTES - SPX_N];
    spx_ctx ctx;
    uint32_t addr[8];
    uint8_t msg_hash[SPX_FORS_MSG_BYTES];

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("[%s]: fors_pk_from_sig Test %d/%d\n", xstr(PARAMS), i, TESTS);
        }

        memset(pk_ref, 0, SPX_N);
        memset(pk_jazz, 0, SPX_N);

        randombytes(sig, SPX_BYTES - SPX_N);
        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);
        randombytes(msg_hash, SPX_FORS_MSG_BYTES);
        randombytes((uint8_t *)addr, 8 * sizeof(uint32_t));

        fors_pk_from_sig(pk_ref, sig, msg_hash, &ctx, addr);
        fors_pk_from_sig_jazz(pk_jazz, sig, msg_hash, ctx.pub_seed, addr);

        assert(memcmp(pk_ref, pk_jazz, SPX_N) == 0);
    }
}

void test_treehash_fors(void) {
    bool debug = true;

    uint8_t root_ref[SPX_N], root_jazz[SPX_N];
    uint32_t treeaddrx4_ref[4 * 8], treeaddrx4_jazz[4 * 8];
    uint32_t info_ref[4 * 8], info_jazz[4 * 8];

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            // treehashx4_jazz_wrapper
        }

        assert(memcmp(root_jazz, root_ref, SPX_N) == 0);
        assert(memcmp(&treeaddrx4_jazz, &treeaddrx4_ref, 4 * 8 * sizeof(uint32_t)) == 0);
        assert(memcmp(info_jazz, info_ref, 4 * 8 * sizeof(uint32_t)) == 0);
    }
}

void test_fors_sign(void) {
    bool debug = true;

    for (int i = 0; i < TESTS; i++) {
    }
}

void test_api(void) {
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
            assert(signature_length == CRYPTO_BYTES);
            assert(crypto_sign_verify(signature, signature_length, message, message_length, public_key) == 0);
        }
    }

#undef MESSAGE_LENGTH
}

int main(void) {
    test_fors_gen_sk();  // From ref-jasmin
    test_fors_gen_sk_x4();
    test_fors_sk_to_leaf();  // From ref-jasmin
    test_fors_sk_to_leafx4();
    test_fors_gen_leafx4();
    test_fors_sign();
    test_pk_from_sig();  // From ref-jasmin
    test_api();          // We test treehash here
    printf("PASS: fors = { params : %s ; thash : %s }\n", xstr(PARAMS), xstr(THASH));
}
