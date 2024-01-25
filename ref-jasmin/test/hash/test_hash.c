#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "context.h"
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

#ifndef TESTS
#define TESTS 1000
#endif

typedef struct {
    uint8_t R[SPX_N];
    uint8_t pk[SPX_PK_BYTES];
} args;

extern void prf_addr_jazz(uint8_t *out, const unsigned char *pub_seed, const unsigned char *sk_seed,
                          const uint32_t add[8]);

extern void prf_addr_out_u64_jazz(uint8_t *out, const unsigned char *pub_seed,
                                  const unsigned char *sk_seed, const uint32_t add[8]);

extern void gen_message_random_jazz(uint8_t *R, const uint8_t *sk_prf, const uint8_t *optrand,
                                    const uint8_t *msg, size_t msg_len);

extern void hash_message_jazz(uint8_t *digest, uint64_t *tree, uint32_t *leaf_idx,
                              const args *_args, const uint8_t *msg, size_t msg_len);

void test_prf_addr(void);
void test_prf_addr_out_u64(void);
void test_gen_message_random(void);
void test_hash_message(void);

static void random_addr(uint32_t addr[8]) {
    for (size_t i = 0; i < 8; i++) {
        addr[i] = (uint32_t)rand();
    }
}

void test_prf_addr(void) {
    spx_ctx ctx;
    uint8_t out0[SPX_N], out1[SPX_N];
    uint32_t addr[8];

    for (int t = 0; t < TESTS; t++) {
        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);
        randombytes(out0, SPX_N);
        memcpy(out1, out0, SPX_N);
        random_addr(addr);

        prf_addr_jazz(out0, ctx.pub_seed, ctx.sk_seed, addr);
        prf_addr(out1, &ctx, addr);

        assert(memcmp(out0, out1, SPX_N) == 0);
    }
}

void test_prf_addr_out_u64(void) {
    spx_ctx ctx;
    uint8_t out0[SPX_N], out1[SPX_N];
    uint32_t addr[8];

    for (int t = 0; t < TESTS; t++) {
        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);
        randombytes(out0, SPX_N);
        memcpy(out1, out0, SPX_N);
        random_addr(addr);

        prf_addr_out_u64_jazz(out0, ctx.pub_seed, ctx.sk_seed, addr);
        prf_addr(out1, &ctx, addr);

        assert(memcmp(out0, out1, SPX_N) == 0);
    }
}

void test_gen_message_random(void) {
#define MAX_MSG_LEN 1024
    spx_ctx ctx;
    uint8_t optrand[SPX_N], sk_prf[SPX_N];
    uint8_t R_ref[SPX_N], R_jazz[SPX_N];
    uint8_t msg[MAX_MSG_LEN] = {0};

    for (int i = 0; i < TESTS; i++) {
        for (size_t msg_len = 1; msg_len < MAX_MSG_LEN; msg_len++) {
            randombytes(msg, msg_len);

            randombytes(ctx.sk_seed, SPX_N);
            randombytes(ctx.pub_seed, SPX_N);
            randombytes(optrand, SPX_N);
            randombytes(sk_prf, SPX_N);

            memset(R_ref, 0, SPX_N);
            memset(R_jazz, 0, SPX_N);

            gen_message_random(R_ref, sk_prf, optrand, msg, msg_len, &ctx);
            gen_message_random_jazz(R_jazz, sk_prf, optrand, msg, msg_len);

            assert(memcmp(R_ref, R_jazz, SPX_N) == 0);
        }
    }
#undef MAX_MSG_LEN
}

void test_hash_message(void) {
#define SPX_TREE_BITS (SPX_TREE_HEIGHT * (SPX_D - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

#define MAX_MSG_LEN 1024

    uint8_t digest_ref[SPX_FORS_MSG_BYTES], digest_jazz[SPX_FORS_MSG_BYTES];
    uint64_t tree_ref = 0;
    uint64_t tree_jazz = 0;
    uint32_t leaf_idx_ref = 0;
    uint32_t leaf_idx_jazz = 0;

    spx_ctx ctx;
    args _args;
    uint8_t R[SPX_N];
    uint8_t pk[SPX_PK_BYTES];

    uint8_t msg[MAX_MSG_LEN] = {0};

    for (int i = 0; i < TESTS; i++) {
        for (size_t msg_len = 1; msg_len < MAX_MSG_LEN; msg_len++) {
            memset(digest_ref, 0, SPX_FORS_MSG_BYTES);
            memset(digest_jazz, 0, SPX_FORS_MSG_BYTES);

            randombytes(R, SPX_N);
            randombytes(pk, SPX_PK_BYTES);
            randombytes(msg, msg_len);
            randombytes(ctx.sk_seed, SPX_N);
            randombytes(ctx.pub_seed, SPX_N);

            memcpy(_args.R, R, SPX_N);
            memcpy(_args.pk, pk, SPX_PK_BYTES);

            hash_message(digest_ref, &tree_ref, &leaf_idx_ref, R, pk, msg, msg_len, &ctx);
            hash_message_jazz(digest_jazz, &tree_jazz, &leaf_idx_jazz, &_args, msg, msg_len);

            assert(memcmp(digest_ref, digest_jazz, SPX_FORS_MSG_BYTES) == 0);
            // assert(tree_ref == tree_jazz);
            assert(memcmp(&tree_ref, &tree_jazz, sizeof(uint64_t)) == 0);

            // assert(leaf_idx_ref == leaf_idx_ref);
            assert(memcmp(&leaf_idx_ref, &leaf_idx_ref, sizeof(uint32_t)) == 0);
        }
    }

#undef SPX_TREE_BITS
#undef SPX_TREE_BYTES
#undef SPX_LEAF_BITS
#undef SPX_LEAF_BYTES

#undef MAX_MSG_LEN
}

int main(void) {
    test_prf_addr();
    test_prf_addr_out_u64();
    test_gen_message_random();
    test_hash_message();
    printf("PASS: hash = { params : %s ; hash : %s }\n", xstr(PARAMS), xstr(HASH));
    return 0;
}
