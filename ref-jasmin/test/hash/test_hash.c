#include <assert.h>
#include <inttypes.h>
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

#ifndef MSG_LEN
#define MSG_LEN 64
#endif

#ifndef TESTS
#define TESTS 1000
#endif

// TODO: Refactor
/*
 * Combines R and leaf_idx pk to bypass
 * register allocation: too many parameters according to the ABI (only 6 available on this
 * architecture)
 */
typedef struct {
    uint8_t *R;
    uint8_t *pk;
} r_pk;

extern void shake256(uint8_t *output, size_t outlen, const uint8_t *input,
                     size_t inlen);  // from fips202.c

extern void prf_addr_jazz(uint8_t *out, const unsigned char *pub_seed, const unsigned char *sk_seed,
                          const uint32_t add[8]);

#define gen_message_random_jazz NAMESPACE1(gen_msg_random_jazz, MSG_LEN)
extern void gen_message_random_jazz(uint8_t *R, const uint8_t *sk_prf, const uint8_t *optrand,
                                    const uint8_t *m);

#define hash_message_jazz NAMESPACE1(hash_message_jazz, MSG_LEN)
extern uint32_t hash_message_jazz(uint8_t *digest, uint64_t *tree, const uint32_t *leaf_idx,
                                  const r_pk *rpk, const uint8_t *m, const spx_ctx *ctx);

void test_prf_addr(void);
void test_gen_message_random(void);

void test_gen_message_c_jazz(void);
void test_gen_message_ref_jazz(void);
void test_gen_message_ref_c(void);

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

static void gen_message_random_c(uint8_t *R, const uint8_t *sk_prf, const uint8_t *optrand,
                                 const uint8_t *m) {
    uint8_t buf[2 * SPX_N + MSG_LEN];
    memcpy(buf, sk_prf, SPX_N);
    memcpy(buf + SPX_N, optrand, SPX_N);
    memcpy(buf + 2 * SPX_N, m, MSG_LEN);
    shake256(R, SPX_N, buf, 2 * SPX_N + MSG_LEN);
}

void test_gen_message_ref_c(void) {
    spx_ctx ctx;
    uint8_t optrand[SPX_N], sk_prf[SPX_N];
    uint8_t R0[SPX_N], R1[SPX_N];
    uint8_t message[MSG_LEN];

    for (int t = 0; t < TESTS; t++) {
        randombytes(ctx.sk_seed, SPX_N);
        randombytes(ctx.pub_seed, SPX_N);
        randombytes(optrand, SPX_N);
        randombytes(sk_prf, SPX_N);
        randombytes(message, MSG_LEN);

        memset(R0, 0, SPX_N);
        memset(R1, 0, SPX_N);

        // gen_message_random_jazz(R0, sk_prf, optrand, message);
        gen_message_random_c(R0, sk_prf, optrand, message);
        gen_message_random(R1, sk_prf, optrand, message, MSG_LEN, &ctx);
        printf("--------MSG LEN = %d ---------------\n", MSG_LEN);
        printf("Ref:\n");
        print_u8(R1, SPX_N);
        printf("\nC:\n");
        print_u8(R0, SPX_N);
        printf("-----------------------\n");
        if (memcmp(R0, R1, SPX_N) != 0) {
            printf("Falhou\n");
        }
        assert(memcmp(R0, R1, SPX_N) == 0);
    }
}

void test_gen_message_c_jazz(void) {
    spx_ctx ctx;
    uint8_t optrand[SPX_N], sk_prf[SPX_N];
    uint8_t optrand_copy[SPX_N], sk_prf_copy[SPX_N];
    uint8_t R0[SPX_N], R1[SPX_N];
    uint8_t message[MSG_LEN];
    uint8_t message_copy[MSG_LEN];

    for (int t = 0; t < TESTS; t++) {
        randombytes(ctx.sk_seed, SPX_N);
        randombytes(ctx.pub_seed, SPX_N);
        randombytes(optrand, SPX_N);
        randombytes(sk_prf, SPX_N);
        randombytes(message, MSG_LEN);

        memset(R0, 0, SPX_N);
        memset(R1, 0, SPX_N);

        memcpy(message_copy, message, MSG_LEN);
        memcpy(optrand_copy, optrand, SPX_N);
        memcpy(sk_prf_copy, sk_prf, SPX_N);

        gen_message_random_c(R0, sk_prf, optrand, message);

        assert(memcmp(message_copy, message, MSG_LEN) == 0);
        assert(memcmp(optrand_copy, optrand, SPX_N) == 0);
        assert(memcmp(sk_prf_copy, sk_prf, SPX_N) == 0);

        gen_message_random_jazz(R1, sk_prf, optrand, message);

        printf("--------MSG LEN = %d ---------------\n", MSG_LEN);
        printf("Jasmin:\n");
        print_u8(R1, SPX_N);
        printf("\nC:\n");
        print_u8(R0, SPX_N);
        printf("-----------------------\n");
        if (memcmp(R0, R1, SPX_N) != 0) {
            printf("Falhou\n");
        }
        assert(memcmp(R0, R1, SPX_N) == 0);
    }
}

void test_hash_message(void) {
#define SPX_TREE_BITS (SPX_TREE_HEIGHT * (SPX_D - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

    uint8_t digest0[SPX_DGST_BYTES], digest1[SPX_DGST_BYTES];
    uint64_t tree0, tree1;
    uint32_t leaf_idx0, leaf_idx1;

    uint8_t R[SPX_N];
    uint8_t pk[SPX_PK_BYTES];
    r_pk Rpk;

    uint8_t message[MSG_LEN];
    spx_ctx ctx;

    for (int t = 0; t < TESTS; t++) {
        randombytes1(R, SPX_N);
        randombytes(pk, SPX_PK_BYTES);
        randombytes(message, MSG_LEN);
        randombytes(ctx.sk_seed, SPX_N);
        randombytes(ctx.pub_seed, SPX_N);

        Rpk.R = R;
        Rpk.pk = pk;

        memset(digest0, 0, SPX_DGST_BYTES);
        memset(digest1, 0, SPX_DGST_BYTES);
        tree0 = 0;
        tree1 = 0;
        leaf_idx0 = 0;
        leaf_idx1 = 0;

        leaf_idx0 = hash_message_jazz(digest0, &tree0, &leaf_idx0, &Rpk, message, &ctx);

        hash_message(digest1, &tree1, &leaf_idx1, R, pk, message, MSG_LEN, &ctx);

        assert(tree0 == tree1);
        assert(tree1 == tree1);
        assert(memcmp(digest0, digest1, SPX_DGST_BYTES) == 0);
    }

#undef SPX_TREE_BITS
#undef SPX_TREE_BYTES
#undef SPX_LEAF_BITS
#undef SPX_LEAF_BYTES
#undef SPX_DGST_BYTES
}

int main(void) {
    // test_prf_addr();

    // test_gen_message_ref_c();   // Compares C vs ref
    test_gen_message_c_jazz();  // Compares c [not ref] vs jazz impl

    // test_hash_message();

    printf("PASS: hash shake = { msg len : %d }\n", MSG_LEN);

    return 0;
}
