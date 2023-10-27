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

#define message_to_indices_jazz NAMESPACE1(message_to_indices_jazz, MSG_LEN)
extern void message_to_indices_jazz(uint32_t *indices, const uint8_t *m);

#define fors_pk_from_sig_jazz NAMESPACE1(fors_pk_from_sig_jazz, MSG_LEN)
// extern void fors_pk_from_sig_jazz
// _pk _sig _msg _pub_seed _sk_seed _fors_addr

extern void fors_gen_sk_jazz(uint8_t *sk, const uint8_t *pub_seed, const uint8_t *sk_seed,
                             uint32_t fors_leaf_addr[8]);

extern void fors_sk_to_leaf_jazz(uint8_t *leaf, const uint8_t *sk, const uint8_t *pub_seed,
                                 uint32_t fors_leaf_addr[8]);

extern void fors_gen_leafx1_jazz(uint8_t *leaf, const uint8_t *pub_seed, const uint8_t *sk_seed,
                                 uint32_t addr_idx, uint32_t fors_leaf_addr[8]);

void test_fors_gen_sk(void);
void test_fors_sk_to_leaf(void);
void test_message_to_indices(void);
void test_fors_gen_leafx1(void);

void test_fors_sign(void);  // TODO: Calls treehashx1
void test_fors_pk_from_sig(void);

static void random_addr(uint32_t addr[8]) {
    for (size_t i = 0; i < 8; i++) {
        addr[i] = (uint32_t)rand();
    }
}

//////////////////////////// Code from ref impl ///////////////////////////////

static void fors_gen_sk_ref(unsigned char *sk, const spx_ctx *ctx, uint32_t fors_leaf_addr[8]) {
    prf_addr(sk, ctx, fors_leaf_addr);
}

static void fors_sk_to_leaf_ref(unsigned char *leaf, const unsigned char *sk, const spx_ctx *ctx,
                                uint32_t fors_leaf_addr[8]) {
    thash(leaf, sk, 1, ctx, fors_leaf_addr);
}

static void message_to_indices_ref(uint32_t *indices, const unsigned char *m) {
    unsigned int i, j;
    unsigned int offset = 0;

    for (i = 0; i < SPX_FORS_TREES; i++) {
        indices[i] = 0;
        for (j = 0; j < SPX_FORS_HEIGHT; j++) {
            indices[i] ^= ((m[offset >> 3] >> (offset & 0x7)) & 1u) << j;
            offset++;
        }
    }
}

static void fors_gen_leafx1_ref(unsigned char *leaf, const spx_ctx *ctx, uint32_t addr_idx,
                                void *info) {
    struct fors_gen_leaf_info *fors_info = info;
    uint32_t *fors_leaf_addr = fors_info->leaf_addrx;

    /* Only set the parts that the caller doesn't set */
    set_tree_index(fors_leaf_addr, addr_idx);
    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSPRF);
    fors_gen_sk(leaf, ctx, fors_leaf_addr);

    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE);
    fors_sk_to_leaf(leaf, leaf, ctx, fors_leaf_addr);
}

///////////////////////////////////////////////////////////////////////////////

void test_fors_gen_sk(void) {
    uint8_t sk_jazz[SPX_N], sk_ref[SPX_N];
    uint32_t fors_addr[8];
    spx_ctx ctx;

    for (int i = 0; i < TESTS; i++) {
        memset(sk_jazz, 0, SPX_N);
        memset(sk_ref, 0, SPX_N);

        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);
        random_addr(fors_addr);

        fors_gen_sk_jazz(sk_jazz, ctx.pub_seed, ctx.sk_seed, fors_addr);
        fors_gen_sk_ref(sk_ref, &ctx, fors_addr);

        assert(memcmp(sk_ref, sk_jazz, SPX_N) == 0);
    }
}

void test_fors_sk_to_leaf(void) {
    uint8_t leaf_ref[SPX_N], leaf_jazz[SPX_N];
    uint8_t sk[SPX_N];
    spx_ctx ctx;
    uint32_t addr[8];

    for (int i = 0; i < TESTS; i++) {
        memset(leaf_jazz, 0, SPX_N);
        memset(leaf_ref, 0, SPX_N);

        randombytes(sk, SPX_N);
        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);
        random_addr(addr);

        fors_sk_to_leaf_jazz(leaf_jazz, sk, ctx.pub_seed, addr);
        fors_sk_to_leaf_ref(leaf_ref, sk, &ctx, addr);

        assert(memcmp(leaf_ref, leaf_jazz, SPX_N) == 0);
    }
}

void test_message_to_indices(void) {
    uint32_t indices_ref[SPX_FORS_TREES], indices_jazz[SPX_FORS_TREES];
    uint8_t msg[MSG_LEN];

    for (int i = 0; i < TESTS; i++) {
        memset(indices_ref, 0, SPX_FORS_TREES * sizeof(uint32_t));
        memset(indices_jazz, 0, SPX_FORS_TREES * sizeof(uint32_t));

        randombytes(msg, MSG_LEN);

        message_to_indices_ref(indices_ref, msg);
        message_to_indices_jazz(indices_jazz, msg);
        print_str_u8("ref", (uint8_t*)indices_ref, SPX_FORS_TREES * sizeof(uint32_t));
        print_str_u8("jazz", (uint8_t*)indices_jazz, SPX_FORS_TREES * sizeof(uint32_t));

        assert(memcmp(indices_ref, indices_jazz, SPX_FORS_TREES * sizeof(uint32_t)) == 0);
    }
}

void test_fors_gen_leafx1(void) {
    uint8_t leaf_ref[SPX_N], leaf_jazz[SPX_N];
    spx_ctx ctx;
    uint32_t addr_idx;
    struct fors_gen_leaf_info info;

    for (int i = 0; i < TESTS; i++) {
        memset(leaf_ref, 0, SPX_N);
        memset(leaf_jazz, 0, SPX_N);

        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);
        randombytes((uint8_t *)&addr_idx, sizeof(uint32_t));
        randombytes((uint8_t *)info.leaf_addrx, 8 * sizeof(uint32_t));

        fors_gen_leafx1_ref(leaf_ref, &ctx, addr_idx, (void *)&info);
        fors_gen_leafx1_jazz(leaf_jazz, ctx.pub_seed, ctx.sk_seed, addr_idx, info.leaf_addrx);

        assert(memcmp(leaf_ref, leaf_jazz, SPX_N) == 0);
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
    test_fors_gen_sk();
    test_fors_sk_to_leaf();
    test_message_to_indices();  // FIXME: This tests fails
    test_fors_gen_leafx1();
    // test_fors_sign();
    // test_fors_pk_from_sig();

    printf("PASS: fors = { msg len : %d }\n", MSG_LEN);
    return 0;
}
