#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "api.h"
#include "context.h"
#include "fors.c"
#include "fors.h"
#include "hash.h"
#include "macros.h"
#include "notrandombytes.c"
#include "params.h"
#include "print.c"
#include "thash.h"
#include "wotsx1.h"

#ifndef PARAMS
#define PARAMS sphincs - shake - 128f
#endif

#ifndef THASH
#define THASH simple
#endif

#ifndef TESTS
#define TESTS 1000
#endif

extern void fors_gen_sk_jazz(uint8_t *sk, const uint8_t *pub_seed, const uint8_t *sk_seed, uint32_t fors_leaf_addr[8]);
extern void fors_sk_to_leaf_jazz(uint8_t *leaf, const uint8_t *sk, const uint8_t *pub_seed, uint32_t fors_leaf_addr[8]);
extern void fors_gen_leafx1_jazz(uint8_t *leaf, const uint8_t *pub_seed, const uint8_t *sk_seed, uint32_t addr_idx,
                                 uint32_t fors_leaf_addr[8]);

#define message_to_indices_t_jazz NAMESPACE1(message_to_indices_t_jazz, MSG_LEN)
extern void message_to_indices_t_jazz(uint32_t *indices, const uint8_t *m);

extern void fors_sign_jazz(uint8_t *sig, uint8_t *pk, const uint8_t *m, const uint8_t *pub_seed, const uint8_t *sk_seed,
                           const uint32_t fors_addr[8]);

extern void fors_pk_from_sig_jazz(uint8_t *pk, const uint8_t *sig, const uint8_t *m, const uint8_t *pub_seed,
                                  const uint32_t fors_addr[8]);

void test_fors_gen_sk(void);
void test_fors_sk_to_leaf(void);
void test_fors_gen_leafx1(void);
void test_fors_sign(void);
void test_pk_from_sig(void);
void test_treehash_fors(void);
void test_api(void);

/////////////////////////////// TESTS /////////////////////////////////////////

void test_fors_gen_sk(void) {
    bool debug = true;

    uint8_t sk_jazz[SPX_N], sk_ref[SPX_N];
    uint32_t fors_addr[8];
    spx_ctx ctx;

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("[%s]: fors_gen_sk Test %d/%d\n", xstr(PARAMS), i, TESTS);
        }

        memset(sk_jazz, 0, SPX_N);
        memset(sk_ref, 0, SPX_N);

        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);
        randombytes((uint8_t *)fors_addr, 8 * sizeof(uint32_t));

        fors_gen_sk_jazz(sk_jazz, ctx.pub_seed, ctx.sk_seed, fors_addr);
        fors_gen_sk(sk_ref, &ctx, fors_addr);

        assert(memcmp(sk_ref, sk_jazz, SPX_N) == 0);
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

void test_fors_gen_leafx1(void) {
    bool debug = true;

    uint8_t leaf_ref[SPX_N], leaf_jazz[SPX_N];
    spx_ctx ctx;
    uint32_t addr_idx;
    struct fors_gen_leaf_info info;

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("[%s]: fors_gen_leafx1 Test %d/%d\n", xstr(PARAMS), i, TESTS);
        }

        memset(leaf_ref, 0, SPX_N);
        memset(leaf_jazz, 0, SPX_N);

        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);
        randombytes((uint8_t *)&addr_idx, sizeof(uint32_t));
        randombytes((uint8_t *)info.leaf_addrx, 8 * sizeof(uint32_t));

        fors_gen_leafx1(leaf_ref, &ctx, addr_idx, (void *)&info);
        fors_gen_leafx1_jazz(leaf_jazz, ctx.pub_seed, ctx.sk_seed, addr_idx, (uint32_t *)&info);

        if (debug && false) {
            printf("info: %p\n", (void *)&info);
            printf("info.leaf_addrx: %p\n", (void *)info.leaf_addrx);
            printf("%s\n", (void *)&info == (void *)info.leaf_addrx ? "Same Address" : "Not the same address");
        }

        assert(memcmp(leaf_ref, leaf_jazz, SPX_N) == 0);
    }
}

void test_fors_sign(void) {
    bool debug = true;

    uint8_t sig_ref[SPX_BYTES - SPX_N];
    uint8_t sig_jazz[SPX_BYTES - SPX_N];
    uint8_t pk_ref[SPX_N];
    uint8_t pk_jazz[SPX_N];
    spx_ctx ctx;
    uint32_t addr[8];
    uint8_t msg[SPX_FORS_MSG_BYTES];

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("[%s]: fors_sign Test %d/%d\n", xstr(PARAMS), i, TESTS);
        }

        memset(sig_ref, 0, SPX_BYTES - SPX_N);
        memset(sig_jazz, 0, SPX_BYTES - SPX_N);

        memset(pk_ref, 0, SPX_N);
        memset(pk_jazz, 0, SPX_N);

        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);
        randombytes(msg, SPX_FORS_MSG_BYTES);
        randombytes((uint8_t *)addr, 8 * sizeof(uint32_t));

        assert(memcmp(sig_ref, sig_jazz, SPX_BYTES - SPX_N) == 0);
        assert(memcmp(pk_ref, pk_jazz, SPX_FORS_PK_BYTES) == 0);

        fors_sign(sig_ref, pk_ref, msg, &ctx, addr);
        fors_sign_jazz(sig_jazz, pk_jazz, msg, ctx.pub_seed, ctx.sk_seed, addr);

        assert(memcmp(sig_ref, sig_jazz, SPX_BYTES - SPX_N) == 0);
        assert(memcmp(pk_ref, pk_jazz, SPX_N) == 0);
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
            assert(crypto_sign_verify(signature, signature_length, message, message_length, public_key) == 0);
        }
    }

#undef MESSAGE_LENGTH
}

int main(void) {
    test_fors_gen_sk();
    test_fors_sk_to_leaf();
    test_fors_gen_leafx1();
    test_pk_from_sig();
    test_fors_sign();
    test_api();  // We test treehash here
    printf("PASS: fors = { params : %s ; thash : %s }\n", xstr(PARAMS), xstr(THASH));
    return 0;
}
