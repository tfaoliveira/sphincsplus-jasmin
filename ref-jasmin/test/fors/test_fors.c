#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "context.h"
#include "fors.h"
#include "fors.c"
#include "hash.h"
#include "thash.h"
#include "macros.h"
#include "notrandombytes.c"
#include "params.h"
#include "print.c"

#include "api.h"

#ifndef PARAMS
#define PARAMS sphincs-shake-128f
#endif

#ifndef THASH
#define THASH simple
#endif

#ifndef MSG_LEN
#define MSG_LEN 64
#endif

#ifndef TESTS
#define TESTS 10
#endif

// signature size for 128f
#ifndef SIG_SIZE
#define SIG_SIZE 7856
#endif

extern void fors_gen_sk_jazz(uint8_t *sk, const uint8_t *pub_seed, const uint8_t *sk_seed,
                             uint32_t fors_leaf_addr[8]);  // ref impl
extern void fors_sk_to_leaf_jazz(uint8_t *leaf, const uint8_t *sk, const uint8_t *pub_seed,
                                 uint32_t fors_leaf_addr[8]);  // ref impl
extern void fors_gen_leafx1_jazz(uint8_t *leaf, const uint8_t *pub_seed, const uint8_t *sk_seed,
                                 uint32_t addr_idx, uint32_t fors_leaf_addr[8]);  // ref impl
extern void message_to_indices_jazz(uint32_t *indices, const uint8_t *m);

#define message_to_indices_t_jazz NAMESPACE1(message_to_indices_t_jazz, MSG_LEN)
extern void message_to_indices_t_jazz(uint32_t *indices, const uint8_t *m);

extern void fors_sign_jazz(uint8_t *sig, uint8_t *pk, const uint8_t *m, const uint8_t *pub_seed,
                           const uint8_t *sk_seed, const uint32_t fors_addr[8]);

extern void fors_pk_from_sig_jazz(uint8_t *pk, const uint8_t *sig, const uint8_t *m,
                                  const uint8_t *pub_seed, const uint8_t *sk_seed,
                                  const uint32_t fors_addr[8]);

void test_fors_gen_sk(void);
void test_fors_sk_to_leaf(void);
void test_fors_gen_leafx1(void);
void test_message_to_indices(void);
void test_message_to_indices_t(void);
void test_fors_sign(void);
void test_pk_from_sig(void);
void test_treehash_fors(void);

static void random_addr(uint32_t addr[8]) { randombytes((uint8_t *)addr, 8 * sizeof(uint32_t)); }

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
            indices[i] ^= ((m[offset >> 3] >> (~offset & 0x7)) & 0x1) << (SPX_FORS_HEIGHT - 1 - j);
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

/////////////////////////////// TESTS /////////////////////////////////////////
#if 0
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

void test_message_to_indices(void) {
    uint32_t indices_ref[SPX_FORS_TREES], indices_jazz[SPX_FORS_TREES];
    uint8_t msg[MSG_LEN];

    // We assume m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
    if (MSG_LEN < (SPX_FORS_HEIGHT * SPX_FORS_TREES) / 8) {
        puts("Skipping message_to_indices");
        printf("m must be at least SPX_FORS_HEIGHT * SPX_FORS_TREES = %d bits = %d bytes\n",
               SPX_FORS_HEIGHT * SPX_FORS_TREES, (SPX_FORS_HEIGHT * SPX_FORS_TREES) / 8);
        return;
    } else {
        puts("Testing message_to_indices");
    }

    for (int i = 0; i < TESTS; i++) {
        memset(indices_ref, 0, SPX_FORS_TREES * sizeof(uint32_t));
        memset(indices_jazz, 0, SPX_FORS_TREES * sizeof(uint32_t));
        randombytes(msg, MSG_LEN);

        message_to_indices_ref(indices_ref, msg);
        message_to_indices_jazz(indices_jazz, msg);

        assert(memcmp(indices_ref, indices_jazz, SPX_FORS_TREES * sizeof(uint32_t)) == 0);
    }
}

void test_message_to_indices_t(void) {
    uint32_t indices_ref[SPX_FORS_TREES], indices_jazz[SPX_FORS_TREES];
    uint8_t msg[MSG_LEN];

    // We assume m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
    if (MSG_LEN < (SPX_FORS_HEIGHT * SPX_FORS_TREES) / 8) {
        puts("Skipping message_to_indices");
        printf("m must be at least SPX_FORS_HEIGHT * SPX_FORS_TREES = %d bits = %d bytes\n",
               SPX_FORS_HEIGHT * SPX_FORS_TREES, (SPX_FORS_HEIGHT * SPX_FORS_TREES) / 8);
        return;
    } else {
        puts("Testing message_to_indices");
    }

    for (int i = 0; i < TESTS; i++) {
        memset(indices_ref, 0, SPX_FORS_TREES * sizeof(uint32_t));
        memset(indices_jazz, 0, SPX_FORS_TREES * sizeof(uint32_t));
        randombytes(msg, MSG_LEN);

        message_to_indices_ref(indices_ref, msg);
        message_to_indices_t_jazz(indices_jazz, msg);

        assert(memcmp(indices_ref, indices_jazz, SPX_FORS_TREES * sizeof(uint32_t)) == 0);
    }
}

void test_fors_sign(void) {
    uint8_t sig_ref[SIG_SIZE], sig_jazz[SIG_SIZE];
    uint8_t pk_ref[SPX_FORS_PK_BYTES], pk_jazz[SPX_FORS_PK_BYTES];
    spx_ctx ctx;
    uint32_t addr[8];
    uint8_t msg[SPX_FORS_MSG_BYTES];

    for (int i = 0; i < TESTS; i++) {
        memset(sig_ref, 0, SIG_SIZE);
        memset(sig_jazz, 0, SIG_SIZE);

        memset(pk_ref, 0, SPX_FORS_PK_BYTES);
        memset(pk_jazz, 0, SPX_FORS_PK_BYTES);

        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);
        randombytes(msg, SPX_FORS_MSG_BYTES);
        randombytes((uint8_t *)addr, 8 * sizeof(uint32_t));

        assert(memcmp(sig_ref, sig_jazz, SIG_SIZE) == 0);  // fails
        assert(memcmp(pk_ref, pk_jazz, SPX_FORS_PK_BYTES) == 0);

        fors_sign(sig_ref, pk_ref, msg, &ctx, addr);
        fors_sign_jazz(sig_jazz, pk_jazz, msg, ctx.pub_seed, ctx.sk_seed, addr);

        if (memcmp(sig_ref, sig_jazz, SIG_SIZE) != 0) {
            print_str_u8("sig ref", sig_ref, SIG_SIZE);
            print_str_u8("sig jazz", sig_jazz, SIG_SIZE);
        }

        if (memcmp(pk_ref, pk_jazz, SPX_FORS_PK_BYTES) != 0) {
            print_str_u8("pk ref", pk_ref, SPX_FORS_PK_BYTES);
            print_str_u8("pk jazz", pk_jazz, SPX_FORS_PK_BYTES);
        }

        assert(memcmp(sig_ref, sig_jazz, SIG_SIZE) == 0);  // fails
        assert(memcmp(pk_ref, pk_jazz, SPX_FORS_PK_BYTES) == 0);
    }
}

void test_pk_from_sig(void) {
    uint8_t pk_ref[SPX_FORS_PK_BYTES], pk_jazz[SPX_FORS_PK_BYTES];
    uint8_t sig[SPX_FORS_BYTES];
    spx_ctx ctx;
    uint32_t addr[8];
    uint8_t msg[SPX_FORS_MSG_BYTES];

    for (int i = 0; i < TESTS; i++) {
        memset(pk_ref, 0, SPX_FORS_PK_BYTES);
        memset(pk_jazz, 0, SPX_FORS_PK_BYTES);

        randombytes(sig, SPX_FORS_BYTES);
        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);
        randombytes(msg, MSG_LEN);
        randombytes((uint8_t *)addr, 8 * sizeof(uint32_t));

        fors_pk_from_sig(pk_ref, sig, msg, &ctx, addr);
        fors_pk_from_sig_jazz(pk_jazz, sig, msg, ctx.pub_seed, ctx.sk_seed, addr);

        if (memcmp(pk_ref, pk_jazz, SPX_FORS_PK_BYTES) != 0) {
            print_str_u8("pk ref", pk_ref, SPX_FORS_PK_BYTES);
            print_str_u8("pk jazz", pk_jazz, SPX_FORS_PK_BYTES);
        }

        assert(memcmp(pk_ref, pk_jazz, SPX_FORS_PK_BYTES) == 0);
    }
}

/* static */ uint32_t random_idx_offset(uint32_t max_idx_offset, uint32_t min_idx_offset) {
    uint32_t range = max_idx_offset - min_idx_offset;
    uint32_t value;

    size_t num_bytes = (size_t)(sizeof(uint32_t));
    size_t bytes_needed = sizeof(uint32_t);

    do {
        uint8_t random_bytes[bytes_needed];
        randombytes(random_bytes, bytes_needed);

        value = 0;
        for (size_t i = 0; i < num_bytes; ++i) {
            value = (value << 8) | random_bytes[i];
        }
        value %= range;

    } while (value >= range);

    value += min_idx_offset;

    assert(value >= min_idx_offset);
    assert(value <= max_idx_offset);

    return value;
}
#endif

void test_treehash_fors(void)
{
  #define MESSAGE_LENGTH 32

  uint8_t secret_key[CRYPTO_SECRETKEYBYTES];
  uint8_t public_key[CRYPTO_PUBLICKEYBYTES];

  uint8_t signature[CRYPTO_BYTES];
  size_t signature_length;

  uint8_t message[MESSAGE_LENGTH];
  size_t message_length = MESSAGE_LENGTH;

  for (int i = 0; i < 100; i++)
  {
    // note: the 'real' test is in fors.c file and it is activated when TEST_FORS_TREEHASH is defined
    randombytes(message, MESSAGE_LENGTH);

    crypto_sign_keypair(public_key, secret_key);
    crypto_sign_signature(signature, &signature_length, message, message_length, secret_key);
    assert( crypto_sign_verify(signature, signature_length, message, message_length, public_key) == 0);
  }

  #undef MESSAGE_LENGTH
}

int main(void) {

#if 0
    test_fors_gen_sk();
    test_fors_sk_to_leaf();
    test_fors_gen_leafx1();
    test_message_to_indices();    // msg is a reg u64
    test_message_to_indices_t();  // msg is a reg ptr u8[MSG_LEN]
    test_fors_sign();
    test_pk_from_sig();
#endif

    test_treehash_fors();
    printf("PASS: fors = { msg len : %d ; params : %s }\n", MSG_LEN, xstr(PARAMS));

    return 0;
}
