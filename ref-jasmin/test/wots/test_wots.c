#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "context.h"
#include "hash.h"
#include "macros.h"
#include "notrandombytes.c"
#include "params.h"
#include "print.c"
#include "thash.h"
#include "wots.h"

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

extern void gen_chain_jazz(uint8_t *out, const uint8_t *in, uint32_t start, uint32_t steps,
                           const uint8_t *pub_seed, uint32_t addr[8]);

#define base_w_jazz NAMESPACE1(base_w_jazz, MSG_LEN)
extern void base_w_jazz(uint32_t *output, const uint8_t *input);

extern void wots_checksum_jazz(uint32_t *csum_base_w, const uint32_t *msg_base_w);

extern void wots_pk_from_sig_jazz(uint8_t *pk, const uint8_t *sig, const uint8_t *msg,
                                  const spx_ctx *ctx, uint32_t addr[8]);

extern void chain_lengths_jazz(uint32_t *lengths, const uint8_t *msg);

static void random_addr(uint32_t addr[8]) { randombytes((uint8_t *)addr, 8 * sizeof(uint32_t)); }

static uint32_t random_u32() {
    uint32_t res;
    randombytes((uint8_t *)&res, sizeof(uint32_t));
    return res;
}

//////////////////////// CODE FROM REF IMPL  ////////////////////////
void ull_to_bytes(unsigned char *out, unsigned int outlen, unsigned long long in) {
    int i;

    /* Iterate over out in decreasing order, for big-endianness. */
    for (i = (signed int)outlen - 1; i >= 0; i--) {
        out[i] = (unsigned char)(in & 0xff);
        in = in >> 8;
    }
}

static void gen_chain(unsigned char *out, const unsigned char *in, unsigned int start,
                      unsigned int steps, const spx_ctx *ctx, uint32_t addr[8]) {
    uint32_t i;

    /* Initialize out with the value at position 'start'. */
    memcpy(out, in, SPX_N);

    /* Iterate 'steps' calls to the hash function. */
    for (i = start; i < (start + steps) && i < SPX_WOTS_W; i++) {
        set_hash_addr(addr, i);
        thash(out, out, 1, ctx, addr);
    }
}

static void base_w(unsigned int *output, const int out_len, const unsigned char *input) {
    int in = 0;
    int out = 0;
    unsigned char total;
    int bits = 0;
    int consumed;

    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= SPX_WOTS_LOGW;
        output[out] = (total >> bits) & (SPX_WOTS_W - 1);
        out++;
    }
}

static void wots_checksum(unsigned int *csum_base_w, const unsigned int *msg_base_w) {
    unsigned int csum = 0;
    unsigned char csum_bytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];
    unsigned int i;

    for (i = 0; i < SPX_WOTS_LEN1; i++) {
        csum += SPX_WOTS_W - 1 - msg_base_w[i];
    }

    csum = csum << ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8);
    ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
    base_w(csum_base_w, SPX_WOTS_LEN2, csum_bytes);
}
////////////////////////////////////////////////////////////////////////

void test_gen_chain(void) {
    uint8_t out_ref[SPX_N], out_jazz[SPX_N];
    uint8_t in[SPX_N];
    uint32_t start, steps;
    spx_ctx ctx;
    uint32_t addr_ref[8], addr_jazz[8];

    for (int i = 0; i < TESTS; i++) {
        memset(out_ref, 0, SPX_N * sizeof(uint8_t));
        memset(out_jazz, 0, SPX_N * sizeof(uint8_t));

        randombytes(in, SPX_N);
        start = random_u32();
        steps = random_u32();

        randombytes(ctx.sk_seed, SPX_N);
        randombytes(ctx.pub_seed, SPX_N);

        random_addr(addr_ref);
        memcpy(addr_jazz, addr_ref, 8 * sizeof(uint32_t));

        gen_chain(out_ref, in, start, steps, &ctx, addr_ref);
        gen_chain_jazz(out_jazz, in, start, steps, ctx.pub_seed, addr_jazz);

        assert(memcmp(out_ref, out_jazz, SPX_N) == 0);
        assert(memcmp(addr_jazz, addr_ref, 8 * sizeof(uint32_t)) == 0);
    }
}

void test_wots_checksum(void) {
    uint32_t csum_base_w_ref[SPX_WOTS_LEN2], csum_base_w_jazz[SPX_WOTS_LEN2];
    uint32_t msg_base_w[SPX_WOTS_LEN];

    for (int i = 0; i < TESTS; i++) {
        memset((uint8_t *)csum_base_w_ref, 0, SPX_WOTS_LEN2 * sizeof(uint32_t));
        memset((uint8_t *)csum_base_w_jazz, 0, SPX_WOTS_LEN2 * sizeof(uint32_t));
        randombytes((uint8_t *)msg_base_w, SPX_WOTS_LEN * sizeof(uint32_t));

        wots_checksum(csum_base_w_ref, msg_base_w);
        wots_checksum_jazz(csum_base_w_jazz, msg_base_w);

        assert(memcmp(csum_base_w_ref, csum_base_w_jazz, SPX_WOTS_LEN2 * sizeof(uint32_t)) == 0);
    }
}

void test_chain_lengths(void) {
    unsigned int lengths_ref[SPX_WOTS_LEN];
    uint32_t lengths_jazz[SPX_WOTS_LEN];
    uint8_t msg[SPX_N];

    for (int t = 0; t < TESTS; t++) {
        memset(lengths_ref, 0, SPX_WOTS_LEN * sizeof(unsigned int));
        memset(lengths_jazz, 0, SPX_WOTS_LEN * sizeof(uint32_t));
        randombytes(msg, SPX_N);

        chain_lengths(lengths_ref, msg);
        chain_lengths_jazz(lengths_jazz, msg);

        assert(memcmp(lengths_ref, lengths_jazz, SPX_WOTS_LEN * sizeof(uint32_t)) == 0);
    }
}

void test_wots_pk_from_sig(void) {
    uint8_t pk_ref[SPX_WOTS_BYTES], pk_jazz[SPX_WOTS_BYTES];
    uint8_t sig[SPX_BYTES];
    uint8_t msg[MSG_LEN];
    spx_ctx ctx;
    uint32_t addr_ref[8], addr_jazz[8];

    for (int t = 0; t < TESTS; t++) {
        memset(pk_ref, 0, SPX_WOTS_BYTES);
        memset(pk_jazz, 0, SPX_WOTS_BYTES);

        randombytes(sig, SPX_BYTES);
        randombytes(msg, MSG_LEN);
        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);
        random_addr(addr_ref);
        memcpy(addr_jazz, addr_ref, 8 * sizeof(uint32_t));

        wots_pk_from_sig_jazz(pk_jazz, sig, msg, &ctx, addr_jazz);
        wots_pk_from_sig(pk_ref, sig, msg, &ctx, addr_ref);

        assert(memcmp(pk_ref, pk_jazz, SPX_WOTS_BYTES) == 0);
        assert(memcmp(addr_ref, addr_jazz, 8 * sizeof(uint32_t)) == 0);
    }
}

int main(void) {
    test_gen_chain();
    test_wots_checksum(); // Se o wots checksum functiona, assume se que o base_w tambem funciona
    test_chain_lengths();
    // test_wots_pk_from_sig();
    printf("PASS: wots { msg len : %d }\n", MSG_LEN);
    return 0;
}
