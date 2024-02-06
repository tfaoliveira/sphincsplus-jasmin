#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "api.h"
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

extern void gen_chain_jazz(uint8_t *out, const uint8_t *in, uint32_t start, uint32_t steps, const uint8_t *pub_seed,
                           uint32_t addr[8]);

extern void base_w_jazz_out_WOTS_LEN2(uint32_t *out, const uint8_t *in);
extern void base_w_jazz_out_WOTS_LEN1(uint32_t *out, const uint8_t *in);

extern void wots_checksum_jazz(uint32_t *csum_base_w, const uint32_t *msg_base_w);

extern void wots_pk_from_sig_jazz(uint8_t *pk, const uint8_t *sig, const uint8_t *msg, const spx_ctx *ctx,
                                  uint32_t addr[8]);

extern void chain_lengths_jazz(uint32_t *lengths, const uint8_t *msg);

//////////////////////// CODE FROM REF IMPL  ////////////////////////
void ull_to_bytes(unsigned char *out, unsigned int outlen, unsigned long long in) {
    int i;

    /* Iterate over out in decreasing order, for big-endianness. */
    for (i = (signed int)outlen - 1; i >= 0; i--) {
        out[i] = (unsigned char)(in & 0xff);
        in = in >> 8;
    }
}

static void gen_chain(unsigned char *out, const unsigned char *in, unsigned int start, unsigned int steps,
                      const spx_ctx *ctx, uint32_t addr[8]) {
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

void test_base_w(void) {
    bool debug = true;
    /*
     * There's 2 calls to base_w (both in wots.jtmpl)
     *
     * __base_w<SPX_WOTS_LEN2, (SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8>(csum_base_w, csum_bytes_p);
     * __base_w<SPX_WOTS_LEN1,SPX_N>(lengths, msg);
     *
     * We need to support INLEN=(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8 & OUTLEN SPX_WOTS_LEN2
     *            and
     *                    INLEN=SPX_N & OUTLEN=SPX_WOTS_LEN1
     * Here, the OUTLEN is SPX_WOTS_LEN1 but the actual size of the buffer is SPX_WOTS_LEN
     */

    // INLEN=(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8 & OUTLEN SPX_WOTS_LEN2
    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("Base w [1]: test %d/%d\n", i, TESTS);
        }

        uint32_t out_ref[SPX_WOTS_LEN2] = {0};
        uint32_t out_jazz[SPX_WOTS_LEN2] = {0};
        uint8_t in[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8] = {0};

        randombytes(in, (SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8);

        base_w(out_ref, SPX_WOTS_LEN2, in);
        base_w_jazz_out_WOTS_LEN2(out_jazz, in);

        if (memcmp(out_ref, out_jazz, SPX_WOTS_LEN2 * sizeof(uint32_t)) != 0) {
            print_str_u8("out_ref", (uint8_t *)out_ref, SPX_WOTS_LEN2 * sizeof(uint32_t));
            print_str_u8("out_jazz", (uint8_t *)out_jazz, SPX_WOTS_LEN2 * sizeof(uint32_t));
        }

        assert(memcmp(out_ref, out_jazz, SPX_WOTS_LEN2 * sizeof(uint32_t)) == 0);
    }

    // INLEN=SPX_N & OUTLEN=SPX_WOTS_LEN1
    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("Base w [2]: test %d/%d\n", i, TESTS);
        }

        uint32_t out_ref[SPX_WOTS_LEN1] = {0};
        uint32_t out_jazz[SPX_WOTS_LEN1] = {0};
        uint8_t in[SPX_N] = {0};

        randombytes(in, SPX_N);

        base_w(out_ref, SPX_WOTS_LEN1, in);
        base_w_jazz_out_WOTS_LEN1(out_jazz, in);

        if (memcmp(out_ref, out_jazz, SPX_WOTS_LEN1 * sizeof(uint32_t)) != 0) {
            print_str_u8("out_ref", (uint8_t *)out_ref, SPX_WOTS_LEN1 * sizeof(uint32_t));
            print_str_u8("out_jazz", (uint8_t *)out_jazz, SPX_WOTS_LEN1 * sizeof(uint32_t));
        }

        assert(memcmp(out_ref, out_jazz, SPX_WOTS_LEN1 * sizeof(uint32_t)) == 0);
    }
}

void test_gen_chain(void) {
    bool debug = true;

    uint8_t out_ref[SPX_N], out_jazz[SPX_N];
    uint8_t in[SPX_N];
    uint32_t start, steps;
    spx_ctx ctx;
    uint32_t addr_ref[8], addr_jazz[8];

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("Gen Chain: test %d/%d\n", i, TESTS);
        }

        memset(out_ref, 0, SPX_N * sizeof(uint8_t));
        memset(out_jazz, 0, SPX_N * sizeof(uint8_t));

        randombytes(in, SPX_N);
        randombytes((uint8_t *)&start, sizeof(uint32_t));
        randombytes((uint8_t *)&steps, sizeof(uint32_t));

        randombytes(ctx.sk_seed, SPX_N);
        randombytes(ctx.pub_seed, SPX_N);

        randombytes(addr_ref, 8 * sizeof(uint32_t));
        memcpy(addr_jazz, addr_ref, 8 * sizeof(uint32_t));

        gen_chain(out_ref, in, start, steps, &ctx, addr_ref);
        gen_chain_jazz(out_jazz, in, start, steps, ctx.pub_seed, addr_jazz);

        assert(memcmp(out_ref, out_jazz, SPX_N) == 0);
        assert(memcmp(addr_jazz, addr_ref, 8 * sizeof(uint32_t)) == 0);
    }
}

void test_wots_checksum(void) {
    bool debug = true;

    uint32_t csum_base_w_ref[SPX_WOTS_LEN2], csum_base_w_jazz[SPX_WOTS_LEN2];
    uint32_t msg_base_w[SPX_WOTS_LEN];

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("Wots Checksum: test %d/%d\n", i, TESTS);
        }

        memset((uint8_t *)csum_base_w_ref, 0, SPX_WOTS_LEN2 * sizeof(uint32_t));
        memset((uint8_t *)csum_base_w_jazz, 0, SPX_WOTS_LEN2 * sizeof(uint32_t));

        randombytes((uint8_t *)msg_base_w, SPX_WOTS_LEN * sizeof(uint32_t));

        wots_checksum(csum_base_w_ref, msg_base_w);
        wots_checksum_jazz(csum_base_w_jazz, msg_base_w);

        if (memcmp(csum_base_w_ref, csum_base_w_jazz, SPX_WOTS_LEN2 * sizeof(uint32_t)) != 0) {
            print_str_u8("ref", (uint8_t *)csum_base_w_ref, SPX_WOTS_LEN2 * sizeof(uint32_t));
            print_str_u8("jazz", (uint8_t *)csum_base_w_jazz, SPX_WOTS_LEN2 * sizeof(uint32_t));
        }

        assert(memcmp(csum_base_w_ref, csum_base_w_jazz, SPX_WOTS_LEN2 * sizeof(uint32_t)) == 0);
    }
}

void test_chain_lengths(void) {
    bool debug = true;

    unsigned int lengths_ref[SPX_WOTS_LEN];
    uint32_t lengths_jazz[SPX_WOTS_LEN];
    uint8_t msg[SPX_N];

    for (int t = 0; t < TESTS; t++) {
        if (debug) {
            printf("Chain Lengths: test %d/%d\n", t, TESTS);
        }

        memset(lengths_ref, 0, SPX_WOTS_LEN * sizeof(unsigned int));
        memset(lengths_jazz, 0, SPX_WOTS_LEN * sizeof(uint32_t));
        randombytes(msg, SPX_N);

        chain_lengths(lengths_ref, msg);
        chain_lengths_jazz(lengths_jazz, msg);

        assert(memcmp(lengths_ref, lengths_jazz, SPX_WOTS_LEN * sizeof(uint32_t)) == 0);
    }
}

void test_wots_pk_from_sig(void) {
    bool debug = true;

    uint8_t pk_ref[SPX_WOTS_BYTES], pk_jazz[SPX_WOTS_BYTES];
    uint8_t sig[SPX_BYTES];
    uint8_t msg[SPX_N];  // ROOT
    spx_ctx ctx;
    uint32_t addr_ref[8], addr_jazz[8];

    for (int t = 0; t < TESTS; t++) {
        if (debug) {
            printf("Wots Pk from Sig: test %d/%d\n", t, TESTS);
        }

        memset(pk_ref, 0, SPX_WOTS_BYTES);
        memset(pk_jazz, 0, SPX_WOTS_BYTES);

        randombytes(sig, SPX_BYTES);
        randombytes(msg, SPX_N);
        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);
        randombytes(addr_ref, 8 * sizeof(uint32_t));

        memcpy(addr_jazz, addr_ref, 8 * sizeof(uint32_t));

        assert(memcmp(pk_ref, pk_jazz, SPX_WOTS_BYTES) == 0);
        assert(memcmp(addr_ref, addr_jazz, 8 * sizeof(uint32_t)) == 0);

        wots_pk_from_sig_jazz(pk_jazz, sig, msg, &ctx, addr_jazz);
        wots_pk_from_sig(pk_ref, sig, msg, &ctx, addr_ref);

        if (memcmp(pk_ref, pk_jazz, SPX_WOTS_BYTES * sizeof(uint8_t)) != 0) {
            print_str_u8("PK Ref", pk_ref, SPX_WOTS_BYTES * sizeof(uint8_t));
            print_str_u8("PK Jazz", pk_jazz, SPX_WOTS_BYTES * sizeof(uint8_t));
        }

        assert(memcmp(pk_ref, pk_jazz, SPX_WOTS_BYTES) == 0);
        assert(memcmp(addr_ref, addr_jazz, 8 * sizeof(uint32_t)) == 0);
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
    test_gen_chain();
    test_base_w();
    test_wots_checksum();
    test_chain_lengths();
    test_wots_pk_from_sig();
    test_api();
    printf("PASS: wots { params : %s }\n", xstr(PARAMS));
    return 0;
}
