#include "wots.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "address.h"
#include "hash.h"
#include "params.h"
#include "thash.h"
#include "utils.h"
#include "utilsx1.h"
#include "wotsx1.h"

/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays.
 *
 * Interprets in as start-th value of the chain.
 * addr has to contain the address of the chain.
 */
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

/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 * This only works when log_w is a divisor of 8.
 */
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

/* Computes the WOTS+ checksum over a message (in base_w). */
static void wots_checksum(unsigned int *csum_base_w, const unsigned int *msg_base_w) {
    unsigned int csum = 0;
    unsigned char csum_bytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];
    unsigned int i;

    /* Compute checksum. */
    for (i = 0; i < SPX_WOTS_LEN1; i++) {
        csum += SPX_WOTS_W - 1 - msg_base_w[i];
    }

    /* Convert checksum to base_w. */
    /* Make sure expected empty zero bits are the least significant bits. */
    csum = csum << ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8);
    ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);

#ifdef TEST_WOTS_BASE_W
    // extern void base_w_jazz_out_WOTS_LEN2(uint32_t *out, const uint8_t *in);

    // OUTLEN : SPX_WOTS_LEN2
    // INLEN  : len (csum_bytes) = (SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8

    unsigned int out_jazz[SPX_WOTS_LEN2];

    memcpy(out_jazz, csum_base_w, SPX_WOTS_LEN2 * sizeof(unsigned int));

    base_w(csum_base_w, SPX_WOTS_LEN2, csum_bytes);
    base_w_jazz_out_WOTS_LEN2(out_jazz, csum_bytes);

    if (memcmp(out_jazz, csum_base_w, SPX_WOTS_LEN2 * sizeof(unsigned int)) != 0) {
        print_str_u8("ref", (uint8_t *)csum_base_w, SPX_WOTS_LEN2 * sizeof(unsigned int));
        print_str_u8("jazz", (uint8_t *)out_jazz, SPX_WOTS_LEN2 * sizeof(unsigned int));
    }

    assert(memcmp(out_jazz, csum_base_w, SPX_WOTS_LEN2 * sizeof(unsigned int)) == 0);

#else
    base_w(sum_base_w, SPX_WOTS_LEN2, csum_bytes);
#endif
}

/* Takes a message and derives the matching chain lengths. */
void chain_lengths(unsigned int *lengths, const unsigned char *msg) {
#ifdef TEST_WOTS_BASE_W
    // extern void base_w_jazz_out_WOTS_LEN1(uint32_t *out, const uint8_t *in);

    // OUTLEN = SPX_WOTS_LEN1
    // INLEN  = len(3rd arg of wots_pk_from_sig) = SPX_N

    unsigned int out_jazz[SPX_WOTS_LEN1];

    memcpy(out_jazz, msg, SPX_WOTS_LEN1 * sizeof(unsigned int));

    base_w(lengths, SPX_WOTS_LEN1, msg);
    base_w_jazz_out_WOTS_LEN1(out_jazz, msg);

    if (memcmp(out_jazz, lengths, SPX_WOTS_LEN1 * sizeof(unsigned int)) != 0) {
        print_str_u8("ref", (uint8_t *)lengths, SPX_WOTS_LEN1 * sizeof(unsigned int));
        print_str_u8("jazz", (uint8_t *)out_jazz, SPX_WOTS_LEN1 * sizeof(unsigned int));
    }

    assert(memcmp(out_jazz, lengths, SPX_WOTS_LEN1 * sizeof(unsigned int)) == 0);

#else
    base_w(lengths, SPX_WOTS_LEN1, msg);
#endif

#ifdef TEST_WOTS_CHECKSUM
    uint32_t lengths_jazz[SPX_WOTS_LEN];

    memcpy(lengths_jazz, lengths, SPX_WOTS_LEN * sizeof(uint32_t));

    wots_checksum(lengths + SPX_WOTS_LEN1, lengths);
    wots_checksum_jazz(lengths_jazz + SPX_WOTS_LEN1, lengths_jazz);

    assert(memcmp(lengths, lengths_jazz, SPX_WOTS_LEN) == 0);

#else
    wots_checksum(lengths + SPX_WOTS_LEN1, lengths);
#endif
}

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pk_from_sig(unsigned char *pk, const unsigned char *sig, const unsigned char *msg, const spx_ctx *ctx,
                      uint32_t addr[8]) {
    unsigned int lengths[SPX_WOTS_LEN];
    uint32_t i;

#ifdef TEST_WOTS_CHAIN_LENGTHS
    uint32_t lengths_jazz[SPX_WOTS_LEN];

    memcpy(lengths_jazz, lengths, SPX_WOTS_LEN * sizeof(uint32_t));

    chain_lengths(lengths, msg);
    chain_lengths_jazz(lengths_jazz, msg);

    assert(memcmp(lengths_jazz, lengths, SPX_WOTS_LEN * sizeof(uint32_t)) == 0);
#else
    chain_lengths(lengths, msg);
#endif

    for (i = 0; i < SPX_WOTS_LEN; i++) {
        set_chain_addr(addr, i);
        gen_chain(pk + i * SPX_N, sig + i * SPX_N, lengths[i], SPX_WOTS_W - 1 - lengths[i], ctx, addr);
    }
}
