#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "utilsx1.h"
#include "hash.h"
#include "wots.h"
#include "wotsx1.h"
#include "params.h"

extern void set_chain_addr_jazz(uint32_t addr[8], uint32_t chain);
extern void set_hash_addr_jazz(uint32_t addr[8], uint32_t hash);

extern void thash_1(uint8_t *out, const uint8_t *in, const uint8_t *pub_seed, uint32_t addr[8]);

extern void gen_chain_jazz(uint8_t *out, const uint8_t *in, uint32_t start, uint32_t steps,
                           const uint8_t *pub_seed, uint32_t addr[8]);

extern void wots_checksum_jazz(uint32_t *csum_base_w, const uint32_t *msg_base_w);

extern void base_w_jazz_in_SPX_N(uint32_t* out, const uint8_t* in);

/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 * This only works when log_w is a divisor of 8.
 */
static void base_w(unsigned int *output, const int out_len,
                   const unsigned char *input)
{
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

/* Takes a message and derives the matching chain lengths. */
void chain_lengths(unsigned int *lengths, const unsigned char *msg)
{
    base_w(lengths, SPX_WOTS_LEN1, msg);
    wots_checksum_jazz(lengths + SPX_WOTS_LEN1, lengths);
}

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const spx_ctx *ctx, uint32_t addr[8])
{
    unsigned int lengths[SPX_WOTS_LEN];
    uint32_t i;

    chain_lengths(lengths, msg);

    for (i = 0; i < SPX_WOTS_LEN; i++) {
        set_chain_addr_jazz(addr, i);
        gen_chain_jazz(pk + i*SPX_N, sig + i*SPX_N,
                  lengths[i], SPX_WOTS_W - 1 - lengths[i], ctx->pub_seed, addr);
    }
}
