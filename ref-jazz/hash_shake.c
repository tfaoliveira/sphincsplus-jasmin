#include <stdint.h>
#include <string.h>

#include "address.h"
#include "fips202.h"
#include "hash.h"
#include "params.h"
#include "utils.h"

extern uint64_t bytes_to_ull_jazz_1(const uint8_t *a);
extern uint64_t bytes_to_ull__8_jazz(const uint8_t *a);

/* For SHAKE256, there is no immediate reason to initialize at the start,
   so this function is an empty operation. */
void initialize_hash_function(spx_ctx *ctx) { (void)ctx; /* Suppress an 'unused parameter' warning. */ }

/**
 * Computes the message hash using R, the public key, and the message.
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 */
void hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx, const unsigned char *R,
                  const unsigned char *pk, const unsigned char *m, unsigned long long mlen, const spx_ctx *ctx) {
    (void)ctx;
#define SPX_TREE_BITS (SPX_TREE_HEIGHT * (SPX_D - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

    unsigned char buf[SPX_DGST_BYTES];
    unsigned char *bufp = buf;
    uint64_t s_inc[26];

    shake256_inc_init(s_inc);
    shake256_inc_absorb(s_inc, R, SPX_N);
    shake256_inc_absorb(s_inc, pk, SPX_PK_BYTES);
    shake256_inc_absorb(s_inc, m, mlen);
    shake256_inc_finalize(s_inc);
    shake256_inc_squeeze(buf, SPX_DGST_BYTES, s_inc);

    memcpy(digest, bufp, SPX_FORS_MSG_BYTES);
    bufp += SPX_FORS_MSG_BYTES;

#if SPX_TREE_BITS > 64
#error For given height and depth, 64 bits cannot represent all
#endif
    // *tree = bytes_to_ull(bufp, SPX_TREE_BYTES); // ref
    *tree = bytes_to_ull__8_jazz(bufp);  // jasmin impl
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    bufp += SPX_TREE_BYTES;

    // *leaf_idx = (uint32_t)bytes_to_ull(bufp, SPX_LEAF_BYTES); // ref
    *leaf_idx = (uint32_t)bytes_to_ull_jazz(bufp);  // jasmin impl
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}
