#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "fors.h"
#include "utils.h"
#include "utilsx1.h"
#include "hash.h"
#include "thash.h"
#include "address.h"

static void fors_gen_sk(unsigned char *sk, const spx_ctx *ctx,
                        uint32_t fors_leaf_addr[8])
{
    prf_addr(sk, ctx, fors_leaf_addr);
}

static void fors_sk_to_leaf(unsigned char *leaf, const unsigned char *sk,
                            const spx_ctx *ctx,
                            uint32_t fors_leaf_addr[8])
{
    thash(leaf, sk, 1, ctx, fors_leaf_addr);
}

struct fors_gen_leaf_info {
    uint32_t leaf_addrx[8];
};

static void fors_gen_leafx1(unsigned char *leaf,
                            const spx_ctx *ctx,
                            uint32_t addr_idx, void *info)
{
    struct fors_gen_leaf_info *fors_info = info;
    uint32_t *fors_leaf_addr = fors_info->leaf_addrx;

    /* Only set the parts that the caller doesn't set */
    set_tree_index(fors_leaf_addr, addr_idx);
    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSPRF);
    fors_gen_sk(leaf, ctx, fors_leaf_addr);

    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE);
    fors_sk_to_leaf(leaf, leaf,
                    ctx, fors_leaf_addr);
}

/**
 * Interprets m as SPX_FORS_HEIGHT-bit unsigned integers.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 * Assumes indices has space for SPX_FORS_TREES integers.
 */
static void message_to_indices(uint32_t *indices, const unsigned char *m)
{
    unsigned int i, j;
    unsigned int offset = 0;

    for (i = 0; i < SPX_FORS_TREES; i++) {
        indices[i] = 0;
        for (j = 0; j < SPX_FORS_HEIGHT; j++) {
            indices[i] ^= ((m[offset >> 3] >> (~offset & 0x7)) & 1u) << (SPX_FORS_HEIGHT-1-j);
            offset++;
        }
    }
}



/**
 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */

#ifndef TEST_FORS_TREEHASH
void fors_sign(unsigned char *sig, unsigned char *pk,
               const unsigned char *m,
               const spx_ctx *ctx,
               const uint32_t fors_addr[8])
{
    uint32_t indices[SPX_FORS_TREES];
    unsigned char roots[SPX_FORS_TREES * SPX_N];
    uint32_t fors_tree_addr[8] = {0};
    struct fors_gen_leaf_info fors_info = {0};
    uint32_t *fors_leaf_addr = fors_info.leaf_addrx;
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_leaf_addr, fors_addr);

    copy_keypair_addr(fors_pk_addr, fors_addr);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);

    for (i = 0; i < SPX_FORS_TREES; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSPRF);

        fors_gen_sk(sig, ctx, fors_tree_addr);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
        sig += SPX_N;

        treehashx1(roots + i*SPX_N, sig, ctx,
                 indices[i], idx_offset, SPX_FORS_HEIGHT, fors_gen_leafx1,
                 fors_tree_addr, fors_leaf_addr);

        sig += SPX_N * SPX_FORS_HEIGHT;
    }
    thash(pk, roots, SPX_FORS_TREES, ctx, fors_pk_addr);
}
#else

extern void treehash_fors_jazz(uint8_t *root, uint8_t *auth_path, uint8_t *ctx,
                               uint32_t leaf_idx, uint32_t idx_offset, void *addr);


void fors_sign(unsigned char *sig, unsigned char *pk,
               const unsigned char *m,
               const spx_ctx *ctx,
               const uint32_t fors_addr[8])
{
    uint8_t *sig_at_entry = sig;
    uint8_t sig_at_entry_jazz[SPX_FORS_BYTES]; //
    uint8_t *sig_jazz = sig_at_entry_jazz; //
    uint8_t ctx_jazz[2*SPX_N]; //

    uint32_t indices[SPX_FORS_TREES];

    unsigned char roots[SPX_FORS_TREES * SPX_N];
    unsigned char roots_jazz[SPX_FORS_TREES * SPX_N]; //

    uint32_t fors_tree_addr[8] = {0};
    uint32_t fors_tree_addr_jazz[8] = {0}; //

    struct fors_gen_leaf_info fors_info = {0};
    uint32_t *fors_leaf_addr = fors_info.leaf_addrx;

    struct fors_gen_leaf_info fors_info_jazz = {0}; //
    uint32_t *fors_leaf_addr_jazz = fors_info_jazz.leaf_addrx; //

    uint32_t *fors_tree_leaf_addr_jazz[2]; //
    fors_tree_leaf_addr_jazz[0] = fors_tree_addr_jazz; //
    fors_tree_leaf_addr_jazz[1] = fors_leaf_addr_jazz; //

    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_leaf_addr, fors_addr);

    copy_keypair_addr(fors_pk_addr, fors_addr);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);

    for (i = 0; i < SPX_FORS_TREES; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSPRF);

        fors_gen_sk(sig, ctx, fors_tree_addr);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
        sig += SPX_N;
        sig_jazz += SPX_N; //

        // copy state
        memcpy(roots_jazz, roots, SPX_FORS_TREES * SPX_N);
        memcpy(sig_at_entry_jazz, sig_at_entry, sizeof(sig_at_entry_jazz));
        memcpy(ctx_jazz, ctx->pub_seed, SPX_N);
        memcpy(ctx_jazz+SPX_N, ctx->sk_seed, SPX_N);
        memcpy(fors_tree_addr_jazz, fors_tree_addr, sizeof(fors_tree_addr));
        memcpy(fors_leaf_addr_jazz, fors_leaf_addr, sizeof(uint32_t)*8); // note: depends on definition from line ~25.

        treehashx1(roots + i*SPX_N, // ptr
                   sig, // ptr
                   ctx, // ptr
                   indices[i], // u32
                   idx_offset, // u32
                   SPX_FORS_HEIGHT, 
                   fors_gen_leafx1,
                   fors_tree_addr, // ptr (merged)
                   fors_leaf_addr // ptr (merged)
                  );

        treehash_fors_jazz(
                   roots_jazz + i*SPX_N, // ptr
                   sig_jazz, // ptr
                   ctx_jazz, // ptr
                   indices[i], // u32
                   idx_offset, // u32
                   fors_tree_leaf_addr_jazz
                  );

        // assert that "outputs" are equal
        assert(memcmp(roots_jazz, roots, SPX_FORS_TREES * SPX_N) == 0);
        assert(memcmp(sig_at_entry_jazz, sig_at_entry, sizeof(sig_at_entry_jazz)) == 0);
        assert(memcmp(fors_tree_addr_jazz, fors_tree_addr, sizeof(fors_tree_addr)) == 0);
        assert(memcmp(fors_leaf_addr_jazz, fors_leaf_addr, sizeof(uint32_t)*8) == 0);
 
        sig += SPX_N * SPX_FORS_HEIGHT;
        sig_jazz += SPX_N * SPX_FORS_HEIGHT;
    }
    thash(pk, roots, SPX_FORS_TREES, ctx, fors_pk_addr);
}

#endif

/**
 * Derives the FORS public key from a signature.
 * This can be used for verification by comparing to a known public key, or to
 * subsequently verify a signature on the derived public key. The latter is the
 * typical use-case when used as an FTS below an OTS in a hypertree.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */
void fors_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *m,
                      const spx_ctx* ctx,
                      const uint32_t fors_addr[8])
{
    uint32_t indices[SPX_FORS_TREES];
    unsigned char roots[SPX_FORS_TREES * SPX_N] = {0}; // FIXME: Remove this when treehash is done
    unsigned char leaf[SPX_N];
    uint32_t fors_tree_addr[8] = {0};
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_pk_addr, fors_addr);

    set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);

    for (i = 0; i < SPX_FORS_TREES; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        fors_sk_to_leaf(leaf, sig, ctx, fors_tree_addr);
        sig += SPX_N;

        compute_root(roots + i*SPX_N, leaf, indices[i], idx_offset,
                     sig, SPX_FORS_HEIGHT, ctx, fors_tree_addr);
        sig += SPX_N * SPX_FORS_HEIGHT;
    }

    thash(pk, roots, SPX_FORS_TREES, ctx, fors_pk_addr);
}
