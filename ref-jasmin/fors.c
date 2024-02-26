#include "fors.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "hash.h"
#include "macros.h"
#include "thash.h"
#include "utils.h"
#include "utilsx1.h"
#include "wrappers.h"

#ifdef TEST_THASH
extern void thash_1(uint8_t *out, const uint8_t *in, const uint8_t *pub_seed, uint32_t addr[8]);
#endif

#ifdef TEST_HASH_PRF_ADDR
extern void prf_addr_jazz(uint8_t *out, const unsigned char *pub_seed, const unsigned char *sk_seed,
                          const uint32_t add[8]);
#endif

#ifdef TEST_FORS_TREEHASH
extern void treehash_fors_jazz(uint8_t *root, uint8_t *auth_path, uint8_t *ctx, uint32_t leaf_idx, uint32_t idx_offset,
                               void *addr);
#endif

static void fors_gen_sk(unsigned char *sk, const spx_ctx *ctx, uint32_t fors_leaf_addr[8]) {
#ifdef TEST_HASH_PRF_ADDR
    prf_addr_jazz(sk, ctx->pub_seed, ctx->sk_seed, fors_leaf_addr);
#else
    prf_addr(sk, ctx, fors_leaf_addr);
#endif
}

static void fors_sk_to_leaf(unsigned char *leaf, const unsigned char *sk, const spx_ctx *ctx,
                            uint32_t fors_leaf_addr[8]) {
#ifdef TEST_THASH
    thash_1(leaf, sk, ctx->pub_seed, fors_leaf_addr);
#else
    thash(leaf, sk, 1, ctx, fors_leaf_addr);
#endif
}

struct fors_gen_leaf_info {
    uint32_t leaf_addrx[8];
};

// NOTE: This function is no longer static because we use it in wrappers.c
//       We also need to add it to the header file
void fors_gen_leafx1(unsigned char *leaf, const spx_ctx *ctx, uint32_t addr_idx, void *info) {
    struct fors_gen_leaf_info *fors_info = info;
    uint32_t *fors_leaf_addr = fors_info->leaf_addrx;

/* Only set the parts that the caller doesn't set */
#ifdef TEST_ADDRESS
    set_tree_index_jazz(fors_leaf_addr, addr_idx);
    set_type_jazz(fors_leaf_addr, SPX_ADDR_TYPE_FORSPRF);
#else
    set_tree_index(fors_leaf_addr, addr_idx);
    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSPRF);
#endif

#ifdef TEST_FORS_GEN_SK
    fors_gen_sk_jazz(leaf, ctx->pub_seed, ctx->sk_seed, fors_leaf_addr);
#else
    fors_gen_sk(leaf, ctx, fors_leaf_addr);
#endif

#ifdef TEST_ADDRESS
    set_type_jazz(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE);
#else
    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE);
#endif

#ifdef TEST_FORS_SK_TO_LEAF
    fors_sk_to_leaf_jazz(leaf, leaf, ctx->pub_seed, fors_leaf_addr);
#else
    fors_sk_to_leaf(leaf, leaf, ctx, fors_leaf_addr);
#endif
}

/**
 * Interprets m as SPX_FORS_HEIGHT-bit unsigned integers.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 * Assumes indices has space for SPX_FORS_TREES integers.
 */
static void message_to_indices(uint32_t *indices, const unsigned char *m) {
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

/**
 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */
void fors_sign(unsigned char *sig, unsigned char *pk, const unsigned char *m, const spx_ctx *ctx,
               const uint32_t fors_addr[8]) {
    uint32_t indices[SPX_FORS_TREES];
    unsigned char roots[SPX_FORS_TREES * SPX_N];
    uint32_t fors_tree_addr[8] = {0};
    struct fors_gen_leaf_info fors_info = {0};
    uint32_t *fors_leaf_addr = fors_info.leaf_addrx;
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

#ifdef TEST_ADDRESS
    copy_keypair_addr_jazz(fors_tree_addr, fors_addr);
    copy_keypair_addr_jazz(fors_leaf_addr, fors_addr);
    copy_keypair_addr_jazz(fors_pk_addr, fors_addr);
    set_type_jazz(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

#else
    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_leaf_addr, fors_addr);
    copy_keypair_addr(fors_pk_addr, fors_addr);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);
#endif

    message_to_indices(indices, m);

    for (i = 0; i < SPX_FORS_TREES; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT);

#ifdef TEST_ADDRESS
        set_tree_height_jazz(fors_tree_addr, 0);
        set_tree_index_jazz(fors_tree_addr, indices[i] + idx_offset);
        set_type_jazz(fors_tree_addr, SPX_ADDR_TYPE_FORSPRF);
#else
        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSPRF);
#endif

        /* Include the secret key part that produces the selected leaf node. */
        fors_gen_sk(sig, ctx, fors_tree_addr);

#ifdef TEST_ADDRESS
        set_type_jazz(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
#else
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
#endif

        sig += SPX_N;

/* Compute the authentication path for this leaf node. */
#ifdef TEST_FORS_TREEHASH
        uint32_t *fors_tree_leaf_addr_jazz[2];
        fors_tree_leaf_addr_jazz[0] = fors_tree_addr;
        fors_tree_leaf_addr_jazz[1] = fors_info.leaf_addrx;

        treehash_fors_jazz(roots + i * SPX_N, sig, ctx, indices[i], idx_offset, fors_tree_leaf_addr_jazz);
#else
        treehashx1_fors(roots + i * SPX_N, sig, ctx, indices[i], idx_offset, SPX_FORS_HEIGHT, fors_tree_addr,
                        &fors_info);
#endif

        sig += SPX_N * SPX_FORS_HEIGHT;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    // TODO: replace this call
    thash(pk, roots, SPX_FORS_TREES, ctx, fors_pk_addr);
}

/**
 * Derives the FORS public key from a signature.
 * This can be used for verification by comparing to a known public key, or to
 * subsequently verify a signature on the derived public key. The latter is the
 * typical use-case when used as an FTS below an OTS in a hypertree.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */
void fors_pk_from_sig(unsigned char *pk, const unsigned char *sig, const unsigned char *m, const spx_ctx *ctx,
                      const uint32_t fors_addr[8]) {
    uint32_t indices[SPX_FORS_TREES];
    unsigned char roots[SPX_FORS_TREES * SPX_N];
    unsigned char leaf[SPX_N];
    uint32_t fors_tree_addr[8] = {0};
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

#ifdef TEST_ADDRESS
    copy_keypair_addr_jazz(fors_tree_addr, fors_addr);
    copy_keypair_addr_jazz(fors_pk_addr, fors_addr);
    set_type_jazz(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    set_type_jazz(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);
#else
    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_pk_addr, fors_addr);
    set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);
#endif

    message_to_indices(indices, m);

    for (i = 0; i < SPX_FORS_TREES; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT);

#ifdef TEST_ADDRESS
        set_tree_height_jazz(fors_tree_addr, 0);
        set_tree_index_jazz(fors_tree_addr, indices[i] + idx_offset);
#else
        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);
#endif

/* Derive the leaf from the included secret key part. */
#ifdef TEST_FORS_SK_TO_LEAF
        fors_sk_to_leaf_jazz(leaf, sig, ctx->pub_seed, fors_tree_addr);
#else
        fors_sk_to_leaf(leaf, sig, ctx, fors_tree_addr);
#endif

        sig += SPX_N;

/* Derive the corresponding root node of this tree. */
#ifdef TEST_COMPUTE_ROOT
        compute_root_jasmin(roots + i * SPX_N, leaf, indices[i], idx_offset, sig, SPX_FORS_HEIGHT, ctx, fors_tree_addr);
#else
        compute_root(roots + i * SPX_N, leaf, indices[i], idx_offset, sig, SPX_FORS_HEIGHT, ctx, fors_tree_addr);
#endif

        sig += SPX_N * SPX_FORS_HEIGHT;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    thash(pk, roots, SPX_FORS_TREES, ctx, fors_pk_addr);
}
