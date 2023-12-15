#include "merkle.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "address.h"
#include "params.h"
#include "utils.h"
#include "utilsx1.h"
#include "wots.h"
#include "wotsx1.h"

/*
 * This generates a Merkle signature (WOTS signature followed by the Merkle
 * authentication path).  This is in this file because most of the complexity
 * is involved with the WOTS signature; the Merkle authentication path logic
 * is mostly hidden in treehashx4
 */
#ifndef TEST_WOTSX1
void merkle_sign(uint8_t *sig, unsigned char *root, const spx_ctx *ctx, uint32_t wots_addr[8],
                 uint32_t tree_addr[8], uint32_t idx_leaf) {
    unsigned char *auth_path = sig + SPX_WOTS_BYTES;
    struct leaf_info_x1 info = {0};
    unsigned steps[SPX_WOTS_LEN];

    info.wots_sig = sig;
    chain_lengths(steps, root);
    info.wots_steps = steps;

    set_type(&tree_addr[0], SPX_ADDR_TYPE_HASHTREE);
    set_type(&info.pk_addr[0], SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr(&info.leaf_addr[0], wots_addr);
    copy_subtree_addr(&info.pk_addr[0], wots_addr);

    info.wots_sign_leaf = idx_leaf;

    treehashx1(root, auth_path, ctx, idx_leaf, 0, SPX_TREE_HEIGHT, wots_gen_leafx1, tree_addr,
               &info);
}
#else

// NOTE: In this test, when calling treehash, we test both treehash and wots_gen_leaf
// FIXME: Maybe test wots_gen_leaf_separately

extern void treehash_wots_jazz(uint8_t *root, uint8_t *auth_path, uint8_t *ctx, uint32_t leaf_idx,
                               uint32_t tree_addr[8], void *info);

void merkle_sign(uint8_t *sig, unsigned char *root, const spx_ctx *ctx, uint32_t wots_addr[8],
                 uint32_t tree_addr[8], uint32_t idx_leaf) {
    uint8_t root_jazz[SPX_N];
    uint8_t auth_path_jazz[SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES];
    uint8_t ctx_jazz[2 * SPX_N];
    uint32_t idx_leaf_jazz;
    uint32_t tree_addr_jazz[8];
    struct leaf_info_x1 info_jazz = {0};

    puts("Testing treehash wots + wots gen leaf inside merkle sign");

    unsigned char *auth_path = sig + SPX_WOTS_BYTES;
    struct leaf_info_x1 info = {0};
    unsigned steps[SPX_WOTS_LEN];

    info.wots_sig = sig;
    chain_lengths(steps, root);
    info.wots_steps = steps;

    set_type(&tree_addr[0], SPX_ADDR_TYPE_HASHTREE);
    set_type(&info.pk_addr[0], SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr(&info.leaf_addr[0], wots_addr);
    copy_subtree_addr(&info.pk_addr[0], wots_addr);

    info.wots_sign_leaf = idx_leaf;

    // copy state
    memcpy(root_jazz, root, SPX_N);
    memcpy(auth_path_jazz, auth_path, SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES);
    memcpy(ctx_jazz, ctx->pub_seed, SPX_N);
    memcpy(ctx_jazz + SPX_N, ctx->sk_seed, SPX_N);
    idx_leaf_jazz = idx_leaf;
    memcpy(tree_addr_jazz, tree_addr, 8 * sizeof(uint32_t));
    memcpy(&info_jazz, &info, sizeof(info));

    assert(memcmp(root_jazz, root, SPX_N) == 0);
    assert(memcmp(auth_path_jazz, auth_path, SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES) == 0);
    assert(memcmp(tree_addr_jazz, tree_addr, 8 * sizeof(uint32_t)) == 0);

    treehashx1(root, auth_path, ctx, idx_leaf, 0, SPX_TREE_HEIGHT, wots_gen_leafx1, tree_addr,
               &info);
    puts("Finished treehash ref");
    treehash_wots_jazz(root_jazz, auth_path_jazz, ctx_jazz, idx_leaf_jazz, tree_addr_jazz,
                       &info_jazz);

    puts("Finished treehash jazz");

    assert(memcmp(root_jazz, root, SPX_N) == 0);  // fails
    assert(memcmp(auth_path_jazz, auth_path, SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES) == 0);  //
    assert(memcmp(tree_addr_jazz, tree_addr, 8 * sizeof(uint32_t)) == 0);
}
#endif

void merkle_gen_root(unsigned char *root, const spx_ctx *ctx) {
    unsigned char auth_path[SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES];
    uint32_t top_tree_addr[8] = {0};
    uint32_t wots_addr[8] = {0};

    set_layer_addr(top_tree_addr, SPX_D - 1);
    set_layer_addr(wots_addr, SPX_D - 1);

    merkle_sign(auth_path, root, ctx, wots_addr, top_tree_addr,
                (uint32_t)~0 /* ~0 means "don't bother generating an auth path */);
}