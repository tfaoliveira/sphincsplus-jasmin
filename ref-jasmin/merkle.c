#include "merkle.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "address.h"
#include "params.h"
#include "print.h"
#include "utils.h"
#include "utilsx1.h"
#include "wots.h"
#include "wotsx1.h"
#include "wrappers.h"

/*
 * This generates a Merkle signature (WOTS signature followed by the Merkle
 * authentication path).  This is in this file because most of the complexity
 * is involved with the WOTS signature; the Merkle authentication path logic
 * is mostly hidden in treehashx4
 */
void merkle_sign(uint8_t *sig, unsigned char *root, const spx_ctx *ctx, uint32_t wots_addr[8], uint32_t tree_addr[8],
                 uint32_t idx_leaf) {
    unsigned char *auth_path = sig + SPX_WOTS_BYTES;
    struct leaf_info_x1 info = {0};
    unsigned steps[SPX_WOTS_LEN];

    info.wots_sig = sig;

#ifdef TEST_WOTS_CHAIN_LENGTHS
    chain_lengths_jazz(steps, root);
#else
    chain_lengths(steps, root);
#endif

    info.wots_steps = steps;

#ifdef TEST_ADDRESS
    set_type_jazz(&tree_addr[0], SPX_ADDR_TYPE_HASHTREE);
    set_type_jazz(&info.pk_addr[0], SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr_jazz(&info.leaf_addr[0], wots_addr);
    copy_subtree_addr_jazz(&info.pk_addr[0], wots_addr);
#else
    set_type(&tree_addr[0], SPX_ADDR_TYPE_HASHTREE);
    set_type(&info.pk_addr[0], SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr(&info.leaf_addr[0], wots_addr);
    copy_subtree_addr(&info.pk_addr[0], wots_addr);
#endif

    info.wots_sign_leaf = idx_leaf;

#ifdef DEBUG
    puts("Debug do treehash wots");

    uint8_t root_jazz[SPX_N];
    uint32_t tree_addr_jazz[8];
    struct leaf_info_x1 info_jazz = {0};

    uint8_t wots_sig_jazz[SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES];
    uint32_t steps_jazz[SPX_WOTS_LEN];

    // CTX AND IDX LEAF ARE THE SAME BECAUSE THEY ARE NOT CHANGED

    // Copy state
    memcpy(wots_sig_jazz, sig, SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES);
    memcpy(steps_jazz, info.wots_steps, SPX_WOTS_LEN * sizeof(uint32_t));

    memcpy(root_jazz, root, SPX_N);
    memcpy(tree_addr_jazz, tree_addr, 8 * sizeof(uint32_t));

    info_jazz.wots_sig = wots_sig_jazz;
    info_jazz.wots_steps = steps_jazz;
    info_jazz.wots_sign_leaf = idx_leaf;

    memcpy(info_jazz.leaf_addr, info.leaf_addr, 8 * sizeof(uint32_t));
    memcpy(info_jazz.pk_addr, info.pk_addr, 8 * sizeof(uint32_t));

    assert(memcmp(root_jazz, root, SPX_N) == 0);
    assert(memcmp(tree_addr_jazz, tree_addr, 8 * sizeof(uint32_t)) == 0);
    assert(memcmp(info.wots_sig, info_jazz.wots_sig, SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES) == 0);
    assert(memcmp(info.wots_steps, info_jazz.wots_steps, SPX_WOTS_LEN * sizeof(uint32_t)) == 0);
    assert(memcmp(info.leaf_addr, info_jazz.leaf_addr, 8 * sizeof(uint32_t)) == 0);
    assert(memcmp(info.pk_addr, info_jazz.pk_addr, 8 * sizeof(uint32_t)) == 0);

    treehashx1_wots(root, ctx, idx_leaf, tree_addr, &info);
    puts("Chegou aqui");
    treehashx1_wots_jasmin(root_jazz, ctx, idx_leaf, tree_addr_jazz, &info_jazz);
    puts("Chegou aqui v2");

    if (memcmp(root_jazz, root, SPX_N) != 0) {
        print_str_u8("Root Ref", root, SPX_N);
        print_str_u8("Root Jasmin", root_jazz, SPX_N);
    }

    assert(memcmp(root_jazz, root, SPX_N) == 0);
    assert(memcmp(tree_addr_jazz, tree_addr, 8 * sizeof(uint32_t)) == 0);
    assert(memcmp(info.wots_sig, info_jazz.wots_sig, SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES) == 0);
    assert(memcmp(info.wots_steps, info_jazz.wots_steps, SPX_WOTS_LEN * sizeof(uint32_t)) == 0);
    assert(memcmp(info.leaf_addr, info_jazz.leaf_addr, 8 * sizeof(uint32_t)) == 0);
    assert(memcmp(info.pk_addr, info_jazz.pk_addr, 8 * sizeof(uint32_t)) == 0);

#else
#ifdef TEST_TREEHASH_WOTS
    treehashx1_wots_jasmin(root, ctx, idx_leaf, tree_addr, &info);
#else
    treehashx1_wots(root, ctx, idx_leaf, tree_addr, &info);
#endif
#endif
}

/* Compute root node of the top-most subtree. */
void merkle_gen_root(unsigned char *root, const spx_ctx *ctx) {
    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one treehash routine that computes both root and path
       in one function. */
    unsigned char auth_path[SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES];
    uint32_t top_tree_addr[8] = {0};
    uint32_t wots_addr[8] = {0};

#ifdef TEST_ADDRESS
    set_layer_addr_jazz(top_tree_addr, SPX_D - 1);
    set_layer_addr_jazz(wots_addr, SPX_D - 1);
#else
    set_layer_addr(top_tree_addr, SPX_D - 1);
    set_layer_addr(wots_addr, SPX_D - 1);
#endif

    merkle_sign(auth_path, root, ctx, wots_addr, top_tree_addr, (uint32_t)~0);
}
