#include "wrappers.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "address.h"
#include "fors.h"
#include "params.h"
#include "print.h"
#include "thash.h"
#include "utils.h"
#include "wotsx1.h"

void treehashx1_fors(unsigned char *root, unsigned char *auth_path, const spx_ctx *ctx, uint32_t leaf_idx,
                     uint32_t idx_offset, uint32_t tree_height, uint32_t tree_addr[8], void *info) {
    /* This is where we keep the intermediate nodes */
    uint8_t stack[tree_height * SPX_N];

    uint32_t idx;
    uint32_t max_idx = (uint32_t)((1 << tree_height) - 1);
    for (idx = 0;; idx++) {
        unsigned char current[2 * SPX_N]; /* Current logical node is at */
                                          /* index[SPX_N].  We do this to minimize the number of copies */
                                          /* needed during a thash */

#ifdef TEST_FORS_GEN_LEAF
        fors_gen_leafx1_jazz(&current[SPX_N], ctx->pub_seed, ctx->sk_seed, idx + idx_offset, info);
#else
        fors_gen_leafx1(&current[SPX_N], ctx, idx + idx_offset, info);
#endif

        /* Now combine the freshly generated right node with previously */
        /* generated left ones */
        uint32_t internal_idx_offset = idx_offset;
        uint32_t internal_idx = idx;
        uint32_t internal_leaf = leaf_idx;
        uint32_t h; /* The height we are in the Merkle tree */
        for (h = 0;; h++, internal_idx >>= 1, internal_leaf >>= 1) {
            /* Check if we hit the top of the tree */
            if (h == tree_height) {
                /* We hit the root; return it */
                memcpy(root, &current[SPX_N], SPX_N);
                return;
            }

            /*
             * Check if the node we have is a part of the
             * authentication path; if it is, write it out
             */
            if ((internal_idx ^ internal_leaf) == 0x01) {
                memcpy(&auth_path[h * SPX_N], &current[SPX_N], SPX_N);
            }

            /*
             * Check if we're at a left child; if so, stop going up the stack
             * Exception: if we've reached the end of the tree, keep on going
             * (so we combine the last 4 nodes into the one root node in two
             * more iterations)
             */
            if ((internal_idx & 1) == 0 && idx < max_idx) {
                break;
            }

            /* Ok, we're at a right node */
            /* Now combine the left and right logical nodes together */

            /* Set the address of the node we're creating. */
            internal_idx_offset >>= 1;

#ifdef TEST_ADDRESS
            set_tree_height_jazz(tree_addr, h + 1);
            set_tree_index_jazz(tree_addr, internal_idx / 2 + internal_idx_offset);
#else
            set_tree_height(tree_addr, h + 1);
            set_tree_index(tree_addr, internal_idx / 2 + internal_idx_offset);
#endif

            unsigned char *left = &stack[h * SPX_N];
            memcpy(&current[0], left, SPX_N);
            thash(&current[1 * SPX_N], &current[0 * SPX_N], 2, ctx, tree_addr);
        }

        /* We've hit a left child; save the current for when we get the */
        /* corresponding right right */
        memcpy(&stack[h * SPX_N], &current[SPX_N], SPX_N);
    }
}

#ifdef TEST_WOTS_GEN_LEAF
extern void wots_gen_leafx1_jazz(void *args);

static void wots_gen_leafx1_jasmin(unsigned char *dest, const spx_ctx *ctx, uint32_t leaf_idx, void *info) {
    void *arguments[9];

    arguments[0] = (void *)dest;
    arguments[1] = (void *)ctx->pub_seed;
    arguments[2] = (void *)ctx->sk_seed;
    arguments[3] = (void *)&leaf_idx;
    arguments[4] = (void *)((struct leaf_info_x1 *)info)->wots_sig;
    arguments[5] = (void *)&((struct leaf_info_x1 *)info)->wots_sign_leaf;
    arguments[6] = (void *)((struct leaf_info_x1 *)info)->wots_steps;
    arguments[7] = (void *)((struct leaf_info_x1 *)info)->leaf_addr;
    arguments[8] = (void *)((struct leaf_info_x1 *)info)->pk_addr;

    wots_gen_leafx1_jazz(arguments);
}
#endif

// NOTE: Removed index offset because it is always 0
// NOTE: Removed index offset because it is always SPX_TREE_HEIGHT
// NOTE: Removed iinternal index offset because it is always 0 (because index offset = 0)
void treehashx1_wots(unsigned char *root, unsigned char *auth_path, const spx_ctx *ctx, uint32_t leaf_idx,
                     uint32_t tree_addr[8], void *info) {
    // print_str_u8("root ref", root, SPX_N);
    // print_str_u8("auth path ref", auth_path, SPX_TREE_HEIGHT * SPX_N);
    // print_str_u8("pub seed ref", ctx->pub_seed, SPX_N);
    // print_str_u8("sk seed ref", ctx->sk_seed, SPX_N);
    // print_str_u8("leaf idx ref", (uint8_t *)&leaf_idx, sizeof(uint32_t));
    // print_str_u8("tree addr ref", (uint8_t *)tree_addr, 8 * sizeof(uint32_t));
    // print_str_u8("wots sig ref", (uint8_t *)((struct leaf_info_x1 *)info)->wots_sig,
    //              SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES);
    // print_str_u8("wots sign leaf ref", (uint8_t *)&((struct leaf_info_x1 *)info)->wots_sign_leaf, sizeof(uint32_t));
    // print_str_u8("wots steps ref", (uint8_t *) ((struct leaf_info_x1 *)info)->wots_steps, SPX_WOTS_LEN *
    // sizeof(uint32_t));
    // print_str_u8("leaf addr ref", (uint8_t *)((struct leaf_info_x1 *)info)->leaf_addr, 8 * sizeof(uint32_t));
    // print_str_u8("pk addr ref", (uint8_t *)((struct leaf_info_x1 *)info)->pk_addr, 8 * sizeof(uint32_t));

    uint8_t stack[SPX_TREE_HEIGHT * SPX_N];

    uint32_t idx;
    uint32_t max_idx = (uint32_t)((1 << SPX_TREE_HEIGHT) - 1);
    for (idx = 0;; idx++) {
        unsigned char current[2 * SPX_N]; /* Current logical node is at */
                                          /* index[SPX_N].  We do this to minimize the number of copies */
                                          /* needed during a thash */

#ifdef DEBUG_WOTSX1
        puts("Debug wots gen leaf");

        uint8_t sig_jazz[SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N];
        unsigned char current_jazz[2 * SPX_N];
        uint32_t steps[SPX_WOTS_LEN];

        struct leaf_info_x1 info_jazz;

        memcpy(current_jazz, current, 2 * SPX_N);

        memcpy(steps, ((struct leaf_info_x1 *)info)->wots_steps, SPX_WOTS_LEN * sizeof(uint32_t));
        memcpy(sig_jazz, ((struct leaf_info_x1 *)info)->wots_sig, SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N);

        info_jazz.wots_sig = sig_jazz;
        info_jazz.wots_sign_leaf = ((struct leaf_info_x1 *)info)->wots_sign_leaf;
        info_jazz.wots_steps = steps;
        memcpy(info_jazz.leaf_addr, ((struct leaf_info_x1 *)info)->leaf_addr, 8 * sizeof(uint32_t));
        memcpy(info_jazz.pk_addr, ((struct leaf_info_x1 *)info)->pk_addr, 8 * sizeof(uint32_t));

        assert(memcmp(current_jazz, current, 2 * SPX_N) == 0);
        assert(memcmp(info_jazz.wots_sig, ((struct leaf_info_x1 *)info)->wots_sig,
                      SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N) == 0);
        assert(info_jazz.wots_sign_leaf == ((struct leaf_info_x1 *)info)->wots_sign_leaf);
        assert(memcmp(&info_jazz.wots_sign_leaf, &((struct leaf_info_x1 *)info)->wots_sign_leaf, sizeof(uint32_t)) ==
               0);
        assert(memcmp(info_jazz.wots_steps, ((struct leaf_info_x1 *)info)->wots_steps,
                      SPX_WOTS_LEN * sizeof(uint32_t)) == 0);
        assert(memcmp(info_jazz.leaf_addr, ((struct leaf_info_x1 *)info)->leaf_addr, 8 * sizeof(uint32_t)) == 0);
        assert(memcmp(info_jazz.pk_addr, ((struct leaf_info_x1 *)info)->pk_addr, 8 * sizeof(uint32_t)) == 0);

        wots_gen_leafx1_jasmin(&current_jazz[SPX_N], ctx, idx, &info_jazz);

        wots_gen_leafx1(&current[SPX_N], ctx, idx, info);

        assert(memcmp(current_jazz, current, 2 * SPX_N) == 0);
        assert(memcmp(info_jazz.wots_sig, ((struct leaf_info_x1 *)info)->wots_sig,
                      SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N) == 0);
        assert(info_jazz.wots_sign_leaf == ((struct leaf_info_x1 *)info)->wots_sign_leaf);
        assert(memcmp(&info_jazz.wots_sign_leaf, &((struct leaf_info_x1 *)info)->wots_sign_leaf, sizeof(uint32_t)) ==
               0);
        assert(memcmp(info_jazz.wots_steps, ((struct leaf_info_x1 *)info)->wots_steps,
                      SPX_WOTS_LEN * sizeof(uint32_t)) == 0);
        assert(memcmp(info_jazz.leaf_addr, ((struct leaf_info_x1 *)info)->leaf_addr, 8 * sizeof(uint32_t)) == 0);
        assert(memcmp(info_jazz.pk_addr, ((struct leaf_info_x1 *)info)->pk_addr, 8 * sizeof(uint32_t)) == 0);
#else

#ifdef TEST_WOTS_GEN_LEAF
        wots_gen_leafx1_jasmin(&current[SPX_N], ctx, idx, info);
#else
        wots_gen_leafx1(&current[SPX_N], ctx, idx, info);
#endif

#endif

        /* Now combine the freshly generated right node with previously */
        /* generated left ones */
        uint32_t internal_idx = idx;
        uint32_t internal_leaf = leaf_idx;
        uint32_t h; /* The height we are in the Merkle tree */
        for (h = 0;; h++, internal_idx >>= 1, internal_leaf >>= 1) {
            /* Check if we hit the top of the tree */
            if (h == SPX_TREE_HEIGHT) {
                /* We hit the root; return it */
                memcpy(root, &current[SPX_N], SPX_N);
                return;
            }

            /*
             * Check if the node we have is a part of the
             * authentication path; if it is, write it out
             */
            if ((internal_idx ^ internal_leaf) == 0x01) {
                memcpy(&auth_path[h * SPX_N], &current[SPX_N], SPX_N);
            }

            /*
             * Check if we're at a left child; if so, stop going up the stack
             * Exception: if we've reached the end of the tree, keep on going
             * (so we combine the last 4 nodes into the one root node in two
             * more iterations)
             */
            if ((internal_idx & 1) == 0 && idx < max_idx) {
                break;
            }

            /* Ok, we're at a right node */
            /* Now combine the left and right logical nodes together */

#ifdef TEST_ADDRESS
            set_tree_height_jazz(tree_addr, h + 1);
            set_tree_index_jazz(tree_addr, internal_idx / 2);
#else
            set_tree_height(tree_addr, h + 1);
            set_tree_index(tree_addr, internal_idx / 2);
#endif

            unsigned char *left = &stack[h * SPX_N];
            memcpy(&current[0], left, SPX_N);
            thash(&current[1 * SPX_N], &current[0 * SPX_N], 2, ctx, tree_addr);
        }

        /* We've hit a left child; save the current for when we get the */
        /* corresponding right right */
        memcpy(&stack[h * SPX_N], &current[SPX_N], SPX_N);
    }
}

#ifdef TEST_COMPUTE_ROOT
extern void compute_root_jazz(void *arguments[8]);
// arguments contains:
// root_ptr        = [arguments + 8*0];
// leaf_ptr        = [arguments + 8*1];
// leaf_idx_ptr    = [arguments + 8*2];
// idx_offset_ptr  = [arguments + 8*3];
// auth_path       = [arguments + 8*4];
// tree_height_ptr = [arguments + 8*5];
// pub_seed_ptr    = [arguments + 8*6];
// addr_ptr        = [arguments + 8*7];

void compute_root_jasmin(uint8_t *root, const uint8_t *leaf, uint32_t leaf_idx, uint32_t idx_offset,
                         const uint8_t *auth_path, uint32_t tree_height, const spx_ctx *ctx, uint32_t addr[8]) {
    void *arguments[8];

    arguments[0] = (void *)root;
    arguments[1] = (void *)leaf;
    arguments[2] = (void *)&leaf_idx;
    arguments[3] = (void *)&idx_offset;
    arguments[4] = (void *)auth_path;
    arguments[5] = (void *)&tree_height;
    arguments[6] = (void *)ctx->pub_seed;
    arguments[7] = (void *)addr;

    // assert inputs
    assert(*(uint32_t *)(arguments[2]) == leaf_idx);
    assert(*(uint32_t *)(arguments[3]) == idx_offset);
    assert(*(uint32_t *)(arguments[5]) == tree_height);

    compute_root_jazz(arguments);
}
#endif

#ifdef TEST_HASH_MESSAGE
typedef struct {
    uint8_t R[SPX_N];
    uint8_t pk[SPX_PK_BYTES];
} args;

extern void hash_message_jazz(uint8_t *digest, uint64_t *tree, uint32_t *leaf_idx, const args *_args,
                              const uint8_t *msg, size_t msg_len);

void hash_message_jasmin(uint8_t *digest, uint64_t *tree, uint32_t *leaf_idx, const uint8_t *R, const uint8_t *pk,
                         const uint8_t *m, size_t mlen) {
    args _args;
    memcpy(_args.R, R, SPX_N);
    memcpy(_args.pk, pk, SPX_PK_BYTES);

    hash_message_jazz(digest, tree, leaf_idx, &_args, m, mlen);
}
#endif

#ifdef TEST_TREEHASH_WOTS
extern void treehash_wots_jazz(void *arguments);

void treehashx1_wots_jasmin(unsigned char *root, unsigned char *auth_path, const spx_ctx *ctx, uint32_t leaf_idx,
                            uint32_t tree_addr[8], void *info) {
    // We remove the idx_offset parameter because it is always zero
    // We remove the tree_height parameter because it is always SPX_TREE_HEIGHT
    // These were also removed from the ref impl

    void *args[11];

    args[0] = (void *)root;
    args[1] = (void *)auth_path;
    args[2] = (void *)ctx->pub_seed;
    args[3] = (void *)ctx->sk_seed;
    args[4] = (void *)&leaf_idx;
    args[5] = (void *)tree_addr;
    args[6] = (void *)((struct leaf_info_x1 *)info)->wots_sig;
    args[7] = (void *)&((struct leaf_info_x1 *)info)->wots_sign_leaf;
    args[8] = (void *)((struct leaf_info_x1 *)info)->wots_steps;
    args[9] = (void *)((struct leaf_info_x1 *)info)->leaf_addr;
    args[10] = (void *)((struct leaf_info_x1 *)info)->pk_addr;

    treehash_wots_jazz(args);
}
#endif