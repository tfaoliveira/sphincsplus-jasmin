#include "wrappers.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "address.h"
#include "fors.h"
#include "params.h"
#include "thash.h"
#include "utils.h"

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
