#include <string.h>

#include "utils.h"
#include "utilsx1.h"
#include "params.h"
#include "thash.h"
#include "address.h"

void treehashx1(unsigned char *root, unsigned char *auth_path,
                const spx_ctx* ctx,
                uint32_t leaf_idx, uint32_t idx_offset,
                uint32_t tree_height,
                void (*gen_leaf)(
                   unsigned char*,
                   const spx_ctx*,
                   uint32_t idx, void *info),
                uint32_t tree_addr[8],
                void *info)
{
    SPX_VLA(uint8_t, stack, tree_height*SPX_N);
    uint32_t idx;
    uint32_t max_idx = (uint32_t)((1 << tree_height) - 1);
    for (idx = 0;; idx++) {
        unsigned char current[2*SPX_N] = {0}; 

        gen_leaf( &current[SPX_N], ctx, idx + idx_offset, info );
        
        uint32_t internal_idx_offset = idx_offset;
        uint32_t internal_idx = idx;
        uint32_t internal_leaf = leaf_idx;
        uint32_t h;   
        for (h=0;; h++, internal_idx >>= 1, internal_leaf >>= 1) {

            if (h == tree_height) {
                memcpy( root, &current[SPX_N], SPX_N );
                return;
            }

            if ((internal_idx ^ internal_leaf) == 0x01) {
                memcpy( &auth_path[ h * SPX_N ],
                        &current[SPX_N],
                        SPX_N );
            }

            if ((internal_idx & 1) == 0 && idx < max_idx) {
                break;
            }

            internal_idx_offset >>= 1;
            set_tree_height(tree_addr, h + 1);
            set_tree_index(tree_addr, internal_idx/2 + internal_idx_offset );

            unsigned char *left = &stack[h * SPX_N];
            memcpy( &current[0], left, SPX_N );
            thash( &current[1 * SPX_N],
                   &current[0 * SPX_N],
                   2, ctx, tree_addr);
        }
        memcpy( &stack[h * SPX_N], &current[SPX_N], SPX_N);
    }
}
