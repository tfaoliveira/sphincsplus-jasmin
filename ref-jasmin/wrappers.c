#include "wrappers.h"

#include <assert.h>
#include <stdio.h>

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

extern void hash_message_jazz(uint8_t *digest, uint64_t *tree, uint32_t *leaf_idx, const args * _args,
                              const uint8_t *msg, size_t msg_len);

void hash_message_jasmin(uint8_t *digest, uint64_t *tree, uint32_t *leaf_idx, const uint8_t *R, const uint8_t *pk,
                         const uint8_t *m, size_t mlen) {
    args _args;
    memcpy(_args.R, R, SPX_N);
    memcpy(_args.pk, pk, SPX_PK_BYTES);

    hash_message_jazz(digest, tree, leaf_idx, &_args, m, mlen);
}
#endif
