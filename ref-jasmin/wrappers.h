#ifndef WRAPPERS_H
#define WRAPPERS_H

#include <stddef.h>
#include <stdint.h>

#include "context.h"

// separate treehash => easier to test
void treehashx1_fors(unsigned char *root, unsigned char *auth_path, const spx_ctx *ctx, uint32_t leaf_idx,
                     uint32_t idx_offset, uint32_t tree_height, uint32_t tree_addr[8], void *info);

void treehashx1_wots(unsigned char *root, unsigned char *auth_path, const spx_ctx *ctx, uint32_t leaf_idx,
                     uint32_t idx_offset, uint32_t tree_height, uint32_t tree_addr[8], void *info);

#ifdef TEST_COMPUTE_ROOT
void compute_root_jasmin(uint8_t *root, const uint8_t *leaf, uint32_t leaf_idx, uint32_t idx_offset,
                         const uint8_t *auth_path, uint32_t tree_height, const spx_ctx *ctx, uint32_t addr[8]);
#endif

#ifdef TEST_HASH_MESSAGE
void hash_message_jasmin(uint8_t *digest, uint64_t *tree, uint32_t *leaf_idx, const uint8_t *R, const uint8_t *pk,
                         const uint8_t *m, size_t mlen);
#endif

#endif  // WRAPPERS_H
