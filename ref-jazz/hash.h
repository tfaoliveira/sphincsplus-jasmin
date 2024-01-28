#ifndef SPX_HASH_H
#define SPX_HASH_H

#include <stdint.h>
#include "context.h"
#include "params.h"

#define hash_message SPX_NAMESPACE(hash_message)
void hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const spx_ctx *ctx);
#endif
