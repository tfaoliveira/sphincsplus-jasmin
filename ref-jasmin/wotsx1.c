#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "hash.h"
#include "thash.h"
#include "wots.h"
#include "wotsx1.h"
#include "address.h"
#include "params.h"

/*
 * This generates a WOTS public key
 * It also generates the WOTS signature if leaf_info indicates
 * that we're signing with this WOTS key
 */
void wots_gen_leafx1(unsigned char *dest,
                   const spx_ctx *ctx,
                   uint32_t leaf_idx, void *v_info) {
    struct leaf_info_x1 *info = v_info;
    uint32_t *leaf_addr = info->leaf_addr;
    uint32_t *pk_addr = info->pk_addr;
    unsigned int i, k;
    unsigned char pk_buffer[ SPX_WOTS_BYTES ] = {0};
    unsigned char *buffer;
    uint32_t wots_k_mask;

    if (leaf_idx == info->wots_sign_leaf) {
        wots_k_mask = 0;
    } else {
        wots_k_mask = (uint32_t)~0;
    }

    set_keypair_addr( leaf_addr, leaf_idx );
    set_keypair_addr( pk_addr, leaf_idx );

    for (i = 0, buffer = pk_buffer; i < SPX_WOTS_LEN; i++, buffer += SPX_N) {
        uint32_t wots_k = info->wots_steps[i] | wots_k_mask;

        set_chain_addr(leaf_addr, i);
        set_hash_addr(leaf_addr, 0);
        set_type(leaf_addr, SPX_ADDR_TYPE_WOTSPRF);

        prf_addr(buffer, ctx, leaf_addr);

        set_type(leaf_addr, SPX_ADDR_TYPE_WOTS);

        for (k=0;; k++) {
            if (k == wots_k) {
                memcpy( info->wots_sig + i * SPX_N, buffer, SPX_N );
            }

            if (k == SPX_WOTS_W - 1) break;

            set_hash_addr(leaf_addr, k);

            thash(buffer, buffer, 1, ctx, leaf_addr);
        }
    }

    thash(dest, pk_buffer, SPX_WOTS_LEN, ctx, pk_addr);
}
