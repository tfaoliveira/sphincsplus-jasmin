#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "context.h"
#include "macros.h"
#include "notrandombytes.c"
#include "print.c"
#include "wotsx1.h"

#ifndef HASH
#define HASH shake
#endif

#ifndef PARAM
#define PARAM 128f
#endif

#ifndef TESTS
#define TESTS 100
#endif

extern void wots_gen_leafx1(unsigned char *dest, const spx_ctx *ctx, uint32_t leaf_idx,
                            void *v_info);
extern void wots_gen_leafx1_jazz(uint8_t *dest, const uint8_t *pub_seed, const uint8_t *sk_seed,
                                 uint32_t leaf_idx, struct leaf_info_x1 *info);

static spx_ctx init_ctx(void) {
    spx_ctx ctx;
    randombytes(ctx.pub_seed, SPX_N);
    randombytes(ctx.sk_seed, SPX_N);
    return ctx;
}

static struct leaf_info_x1 init_leaf_info(void) {
    struct leaf_info_x1 info;
    unsigned steps[SPX_WOTS_LEN] = {0};
    uint32_t addr[8];

    randombytes((uint8_t *)addr, sizeof(uint32_t) * 8);
    info.wots_sig = 0;
    info.wots_sign_leaf = ~0u;
    info.wots_steps = steps;
    memcpy(&info.leaf_addr[0], addr, 32);
    memcpy(&info.pk_addr[0], addr, 32);
    return info;
}

int main(void) {
    unsigned char dest_ref[SPX_N];
    uint8_t dest_jazz[SPX_N];
    uint32_t leaf_idx;
    spx_ctx ctx;
    struct leaf_info_x1 leaf_ref, leaf_jazz;

    for (int i = 0; i < TESTS; i++) {
        ctx = init_ctx();
        randombytes((uint8_t *)dest_ref, SPX_N * sizeof(unsigned char));
        randombytes((uint8_t *)&leaf_idx, sizeof(uint32_t));
        leaf_ref = init_leaf_info();
        memcpy(&leaf_jazz, &leaf_ref, sizeof(struct leaf_info_x1));

        wots_gen_leafx1(dest_ref, &ctx, leaf_idx, &leaf_ref);
        wots_gen_leafx1_jazz(dest_jazz, ctx.pub_seed, ctx.sk_seed, leaf_idx, &leaf_jazz);

        assert(memcmp(dest_ref, dest_jazz, SPX_N));
        assert(memcmp(&leaf_ref, &leaf_jazz, sizeof(struct leaf_info_x1)));
    }

    puts("Pass wotsx1");
    return 0;
}
