#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "context.h"
#include "macros.h"
#include "notrandombytes.c"
#include "print.c"

#ifndef HASH
#define HASH shake
#endif

#ifndef PARAM
#define PARAM 128f
#endif

#ifndef MSG_LEN
#define MSG_LEN 64
#endif


#ifndef TESTS
#define TESTS 100
#endif

extern void wots_gen_leafx1(unsigned char *dest, const spx_ctx *ctx, uint32_t leaf_idx,
                            void *v_info);
// TODO: FIXME: Make leafidx a uint32_t instead of a pointer
extern void wots_gen_leafx1_jazz(uint8_t *dest, const uint8_t *pub_seed, const uint8_t *sk_seed,
                                 uint32_t *leaf_idx, struct leaf_info_x1 *info);

// struct leaf_info_x1 {
//     unsigned char *wots_sig; = 0
//     uint32_t wots_sign_leaf; /* The index of the WOTS we're using to sign */
//     uint32_t *wots_steps; u32[SPX_WOTS_LEN]
//     uint32_t leaf_addr[8];
//     uint32_t pk_addr[8];
// };

static spx_ctx init_ctx(void) {
    spx_ctx ctx;
    randombytes(ctx.pub_seed, SPX_N);
    randombytes(ctx.sk_seed, SPX_N);
    return ctx;
}

static struct leaf_info_x1 init_leaf_info(void) {
    struct leaf_info_x1 info;
    randombytes((uint8_t*)info.wots_sig, sizeof(unsigned char));
    randombytes((uint8_t*)info.wots_sign_leaf, sizeof(uint32_t));
    randombytes((uint8_t*)info.wots_steps, sizeof(uint32_t) * SPX_WOTS_LEN);
    randombytes((uint8_t*)info.leaf_addr, sizeof(uint32_t) * 8);
    randombytes((uint8_t*)info.pk_addr, sizeof(uint32_t) * 8);
    return info;
}

int main(void) {
    unsigned char dest0[SPX_N];
    uint8_t dest1[SPX_N];
    spx_ctx ctx;
    uint32_t leaf_idx;
    struct leaf_info_x1 info;

    // Suppress compiler warniings
    (void) dest0;
    (void) dest1;
    (void) leaf_idx;


    for (int i = 0; i<TESTS;i++) {
        ctx = init_ctx();
        info = init_leaf_info();
        (void) ctx;
        (void) info;

    }
    printf("Pass wotsx1\n");
    return 0;
}