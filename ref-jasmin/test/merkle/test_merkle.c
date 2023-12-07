#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "context.h"
#include "hash.h"
#include "macros.h"
#include "merkle.h"
#include "notrandombytes.c"
#include "params.h"
#include "print.c"
#include "wots.h"

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
#define TESTS 1000
#endif

extern void merkle_gen_root_jazz(uint8_t *root, const uint8_t *pub_seed, const uint8_t *sk_seed);

void test_merkle_gen_root(void) {
    unsigned char root_ref[SPX_N];
    uint8_t root_jazz[SPX_N];
    spx_ctx ctx;

    for (int t = 0; t < TESTS; t++) {
        memset(root_ref, 0, SPX_N);
        memset(root_jazz, 0, SPX_N);

        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);

        merkle_gen_root(root_ref, &ctx);
        merkle_gen_root_jazz(root_jazz, ctx.pub_seed, ctx.sk_seed);

        if (memcmp(root_ref, root_jazz, SPX_N) != 0) {
            print_str_u8("ref", (uint8_t *)root_ref, SPX_N);
            print_str_u8("jazz", (uint8_t *)root_jazz, SPX_N);
        }

        assert(memcmp(root_ref, root_jazz, SPX_N) == 0);
    }
}

int main(void) {
    test_merkle_gen_root();
    printf("Pass: merkle { hash = %s ; params = %s }\n", xstr(HASH), xstr(PARAM));
    return 0;
}
