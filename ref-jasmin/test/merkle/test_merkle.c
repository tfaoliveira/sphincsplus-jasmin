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
extern void merkle_sign_jazz(void *args);

// args:
// uint8_t *sig
// unsigned char *root
// const uint8_t *pub_seed
// const uint8_t *sk_seed
// uint32_t wots_addr[8]
// uint32_t tree_addr[8]
// uint32_t idx_leaf

static spx_ctx init_ctx(void) {
    spx_ctx ctx;
    randombytes(ctx.pub_seed, SPX_N);
    randombytes(ctx.sk_seed, SPX_N);
    return ctx;
}

static void alloc_arguments(  //
    void *arguments[7],
    //
    uint8_t **sig,         //
    uint8_t **root,        //
    uint8_t **pub_seed,    //
    uint8_t **sk_seed,     //
    uint32_t **wots_addr,  //
    uint32_t **tree_addr,  //
    uint32_t *idx_leaf     //
) {
    *sig = calloc(SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES, sizeof(uint8_t));
    *root = calloc(SPX_N, sizeof(uint8_t));
    *pub_seed = calloc(SPX_N, sizeof(uint8_t));
    *sk_seed = calloc(SPX_N, sizeof(uint8_t));
    *wots_addr = calloc(8, sizeof(uint32_t));
    *tree_addr = calloc(8, sizeof(uint32_t));
    *idx_leaf = 0;

    arguments[0] = (void *)*sig;
    arguments[1] = (void *)*root;
    arguments[2] = (void *)*pub_seed;
    arguments[3] = (void *)*sk_seed;
    arguments[4] = (void *)*wots_addr;
    arguments[5] = (void *)*tree_addr;
    arguments[6] = (void *)idx_leaf;
}

static void random_arguments(void *arguments[7]) {}

static void free_arguments(void *arguments[7]) {
    for (size_t i = 0; i < 7; i++) {
        if (arguments[i] != NULL) {
            free(arguments[i]);
            arguments[i] = NULL;
        }
    }
}

void test_merkle_sign(void) {
    uint8_t sig0[SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES];
    uint8_t sig1[SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES];

    // TODO: Call to alloc arguments

    for (int t = 0; t < TESTS; t++) {
        // TODO: Call to random arguments
    }

    // TODO: Call to free arguments
}

void test_merkle_gen_root(void) {
    unsigned char root0[SPX_N];
    uint8_t root1[SPX_N];
    spx_ctx ctx;

    for (int t = 0; t < TESTS; t++) {
        memset(root0, 0, SPX_N);
        memset(root1, 0, SPX_N);
        ctx = init_ctx();

        merkle_gen_root(root0, &ctx);
        // merkle_gen_root_jazz(root1, ctx.pub_seed, ctx.sk_seed);
        assert(memcmp(root0, root1, SPX_N) == 0);
    }
}

int main(void) {
    test_merkle_sign();
    test_merkle_gen_root();
    printf("Pass: merkle { }\n");
    return 0;
}
