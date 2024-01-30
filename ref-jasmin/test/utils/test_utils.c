#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "context.h"
#include "macros.h"
#include "notrandombytes.c"
#include "params.h"
#include "print.c"
#include "utils.h"

#ifndef PARAMS
#define PARAMS sphincs - shake - 128f
#endif

#ifndef THASH
#define THASH simple
#endif

#ifndef TESTS
#define TESTS 1000
#endif

#ifndef MAX_TREE_HEIGHT
#define MAX_TREE_HEIGHT 20
#endif

void test_compute_root(void);
void test_wrapper(void);
void test_api(void);

/*
target function:
inline fn __compute_root(
  reg ptr u8[SPX_N] root,
  reg ptr u8[SPX_N] leaf,
  reg u32 leaf_idx,
  reg u32 idx_offset,
  reg u64 auth_path,
  reg u32 tree_height,
  reg ptr u8[SPX_N] pub_seed,
  reg ptr u32[8] addr)
  ->
  reg ptr u8[SPX_N],
  reg ptr u32[8]
*/

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

// implementation from, for instance, ../../thash_shake_robust.c /
// ../../thash_shake_simple.c
void compute_root(unsigned char *root, const unsigned char *leaf, uint32_t leaf_idx, uint32_t idx_offset,
                  const unsigned char *auth_path, uint32_t tree_height, const spx_ctx *ctx, uint32_t addr[8]);

#include "utils.c"

static void alloc_arguments(void *arguments[8],
                            //
                            uint8_t **root,         // [SPX_N]
                            uint8_t **leaf,         // [SPX_N]
                            uint32_t *leaf_idx,     //
                            uint32_t *idx_offset,   //
                            uint8_t **auth_path,    // [SPX_N * tree_height]
                            uint32_t *tree_height,  //
                            uint32_t th,
                            uint8_t **pub_seed,  // [SPX_N] for pub_seed
                            int pub_seed_alloc,  // 1 to calloc it; 0 otherwise
                            uint32_t **addr      // [8]
) {
    *root = calloc(SPX_N, sizeof(uint8_t));
    *leaf = calloc(SPX_N, sizeof(uint8_t));
    *leaf_idx = 0;
    *idx_offset = 0;
    *auth_path = calloc(SPX_N * th, sizeof(uint8_t));
    *tree_height = th;
    if (pub_seed_alloc == 1) {
        *pub_seed = calloc(SPX_N, sizeof(uint8_t));
    }
    *addr = calloc(8, sizeof(uint32_t));

    arguments[0] = (void *)*root;
    arguments[1] = (void *)*leaf;
    arguments[2] = (void *)leaf_idx;
    arguments[3] = (void *)idx_offset;
    arguments[4] = (void *)*auth_path;
    arguments[5] = (void *)tree_height;
    arguments[6] = (void *)*pub_seed;
    arguments[7] = (void *)*addr;
}

static void random_arguments(void *arguments0[8], void *arguments1[8], uint32_t tree_height) {
    // init arguments 0
    randombytes(arguments0[0], SPX_N * sizeof(uint8_t));  // root
    randombytes(arguments0[1], SPX_N * sizeof(uint8_t));  // leaf
    randombytes(arguments0[2], sizeof(uint32_t));         // leaf_idx
    randombytes(arguments0[3], sizeof(uint32_t));         // idx_offset
    randombytes(arguments0[4],
                SPX_N * tree_height * sizeof(uint8_t));  // auth_path
    *(uint32_t *)(arguments0[5]) = tree_height;
    randombytes(arguments0[6], SPX_N * sizeof(uint8_t));  // pub_seed
    randombytes(arguments0[7], 8 * sizeof(uint32_t));     // addr

    // copy to arguments 1
    memcpy(arguments1[0], arguments0[0], SPX_N * sizeof(uint8_t));  // root
    memcpy(arguments1[1], arguments0[1], SPX_N * sizeof(uint8_t));  // leaf
    *(uint32_t *)(arguments1[2]) = *(uint32_t *)(arguments0[2]);    // leaf_idx
    *(uint32_t *)(arguments1[3]) = *(uint32_t *)(arguments0[3]);    // idx_offset
    memcpy(arguments1[4], arguments0[4],
           SPX_N * tree_height * sizeof(uint8_t));                // auth_path
    *(uint32_t *)(arguments1[5]) = *(uint32_t *)(arguments0[5]);  // tree_height

    memcpy(arguments1[6], arguments0[6], SPX_N * sizeof(uint8_t));  // pub_seed

    memcpy(arguments1[7], arguments0[7], 8 * sizeof(uint32_t));  // addr
}

static void free_arguments(void *arguments[8], int pub_seed_alloc) {
    free(arguments[0]);
    arguments[0] = NULL;
    free(arguments[1]);
    arguments[1] = NULL;
    free(arguments[4]);
    arguments[4] = NULL;
    if (pub_seed_alloc == 1) {
        free(arguments[6]);
        arguments[6] = NULL;
    }
    free(arguments[7]);
    arguments[7] = NULL;
}

void test_compute_root() {
    // pointers via *alloc to check with valgrind
    uint8_t *root0, *root1;  // [SPX_N]
    uint8_t *leaf0, *leaf1;  // [SPX_N]
    uint32_t leaf_idx0, leaf_idx1;
    uint32_t idx_offset0, idx_offset1;
    uint8_t *auth_path0, *auth_path1;  // [SPX_N * tree_height]
    uint32_t th, tree_height0, tree_height1;
    uint32_t *addr0, *addr1;  // [8]

    uint8_t *pub_seed0;
    uint8_t *pub_seed1;
    spx_ctx ctx;

    pub_seed1 = &(ctx.pub_seed[0]);

    void *arguments0[8], *arguments1[8];
    int t;

    printf("\nPARAMS: %s\n", xstr(PARAMS));

    for (th = 1; th <= MAX_TREE_HEIGHT; th += 1) {
        alloc_arguments(arguments0, &root0, &leaf0, &leaf_idx0, &idx_offset0, &auth_path0, &tree_height0, th,
                        &pub_seed0, 1, &addr0);
        alloc_arguments(arguments1, &root1, &leaf1, &leaf_idx1, &idx_offset1, &auth_path1, &tree_height1, th,
                        &pub_seed1, 0, &addr1);

        for (t = 0; t < TESTS; t++) {
            random_arguments(arguments0, arguments1, th);

            // check if input variables are equal
            assert(leaf_idx0 == leaf_idx1);
            assert(*(uint32_t *)(arguments0[2]) == leaf_idx1);
            assert(idx_offset0 == idx_offset1);
            assert(*(uint32_t *)(arguments0[3]) == idx_offset1);
            assert(tree_height0 == tree_height1);
            assert(*(uint32_t *)(arguments0[5]) == tree_height1);

            compute_root_jazz(arguments0);
            compute_root(root1, leaf1, leaf_idx1, idx_offset1, auth_path1, tree_height1, &ctx, addr1);

            assert(memcmp(root0, root1, SPX_N * sizeof(uint8_t)) == 0);
            assert(memcmp(leaf0, leaf1, SPX_N * sizeof(uint8_t)) == 0);
            assert(memcmp(auth_path0, auth_path1, SPX_N * th * sizeof(uint8_t)) == 0);
            assert(memcmp(pub_seed0, pub_seed1, SPX_N * sizeof(uint8_t)) == 0);
            assert(memcmp(pub_seed0, ctx.pub_seed, SPX_N * sizeof(uint8_t)) == 0);
            assert(memcmp(addr0, addr1, 8 * sizeof(uint32_t)) == 0);
        }

        printf(" PASS: compute_root = { tree_height : %d }\n", th);

        free_arguments(arguments0, 1);
        free_arguments(arguments1, 0);
    }
}

void test_wrapper(void) {
    bool debug = true;

    uint8_t root_ref[SPX_N], root_jazz[SPX_N];
    uint8_t leaf_ref[SPX_N], leaf_jazz[SPX_N];
    uint32_t leaf_idx_ref, leaf_idx_jazz;
    uint32_t idx_offset_ref, idx_offset_jazz;

    uint32_t tree_height_ref, tree_height_jazz;
    uint32_t addr_ref[8], addr_jazz[8];
    spx_ctx ctx_ref, ctx_jazz;

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("Test Wrapper %d/%d\n", i, TESTS);
        }

        for (uint32_t tree_height = 1; tree_height <= MAX_TREE_HEIGHT; tree_height++) {
            uint8_t auth_path_ref[SPX_N * tree_height], auth_path_jazz[SPX_N * tree_height];

            randombytes(root_ref, SPX_N * sizeof(uint8_t));
            memcpy(root_jazz, root_ref, SPX_N * sizeof(uint8_t));

            randombytes(leaf_ref, SPX_N * sizeof(uint8_t));
            memcpy(leaf_jazz, leaf_ref, SPX_N * sizeof(uint8_t));

            randombytes(&leaf_idx_ref, sizeof(uint32_t));
            memcpy(&leaf_idx_ref, &leaf_idx_jazz, sizeof(uint32_t));

            randombytes(&idx_offset_jazz, sizeof(uint32_t));
            memcpy(&idx_offset_jazz, &idx_offset_ref, sizeof(uint32_t));

            randombytes(auth_path_ref, SPX_N * tree_height * sizeof(uint8_t));
            memcpy(auth_path_jazz, auth_path_ref, SPX_N * tree_height * sizeof(uint8_t));

            randombytes(&ctx_ref.pub_seed, SPX_N * sizeof(uint8_t));
            memcpy(&ctx_jazz.pub_seed, &ctx_ref.pub_seed, SPX_N * sizeof(uint8_t));

            randombytes(addr_ref, 8 * sizeof(uint32_t));
            memcpy(addr_jazz, addr_ref, 8 * sizeof(uint32_t));

            // Check if inputs are equal
            assert(leaf_idx_ref == leaf_idx_jazz);
            assert(idx_offset_ref == idx_offset_jazz);
            assert(memcmp(root_ref, root_jazz, SPX_N * sizeof(uint8_t)) == 0);
            assert(memcmp(leaf_ref, leaf_jazz, SPX_N * sizeof(uint8_t)) == 0);
            assert(memcmp(auth_path_ref, auth_path_jazz, SPX_N * tree_height * sizeof(uint8_t)) == 0);
            assert(memcmp(&ctx_ref.pub_seed, &ctx_jazz.pub_seed, SPX_N * sizeof(uint8_t)) == 0);
            assert(memcmp(addr_ref, addr_jazz, 8 * sizeof(uint32_t)) == 0);

            compute_root(root_ref, leaf_ref, leaf_idx_ref, idx_offset_ref, auth_path_ref, tree_height, &ctx_ref,
                         addr_ref);
            compute_root_jasmin(root_jazz, leaf_jazz, leaf_idx_jazz, idx_offset_jazz, auth_path_jazz, tree_height,
                                &ctx_jazz, addr_jazz);

            // Check if the outputs are equal
            assert(memcmp(root_ref, root_jazz, SPX_N * sizeof(uint8_t)) == 0);
            if (memcmp(root_ref, root_jazz, SPX_N * sizeof(uint8_t)) != 0) {
                print_str_u8("root ref", root_ref, SPX_N);
                print_str_u8("root jazz", root_jazz, SPX_N);
            }

            assert(memcmp(leaf_ref, leaf_jazz, SPX_N * sizeof(uint8_t)) == 0);
            assert(memcmp(auth_path_ref, auth_path_jazz, SPX_N * tree_height * sizeof(uint8_t)) == 0);
            assert(memcmp(&ctx_ref.pub_seed, &ctx_jazz.pub_seed, SPX_N * sizeof(uint8_t)) == 0);
            assert(memcmp(addr_ref, addr_jazz, 8 * sizeof(uint32_t)) == 0);
        }
    }
}

void test_api(void) {
    bool debug = true;

#define MAX_MESSAGE_LENGTH 32
#define TESTS 100

    uint8_t secret_key[CRYPTO_SECRETKEYBYTES];
    uint8_t public_key[CRYPTO_PUBLICKEYBYTES];

    uint8_t signature[CRYPTO_BYTES];
    size_t signature_length;

    uint8_t message[MAX_MESSAGE_LENGTH];

    for (int i = 0; i < TESTS; i++) {
        // clang-format off
        if (debug) { printf("Test %d/%d\n", i, TESTS); }

        for (size_t message_length = 10; message_length < MAX_MESSAGE_LENGTH; message_length++) {
            // note: the 'real' test is in .c files and it is activated when TEST_ADDRESS is defined
            randombytes(message, message_length);
            crypto_sign_keypair(public_key, secret_key);
            crypto_sign_signature(signature, &signature_length, message, message_length, secret_key);
            assert(crypto_sign_verify(signature, signature_length, message, message_length, public_key) == 0);
        }
    }

#undef MAX_MESSAGE_LENGTH
}



int main(void)
{
  test_compute_root();
  test_wrapper();
  test_api();
  return 0;
}
