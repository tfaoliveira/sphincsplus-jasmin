#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "macros.h"

#include "print.c"
#include "notrandombytes.c"

#include "context.h"

#ifndef TESTS
#define TESTS 1000
#endif

#ifndef MAX_TREE_HEIGHT
#define MAX_TREE_HEIGHT 20
#endif

#include "params.h"

void test_compute_root(void);

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


// implementation from, for instance, ../../thash_shake_robust.c / ../../thash_shake_simple.c
void compute_root(unsigned char *root, const unsigned char *leaf,
                  uint32_t leaf_idx, uint32_t idx_offset,
                  const unsigned char *auth_path, uint32_t tree_height,
                  const spx_ctx *ctx, uint32_t addr[8]);

#include "utils.c"

static void alloc_arguments(
  void *arguments[8],
  //
  uint8_t **root,        // [SPX_N]
  uint8_t **leaf,        // [SPX_N]
  uint32_t *leaf_idx,    //
  uint32_t *idx_offset,  // 
  uint8_t **auth_path,   // [SPX_N * tree_height]
  uint32_t *tree_height, // 
  uint32_t th,
  uint8_t **pub_seed,    // [SPX_N] for pub_seed
  int pub_seed_alloc,    // 1 to calloc it; 0 otherwise
  uint32_t **addr        // [8]
)
{
  *root = calloc(SPX_N, sizeof(uint8_t));
  *leaf = calloc(SPX_N, sizeof(uint8_t));
  *leaf_idx = 0;
  *idx_offset = 0;
  *auth_path = calloc(SPX_N * th, sizeof(uint8_t));
  *tree_height = th;
  if(pub_seed_alloc == 1)
  { *pub_seed = calloc(SPX_N, sizeof(uint8_t)); }
  *addr = calloc(8, sizeof(uint32_t));

  arguments[0] = (void*) *root;
  arguments[1] = (void*) *leaf;
  arguments[2] = (void*) leaf_idx;
  arguments[3] = (void*) idx_offset;
  arguments[4] = (void*) *auth_path;
  arguments[5] = (void*) tree_height;
  arguments[6] = (void*) *pub_seed;
  arguments[7] = (void*) *addr;
}

static void random_arguments(void *arguments0[8], void *arguments1[8], uint32_t tree_height)
{
  // init arguments 0
  randombytes(arguments0[0], SPX_N*sizeof(uint8_t)); // root
  randombytes(arguments0[1], SPX_N*sizeof(uint8_t)); // leaf
  randombytes(arguments0[2], sizeof(uint32_t)); // leaf_idx
  randombytes(arguments0[3], sizeof(uint32_t)); // idx_offset
  randombytes(arguments0[4], SPX_N*tree_height*sizeof(uint8_t)); // auth_path
  *(uint32_t*)(arguments0[5]) = tree_height;
  randombytes(arguments0[6], SPX_N*sizeof(uint8_t)); // pub_seed
  randombytes(arguments0[7], 8*sizeof(uint32_t)); // addr

  // copy to arguments 1
  memcpy(arguments1[0], arguments0[0], SPX_N*sizeof(uint8_t)); // root
  memcpy(arguments1[1], arguments0[1], SPX_N*sizeof(uint8_t)); // leaf
   *(uint32_t*)(arguments1[2]) = *(uint32_t*)(arguments0[2]); // leaf_idx
   *(uint32_t*)(arguments1[3]) = *(uint32_t*)(arguments0[3]); // idx_offset
  memcpy(arguments1[4], arguments0[4], SPX_N*tree_height*sizeof(uint8_t)); // auth_path
   *(uint32_t*)(arguments1[5]) = *(uint32_t*)(arguments0[5]); // tree_height

  memcpy(arguments1[6], arguments0[6], SPX_N*sizeof(uint8_t)); // pub_seed

  memcpy(arguments1[7], arguments0[7], 8*sizeof(uint32_t)); // addr
}

static void free_arguments(void *arguments[8], int pub_seed_alloc)
{
  free(arguments[0]); arguments[0] = NULL;
  free(arguments[1]); arguments[1] = NULL;
  free(arguments[4]); arguments[4] = NULL;
  if(pub_seed_alloc == 1)
  { free(arguments[6]); arguments[6] = NULL; }
  free(arguments[7]); arguments[7] = NULL;
}

void test_compute_root()
{
  // pointers via *alloc to check with valgrind
  uint8_t *root0, *root1; // [SPX_N]
  uint8_t *leaf0, *leaf1; // [SPX_N]
  uint32_t leaf_idx0, leaf_idx1;
  uint32_t idx_offset0, idx_offset1;
  uint8_t *auth_path0, *auth_path1; // [SPX_N * tree_height]
  uint32_t th, tree_height0, tree_height1;
  uint32_t *addr0, *addr1; // [8]

  uint8_t *pub_seed0;
  uint8_t *pub_seed1;
  spx_ctx ctx;

  pub_seed1 = &(ctx.pub_seed[0]);

  void *arguments0[8], *arguments1[8];
  int t;

  printf("\nPARAMS: %s\n", xstr(PARAMS));

  for(th = 1; th <= MAX_TREE_HEIGHT; th += 1)
  {
    alloc_arguments(arguments0, &root0, &leaf0, &leaf_idx0, &idx_offset0, &auth_path0, &tree_height0, th, &pub_seed0, 1, &addr0);
    alloc_arguments(arguments1, &root1, &leaf1, &leaf_idx1, &idx_offset1, &auth_path1, &tree_height1, th, &pub_seed1, 0, &addr1);

    for (t = 0; t < TESTS; t++)
    {
      random_arguments(arguments0, arguments1, th);

      // check if input variables are equal
      assert(leaf_idx0 == leaf_idx1);
      assert(*(uint32_t*)(arguments0[2]) == leaf_idx1);
      assert(idx_offset0 == idx_offset1);
      assert(*(uint32_t*)(arguments0[3]) == idx_offset1);
      assert(tree_height0 == tree_height1);
      assert(*(uint32_t*)(arguments0[5]) == tree_height1);

      // TODO: complete compute_root_jazz function and remove first call to compute_root
      // compute_root_jazz(arguments0);

      compute_root((uint8_t*)arguments0[0],
                   (uint8_t*)arguments0[1],
                   *((uint32_t*)arguments0[2]),
                   *((uint32_t*)arguments0[3]),
                   (uint8_t*)arguments0[4],
                   *((uint32_t*)arguments0[5]),
                   &ctx,
                   (uint32_t*)arguments0[7]);


      compute_root(root1, leaf1, leaf_idx1, idx_offset1, auth_path1, tree_height1, &ctx, addr1);

      assert(memcmp(root0,root1,SPX_N*sizeof(uint8_t)) == 0);
      assert(memcmp(leaf0,leaf1,SPX_N*sizeof(uint8_t)) == 0);
      assert(memcmp(auth_path0,auth_path1,SPX_N*th*sizeof(uint8_t)) == 0);
      assert(memcmp(pub_seed0,pub_seed1,SPX_N*sizeof(uint8_t)) == 0);
      assert(memcmp(pub_seed0,ctx.pub_seed,SPX_N*sizeof(uint8_t)) == 0);
      assert(memcmp(addr0,addr1,8*sizeof(uint32_t)) == 0);

    }

    printf(" PASS: compute_root = { tree_height : %d }\n", th);

    free_arguments(arguments0, 1);
    free_arguments(arguments1, 0);
  }

}

int main()
{
  test_compute_root();
  return 0;
}
