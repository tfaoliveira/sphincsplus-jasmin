#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "macros.h"

#include "print.c"
#include "notrandombytes.c"

#include "context.h"

#ifndef HASH
#define HASH shake
#endif

#ifndef PARAM
#define PARAM 128f
#endif

#ifndef THASH
#define THASH simple
#endif

#ifndef INBLOCKS
#define INBLOCKS 1
#endif

#ifndef TESTS
#define TESTS 1000
#endif

#include "params.h"

#define thash_jazz NAMESPACE1(thash, INBLOCKS)

/*
target function:
  inline fn __thash<INBLOCKS>(
    reg ptr u8[SPX_N] out,
    reg ptr u8[INBLOCKS*SPX_N] in,
    reg ptr u8[SPX_N] pub_seed,
    reg ptr u32[8] addr)
    ->
    reg ptr u8[SPX_N]
*/
extern void thash_jazz(
  uint8_t *out,
  const uint8_t *in,
  const uint8_t *pub_seed,
  uint32_t addr[8]
);

// implementation from, for instance, ../../thash_shake_robust.c / ../../thash_shake_simple.c
extern void thash(
  uint8_t *out,
  const uint8_t *in,
  unsigned int inblocks,
  const spx_ctx *ctx,
  uint32_t addr[8]
);

int main()
{
  // TODO: tests: for each test gen rnd in/pub_seed/addr, check out

  return 0;
}

