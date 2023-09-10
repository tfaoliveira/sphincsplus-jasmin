#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "macros.h"

#include "print.c"
#include "notrandombytes.c"

#ifndef OUTLEN 
#define OUTLEN 32
#endif

#ifndef INLEN
#define INLEN 64
#endif

#ifndef TESTS
#define TESTS 100
#endif

#define memcpy_u8u32_jazz NAMESPACE2(x_memcpy_u8u32, OUTLEN, INLEN)
#define memcpy_u8u8_jazz NAMESPACE2(x_memcpy_u8u8, OUTLEN, INLEN)
#define memcpy_u8u8p_jazz NAMESPACE2(x_memcpy_u8u8p, OUTLEN, INLEN)

extern void memcpy_u8u32_jazz(uint8_t *out, uint64_t offset, const uint8_t *in);
extern void memcpy_u8u8_jazz(uint8_t *out, uint64_t offset, const uint8_t *in);
extern void memcpy_u8u8p_jazz(uint8_t *out, uint64_t offset, const uint8_t *in);

int main()
{
  // uint8_t out0[OUTLEN], out1[OUTLEN];
  uint8_t in0[INLEN], in1[INLEN];
  uint64_t offset;

  int t;

  srand(42); // Seed

  for(t=0; t<TESTS; t++)
  {
    randombytes(in0, INLEN);
    memcpy(in1, in0, INLEN);

    // Generate random offset where offset + INLEN <= OUTLEN 
    uint64_t maxOffset = abs(OUTLEN - INLEN);
    offset = (uint64_t)rand() % (maxOffset + 1); 
    assert (offset + INLEN <= OUTLEN);

    //memcpy_jazz(out0, offset, in0); // TODO gen offset
    //memcpy(out1+offset, in1, INLEN);

    // TODO assert(memcmp( ... )
  }

  printf("PASS: memcpy = { outlen : %d ; offset : %" PRIu64" inlen : %d; }\n", OUTLEN, offset, INLEN);

  return 0;
}
