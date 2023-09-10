#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "macros.h"

#include "print.c"
#include "notrandombytes.c"

#ifndef OUTLEN 
#define OUTLEN 128
#endif

#ifndef INLEN
#define INLEN 32
#endif

#ifndef TESTS
#define TESTS 100
#endif

#define memcpy_u8u32_jazz NAMESPACE2(x_memcpy_u8u32, OUTLEN, INLEN)
extern void memcpy_u8u32_jazz(uint8_t *out, uint64_t offset, const uint32_t *in);

int main()
{
  uint8_t out0[OUTLEN], out1[OUTLEN];
  uint32_t in0[INLEN], in1[INLEN];
  uint64_t offset;

  int t;

  for(t=0; t<TESTS; t++)
  {
    randombytes((uint8_t*)in0, INLEN*4);
    memcpy(in1, in0, INLEN*4);

    memset(out0, 0, OUTLEN);
    memset(out1, 0, OUTLEN);

    offset = 0; // TODO

    memcpy_u8u32_jazz(out0, offset, in0);
    memcpy(out1+offset, in1, INLEN*4);

    assert(memcmp(out0+offset,out1+offset,INLEN*4) == 0);
  }

  printf("PASS: memcpy_u8u32 = { outlen : %d ; inlen : %d; }\n", OUTLEN, INLEN);

  return 0;
}
