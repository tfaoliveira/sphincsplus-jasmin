#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

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
#define TESTS 100000
#endif

#define shake256_jazz NAMESPACE2(shake256, OUTLEN, INLEN)

extern void shake256_jazz(uint8_t *out, const uint8_t *in);
extern void shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen); // from fips202.c


int main()
{
  uint8_t out0[OUTLEN], out1[OUTLEN];
  uint8_t in0[INLEN], in1[INLEN];

  int t;

  for(t=0; t<TESTS; t++)
  {
    randombytes(in0, INLEN);
    memcpy(in1, in0, INLEN);
 
    shake256_jazz(out0, in0);
    shake256(out1, OUTLEN, in1, INLEN);

    assert(memcmp(out0, out1, 32) == 0);
  }

  printf("PASS: shake256 = { outlen : %d ; inlen : %d; }\n", OUTLEN, INLEN);

  return 0;
}

