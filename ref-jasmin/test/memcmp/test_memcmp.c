#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "macros.h"
#include "notrandombytes.c"
#include "print.c"

#ifndef INLEN
#define INLEN 32
#endif

#ifndef TESTS
#define TESTS 100
#endif

#define memcmp_jazz NAMESPACE1(memcmp_jazz, INLEN)
extern int memcmp_jazz(const uint8_t *a, const uint8_t *b);

int main(void) {
    uint8_t a[INLEN], b[INLEN];

    for(int i = 0; i < TESTS; i++) {
      randombytes(a, INLEN);
      randombytes(b, INLEN);
      
      // assert(memcmp_jazz(a, b) == (memcmp(a, b, INLEN) == 0 ? 0 : 1));
      if (memcmp(a, b, INLEN) == 0) {
        assert(memcmp_jazz(a, b) == 0);
      } else {
        assert(memcmp_jazz(a, b) == 1);
      }
    }

    printf("PASS: memcmp_u8u8 = { inlen : %d; }\n", INLEN);

    return 0;
}
