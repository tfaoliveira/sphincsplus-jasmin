#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "macros.h"
#include "notrandombytes.c"
#include "print.c"

#ifndef TESTS
#define TESTS 1000
#endif

#ifndef MAX_LEN
#define MAX_LEN 1024
#endif

extern int memset_jazz(uint8_t *a, uint8_t val, size_t n);

int main(void) {
    uint8_t *ref, *jazz;
    uint8_t val;

    for (int i = 0; i < TESTS; i++) {
        for (size_t len = 0; len < MAX_LEN; len++) {
            ref = (uint8_t *)malloc(len * sizeof(uint8_t));
            jazz = (uint8_t *)malloc(len * sizeof(uint8_t));

            randombytes(jazz, len);
            randombytes(&val, 1);

            memset(ref, val, len);
            memset_jazz(jazz, val, len);

            assert(memcmp(ref, jazz, len) == 0);

            free(ref);
            free(jazz);
        }
    }

    puts("Pass memset");
    return 0;
}
