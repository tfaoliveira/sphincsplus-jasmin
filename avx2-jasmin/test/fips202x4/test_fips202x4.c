#include <assert.h>
#include <immintrin.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#include "KeccakP-1600-times4-SIMD256.c"
#include "fips202x4.h"
#include "macros.h"
#include "randombytes.c"

#ifndef TESTS
#define TESTS 1000
#endif

#define str(s) #s
#define xstr(s) str(s)

extern void KeccakF1600_StatePermute4x_jazz(__m256i state[25]);

void test_KeccakF1600_StatePermute4x(void);

void test_KeccakF1600_StatePermute4x(void) {
    bool debug = true;

    __m256i state_ref[25];
    __m256i state_jazz[25];

    for (int i = 0; i < TESTS; i++) {
        if (debug) { printf("Test %d/%d\n", i, TESTS); }

        randombytes((uint8_t*)state_ref, 25 * sizeof(__m256i));
        memcpy(state_jazz, state_ref, 25 * sizeof(__m256i));

        assert(memcmp(state_jazz, state_ref, 25 * sizeof(__m256i)) == 0);

        KeccakF1600_StatePermute4x_jazz(state_jazz);
        KeccakP1600times4_PermuteAll_24rounds(state_ref);

        assert(memcmp(state_jazz, state_ref, 25 * sizeof(__m256i)) == 0);
    }
}

int main(void) {
    test_KeccakF1600_StatePermute4x();
    printf("Pass fips202_4x { Inlen : %s ; OUTLEN : %s }\n", xstr(INLEN), xstr(OUTLEN));
    return 0;
}