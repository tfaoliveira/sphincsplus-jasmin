#include <assert.h>
#include <immintrin.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "KeccakP-1600-times4-SIMD256.c"
#include "fips202x4.h"
#include "macros.h"
#include "randombytes.c"

#ifndef TESTS
#define TESTS 1000
#endif

#ifndef INLEN
#define INLEN 32
#endif

#ifndef MAX_BLOCKS
#define MAX_BLOCKS 20
#endif

#define SHAKE256_RATE 136

#define str(s) #s
#define xstr(s) str(s)

#define PASTE1(x, y) x##_##y
#define NAMESPACE1(x, y) PASTE1(x, y)

extern void KeccakF1600_StatePermute4x_jazz(__m256i state[25]);

#define keccak_absorb4x_jazz NAMESPACE1(keccak_absorb4x_jazz, INLEN)
extern void keccak_absorb4x_jazz(__m256i state[25], uint8_t *m0, uint8_t *m1, uint8_t *m2, uint8_t *m3);

extern void shake256_squeezeblock4x_jazz(uint8_t *h0, uint8_t *h1, uint8_t *h2, uint8_t *h3, __m256i state[25]);
extern void shake256_squeezeblocks_4x_jazz(uint8_t *h0, uint8_t *h1, uint8_t *h2, uint8_t *h3, uint64_t nblocks,
                                           __m256i state[25]);

void test_KeccakF1600_StatePermute4x(void);
void test_keccak_absorb4x(void);
void test_shake256_squeezeblock4x(void);
void test_shake256_squeezeblocks4x(int nblocks);

void test_KeccakF1600_StatePermute4x(void) {
    bool debug = true;

    __m256i state_ref[25];
    __m256i state_jazz[25];

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("[KeccakF1600_StatePermute4x_jazz]: Test %d/%d\n", i, TESTS);
        }

        randombytes((uint8_t *)state_ref, 25 * sizeof(__m256i));
        memcpy(state_jazz, state_ref, 25 * sizeof(__m256i));

        assert(memcmp(state_jazz, state_ref, 25 * sizeof(__m256i)) == 0);

        KeccakF1600_StatePermute4x_jazz(state_jazz);
        KeccakP1600times4_PermuteAll_24rounds(state_ref);

        assert(memcmp(state_jazz, state_ref, 25 * sizeof(__m256i)) == 0);
    }
}

void test_keccak_absorb4x(void) {
    bool debug = true;

    __m256i state_ref[25];
    __m256i state_jazz[25];
    uint8_t in0[INLEN], in1[INLEN], in2[INLEN], in3[INLEN];

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("keccak_absorb4x_jazz]: Test %d/%d\n", i, TESTS);
        }

        randombytes((uint8_t *)state_ref, 25 * sizeof(__m256i));
        memcpy(state_jazz, state_ref, 25 * sizeof(__m256i));

        randombytes(in0, INLEN);
        randombytes(in1, INLEN);
        randombytes(in2, INLEN);
        randombytes(in3, INLEN);

        keccak_absorb4x_jazz(state_jazz, in0, in1, in2, in3);
        keccak_absorb4x(state_ref, SHAKE256_RATE, in0, in1, in2, in3, INLEN, 0x1F);

        assert(memcmp(state_jazz, state_ref, 25 * sizeof(__m256i)) == 0);
    }
}

void test_shake256_squeezeblock4x(void) {
    bool debug = true;

    __m256i state_ref[25];
    __m256i state_jazz[25];

    uint8_t h0_ref[SHAKE256_RATE], h0_jazz[SHAKE256_RATE];
    uint8_t h1_ref[SHAKE256_RATE], h1_jazz[SHAKE256_RATE];
    uint8_t h2_ref[SHAKE256_RATE], h2_jazz[SHAKE256_RATE];
    uint8_t h3_ref[SHAKE256_RATE], h3_jazz[SHAKE256_RATE];

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("shake256_squeezeblock4x_jazz]: Test %d/%d\n", i, TESTS);
        }

        randombytes((uint8_t *)state_ref, 25 * sizeof(__m256i));
        memcpy(state_jazz, state_ref, 25 * sizeof(__m256i));

        randombytes(h0_ref, SHAKE256_RATE);
        memcpy(h0_jazz, h0_ref, SHAKE256_RATE);

        randombytes(h1_ref, SHAKE256_RATE);
        memcpy(h1_jazz, h1_ref, SHAKE256_RATE);

        randombytes(h2_ref, SHAKE256_RATE);
        memcpy(h2_jazz, h2_ref, SHAKE256_RATE);

        randombytes(h3_ref, SHAKE256_RATE);
        memcpy(h3_jazz, h3_ref, SHAKE256_RATE);

        assert(memcmp(h0_jazz, h0_ref, SHAKE256_RATE) == 0);
        assert(memcmp(h1_jazz, h1_ref, SHAKE256_RATE) == 0);
        assert(memcmp(h2_jazz, h2_ref, SHAKE256_RATE) == 0);
        assert(memcmp(h3_jazz, h3_ref, SHAKE256_RATE) == 0);
        assert(memcmp(state_jazz, state_ref, 25 * sizeof(__m256i)) == 0);

        keccak_squeezeblocks4x(h0_ref, h1_ref, h2_ref, h3_ref, 1, state_ref, SHAKE256_RATE);
        shake256_squeezeblock4x_jazz(h0_jazz, h1_jazz, h2_jazz, h3_jazz, state_jazz);

        assert(memcmp(h0_jazz, h0_ref, SHAKE256_RATE) == 0);
        assert(memcmp(h1_jazz, h1_ref, SHAKE256_RATE) == 0);
        assert(memcmp(h2_jazz, h2_ref, SHAKE256_RATE) == 0);
        assert(memcmp(h3_jazz, h3_ref, SHAKE256_RATE) == 0);
        assert(memcmp(state_jazz, state_ref, 25 * sizeof(__m256i)) == 0);
    }
}

void test_shake256_squeezeblocks4x(int nblocks) {
    bool debug = true;

    __m256i state_ref[25];
    __m256i state_jazz[25];

    uint8_t h0_ref[SHAKE256_RATE], h0_jazz[SHAKE256_RATE];
    uint8_t h1_ref[SHAKE256_RATE], h1_jazz[SHAKE256_RATE];
    uint8_t h2_ref[SHAKE256_RATE], h2_jazz[SHAKE256_RATE];
    uint8_t h3_ref[SHAKE256_RATE], h3_jazz[SHAKE256_RATE];

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("[shake256_squeezeblock4x_jazz (%d blocks)]: Test %d/%d\n", nblocks, i, TESTS);
        }

        randombytes((uint8_t *)state_ref, 25 * sizeof(__m256i));
        memcpy(state_jazz, state_ref, 25 * sizeof(__m256i));

        randombytes(h0_ref, SHAKE256_RATE);
        memcpy(h0_jazz, h0_ref, SHAKE256_RATE);

        randombytes(h1_ref, SHAKE256_RATE);
        memcpy(h1_jazz, h1_ref, SHAKE256_RATE);

        randombytes(h2_ref, SHAKE256_RATE);
        memcpy(h2_jazz, h2_ref, SHAKE256_RATE);

        randombytes(h3_ref, SHAKE256_RATE);
        memcpy(h3_jazz, h3_ref, SHAKE256_RATE);

        assert(memcmp(h0_jazz, h0_ref, SHAKE256_RATE) == 0);
        assert(memcmp(h1_jazz, h1_ref, SHAKE256_RATE) == 0);
        assert(memcmp(h2_jazz, h2_ref, SHAKE256_RATE) == 0);
        assert(memcmp(h3_jazz, h3_ref, SHAKE256_RATE) == 0);
        assert(memcmp(state_jazz, state_ref, 25 * sizeof(__m256i)) == 0);

        keccak_squeezeblocks4x(h0_ref, h1_ref, h2_ref, h3_ref, nblocks, state_ref, SHAKE256_RATE);
        shake256_squeezeblocks_4x_jazz(h0_jazz, h1_jazz, h2_jazz, h3_jazz, nblocks, state_jazz);

        assert(memcmp(h0_jazz, h0_ref, SHAKE256_RATE) == 0);
        assert(memcmp(h1_jazz, h1_ref, SHAKE256_RATE) == 0);
        assert(memcmp(h2_jazz, h2_ref, SHAKE256_RATE) == 0);
        assert(memcmp(h3_jazz, h3_ref, SHAKE256_RATE) == 0);
        assert(memcmp(state_jazz, state_ref, 25 * sizeof(__m256i)) == 0);
    }
}

int main(void) {
    // Test permutation
    test_KeccakF1600_StatePermute4x();

    // Test absorb
    test_keccak_absorb4x();

    test_shake256_squeezeblock4x();

    // for (int i = 1; i <= MAX_BLOCKS; i++) {
    //     test_shake256_squeezeblocks4x(i);
    // }

    printf("Pass fips202_4x { INLEN : %s ; OUTLEN : %s }\n", xstr(INLEN), xstr(OUTLEN));
    return 0;
}