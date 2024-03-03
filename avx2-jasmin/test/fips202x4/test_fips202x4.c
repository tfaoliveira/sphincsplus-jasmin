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
#include "print.h"
#include "randombytes.h"

#ifndef TESTS
#define TESTS 1000
#endif

#ifndef INLEN
#define INLEN 32
#endif

#ifndef OUTLEN
#define OUTLEN 32
#endif

#ifndef MAX_BLOCKS
#define MAX_BLOCKS 20
#endif

#define SHAKE256_RATE 136

#define str(s) #s
#define xstr(s) str(s)

#define GREATER_THAN(x, y) ((x) > (y))

extern void KeccakF1600_StatePermute4x_jazz(__m256i state[25]);

#define keccak_absorb4x_jazz NAMESPACE1(keccak_absorb4x_jazz, INLEN)
extern void keccak_absorb4x_jazz(__m256i state[25], uint8_t *m0, uint8_t *m1, uint8_t *m2, uint8_t *m3);

#define shake256_squeezeblocks_4x_jazz NAMESPACE1(shake256_squeezeblocks_4x_jazz, OUTLEN)
extern void shake256_squeezeblocks_4x_jazz(uint8_t *h0, uint8_t *h1, uint8_t *h2, uint8_t *h3, __m256i state[25]);

#define shake256_x4_jazz NAMESPACE2(shake256_x4_jazz, OUTLEN, INLEN)
extern void shake256_x4_jazz(const void *);

void test_KeccakF1600_StatePermute4x(void);
void test_keccak_absorb4x(void);
void test_shake256_squeezeblocks4x(void);
void test_shake256(void);

static void shake256_x4_jazz_wrapper(uint8_t *in0, uint8_t *in1, uint8_t *in2, uint8_t *in3, uint8_t *out0,
                                     uint8_t *out1, uint8_t *out2, uint8_t *out3) {
    void *args[8];

    args[0] = (void *)in0;
    args[1] = (void *)in1;
    args[2] = (void *)in2;
    args[3] = (void *)in3;
    args[4] = (void *)out0;
    args[5] = (void *)out1;
    args[6] = (void *)out2;
    args[7] = (void *)out3;

    shake256_x4_jazz(args);
}

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
            printf("keccak_absorb4x_jazz (INLEN = %s)]: Test %d/%d\n", xstr(INLEN), i, TESTS);
        }

        randombytes((uint8_t *)state_ref, 25 * sizeof(__m256i));
        memcpy(state_jazz, state_ref, 25 * sizeof(__m256i));

        randombytes(in0, INLEN);
        randombytes(in1, INLEN);
        randombytes(in2, INLEN);
        randombytes(in3, INLEN);

        keccak_absorb4x_jazz(state_jazz, in0, in1, in2, in3);
        keccak_absorb4x(state_ref, SHAKE256_RATE, in0, in1, in2, in3, INLEN, 0x1F);

        if (memcmp(state_jazz, state_ref, 25 * sizeof(__m256i)) != 0) {
            print_str_u8("State ref", (uint8_t *)state_ref, 25 * sizeof(__m256i));
            print_str_u8("State jazz", (uint8_t *)state_jazz, 25 * sizeof(__m256i));
        }

        assert(memcmp(state_jazz, state_ref, 25 * sizeof(__m256i)) == 0);
    }
}

void test_shake256_squeezeblocks4x(void) {
    bool debug = true;

    __m256i state_ref[25] = {0};
    __m256i state_jazz[25] = {0};

    uint8_t out0_ref[OUTLEN] = {0};
    uint8_t out1_ref[OUTLEN] = {0};
    uint8_t out2_ref[OUTLEN] = {0};
    uint8_t out3_ref[OUTLEN] = {0};

    uint8_t out0_jazz[OUTLEN] = {0};
    uint8_t out1_jazz[OUTLEN] = {0};
    uint8_t out2_jazz[OUTLEN] = {0};
    uint8_t out3_jazz[OUTLEN] = {0};

    unsigned long long int nblocks = OUTLEN / SHAKE256_RATE;

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("[shake256_squeezeblock4x_jazz (%lld blocks)]: Test %d/%d\n", nblocks, i, TESTS);
        }

        randombytes((uint8_t *)state_ref, 25 * sizeof(__m256i));
        memcpy(state_jazz, state_ref, 25 * sizeof(__m256i));

        randombytes(out0_ref, OUTLEN);
        memcpy(out0_jazz, out0_ref, OUTLEN);

        randombytes(out1_ref, OUTLEN);
        memcpy(out1_jazz, out1_ref, OUTLEN);

        randombytes(out2_ref, OUTLEN);
        memcpy(out2_jazz, out2_ref, OUTLEN);

        randombytes(out3_ref, OUTLEN);
        memcpy(out3_jazz, out3_ref, OUTLEN);

        assert(memcmp(out0_jazz, out0_ref, OUTLEN) == 0);
        assert(memcmp(out1_jazz, out1_ref, OUTLEN) == 0);
        assert(memcmp(out2_jazz, out2_ref, OUTLEN) == 0);
        assert(memcmp(out3_jazz, out3_ref, OUTLEN) == 0);
        assert(memcmp(state_jazz, state_ref, 25 * sizeof(__m256i)) == 0);

        keccak_squeezeblocks4x(out0_ref, out1_ref, out2_ref, out3_ref, nblocks, state_ref, SHAKE256_RATE);
        shake256_squeezeblocks_4x_jazz(out0_jazz, out1_jazz, out2_jazz, out3_jazz, state_jazz);

        assert(memcmp(out0_jazz, out0_ref, OUTLEN) == 0);
        assert(memcmp(out1_jazz, out1_ref, OUTLEN) == 0);
        assert(memcmp(out2_jazz, out2_ref, OUTLEN) == 0);
        assert(memcmp(out3_jazz, out3_ref, OUTLEN) == 0);
        assert(memcmp(state_jazz, state_ref, 25 * sizeof(__m256i)) == 0);
    }
}

void test_shake256(void) {
    bool debug = true;

    // __m256i state_ref[25];
    __m256i state_jazz[25];

    uint8_t in0_ref[INLEN];
    uint8_t in1_ref[INLEN];
    uint8_t in2_ref[INLEN];
    uint8_t in3_ref[INLEN];

    uint8_t in0_jazz[INLEN];
    uint8_t in1_jazz[INLEN];
    uint8_t in2_jazz[INLEN];
    uint8_t in3_jazz[INLEN];

    uint8_t out0_ref[OUTLEN] = {0};
    uint8_t out1_ref[OUTLEN] = {0};
    uint8_t out2_ref[OUTLEN] = {0};
    uint8_t out3_ref[OUTLEN] = {0};

    uint8_t out0_jazz[OUTLEN] = {0};
    uint8_t out1_jazz[OUTLEN] = {0};
    uint8_t out2_jazz[OUTLEN] = {0};
    uint8_t out3_jazz[OUTLEN] = {0};

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("[shake256_jazz (OUTLEN=%s INLEN=%s)]: Test %d/%d\n", xstr(OUTLEN), xstr(INLEN), i, TESTS);
        }

        memset(out0_ref, 0, OUTLEN);
        memset(out0_jazz, 0, OUTLEN);

        memset(out1_ref, 0, OUTLEN);
        memset(out1_jazz, 0, OUTLEN);
        
        memset(out2_ref, 0, OUTLEN);
        memset(out2_jazz, 0, OUTLEN);
        
        memset(out3_ref, 0, OUTLEN);
        memset(out3_jazz, 0, OUTLEN);

        randombytes(in0_ref, INLEN);
        randombytes(in1_ref, INLEN);
        randombytes(in2_ref, INLEN);
        randombytes(in3_ref, INLEN);

        memcpy(in0_jazz, in0_ref, INLEN);
        memcpy(in1_jazz, in1_ref, INLEN);
        memcpy(in2_jazz, in2_ref, INLEN);
        memcpy(in3_jazz, in3_ref, INLEN);        

        assert(memcmp(out0_jazz, out0_ref, OUTLEN) == 0);
        assert(memcmp(out1_jazz, out1_ref, OUTLEN) == 0);
        assert(memcmp(out2_jazz, out2_ref, OUTLEN) == 0);
        assert(memcmp(out3_jazz, out3_ref, OUTLEN) == 0);

        assert(memcmp(in0_jazz, in0_ref, INLEN) == 0);
        assert(memcmp(in1_jazz, in1_ref, INLEN) == 0);
        assert(memcmp(in2_jazz, in2_ref, INLEN) == 0);
        assert(memcmp(in3_jazz, in3_ref, INLEN) == 0);

        shake256x4(out0_ref, out1_ref, out2_ref, out3_ref, OUTLEN, in0_ref, in1_ref, in2_ref, in3_ref, INLEN);
        shake256_x4_jazz_wrapper(in0_jazz, in1_jazz, in2_jazz, in3_jazz, out0_jazz, out1_jazz, out2_jazz, out3_jazz);

        assert(memcmp(out0_jazz, out0_ref, OUTLEN) == 0);
        assert(memcmp(out1_jazz, out1_ref, OUTLEN) == 0);
        assert(memcmp(out2_jazz, out2_ref, OUTLEN) == 0);
        assert(memcmp(out3_jazz, out3_ref, OUTLEN) == 0);
    }
}

// Run
//      find bin -type f -executable -exec sh -c 'if ! "{}"; then echo "{}" >> failed_executables.txt; fi' \;
// to see whcih failed
int main(void) {
    // Test permutation
    test_KeccakF1600_StatePermute4x();  // WORKS

    // Test absorb
    test_keccak_absorb4x();  // WORKS

    // Test squeeze (the number of blocks to absorb is given by NBLOCKS = OUTLEN / SHAKE256_RATE)
    test_shake256_squeezeblocks4x();  // WORKS

    printf("{ INLEN : %s ; OUTLEN : %s }\n", xstr(INLEN), xstr(OUTLEN));
    test_shake256();

    printf("Pass fips202_4x { INLEN : %s ; OUTLEN : %s }\n", xstr(INLEN), xstr(OUTLEN));
    return 0;
}
