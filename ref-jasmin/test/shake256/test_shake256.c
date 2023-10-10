#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "macros.h"
#include "notrandombytes.c"
#include "print.c"

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
#define shake256_inc_absorb_jazz NAMESPACE1(shake256_inc_absorb_jazz, INLEN)
#define shake256_inc_squeeze_jazz NAMESPACE1(shake256_inc_squeeze_jazz, OUTLEN)

// TODO: Uncomment
// extern void shake256_jazz(uint8_t *out, const uint8_t *in);
// extern void shake256(uint8_t *output, size_t outlen, const uint8_t *input,
//                      size_t inlen);  // from fips202.c

extern void shake256_inc_init_jazz(uint64_t *state);
extern void shake256_inc_init(uint64_t *state);  // from fips202.c

extern void shake256_inc_absorb_jazz(uint64_t *state, const uint8_t *in);
extern void shake256_inc_absorb(uint64_t *s_inc, const uint8_t *input,
                                size_t inlen);  // from fips202.c

extern void shake256_inc_finalize_jazz(uint64_t *state);
extern void shake256_inc_finalize(uint64_t *s_inc);  // from fips202.c

extern void shake256_inc_squeeze_jazz(uint8_t *out, uint64_t *state);
extern void shake256_inc_squeeze(uint8_t *output, size_t outlen,
                                 uint64_t *s_inc);  // from fips202.c

void test_shake256(void);
void test_shake256_inc(void);

void test_shake256(void) {
    uint8_t out0[OUTLEN], out1[OUTLEN];
    uint8_t in0[INLEN], in1[INLEN];

    int t;

    for (t = 0; t < TESTS; t++) {
        randombytes(in0, INLEN);
        memcpy(in1, in0, INLEN);

        // TODO: Uncomment
        // shake256_jazz(out0, in0);
        // shake256(out1, OUTLEN, in1, INLEN);

        assert(memcmp(out0, out1, OUTLEN) == 0);
    }
}

void test_shake256_inc(void) {
    uint64_t state0[26], state1[26];
    uint8_t in[INLEN];
    uint8_t out0[OUTLEN], out1[OUTLEN];
    size_t x;

    for (int i = 0; i < TESTS; i++) {
        randombytes1((uint8_t *)state0, 26 * sizeof(uint64_t));
        randombytes1((uint8_t *)state1, 26 * sizeof(uint64_t));

        shake256_inc_init(state0);       // C impl
        shake256_inc_init_jazz(state1);  // Jasmin impl
        assert(memcmp(state0, state1, 26 * sizeof(uint64_t)) == 0);

        // absorb x messages [x in 0..500]
        x = (size_t)(rand() % 501);
        for (size_t j = 0; j < x; j++) {
            randombytes1(in, INLEN);
            shake256_inc_absorb(state0, in, INLEN);
            shake256_inc_absorb_jazz(state1, in);
            assert(memcmp(state0, state1, 26 * sizeof(uint64_t)) == 0);
        }

        shake256_inc_finalize(state0);
        shake256_inc_finalize_jazz(state1);
        assert(memcmp(state0, state1, 26 * sizeof(uint64_t)) == 0);

        shake256_inc_squeeze(out0, OUTLEN, state0);
        shake256_inc_squeeze_jazz(out1, state1);
        assert(memcmp(out0, out1, OUTLEN) == 0);
    }
}

int main() {
    srand(42);
    // TODO: Uncomment
    // test_shake256();
    test_shake256_inc();
    printf("PASS: shake256 = { outlen : %d ; inlen : %d; }\n", OUTLEN, INLEN);
    return 0;
}
