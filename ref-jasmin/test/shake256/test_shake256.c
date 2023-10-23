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
#define TESTS 1000
#endif

#ifndef NMSG
#define NMSG 10
#endif

#define shake256_jazz NAMESPACE2(shake256, OUTLEN, INLEN)
#define shake256_inc_absorb_jazz NAMESPACE1(shake256_inc_absorb_jazz, INLEN)
#define shake256_inc_squeeze_jazz NAMESPACE1(shake256_inc_squeeze_jazz, OUTLEN)

extern void shake256_jazz(uint8_t *out, const uint8_t *in);
extern void shake256(uint8_t *output, size_t outlen, const uint8_t *input,
                     size_t inlen);  // from fips202.c

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
void test_inc_ref(void);
void test_shake_absorb_inc(void) ;

void test_shake256(void) {
    uint8_t out0[OUTLEN], out1[OUTLEN];
    uint8_t in0[INLEN], in1[INLEN];

    int t;

    for (t = 0; t < TESTS; t++) {
        randombytes(in0, INLEN);
        memcpy(in1, in0, INLEN);

        shake256_jazz(out0, in0);
        shake256(out1, OUTLEN, in1, INLEN);

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
            assert(memcmp(state0, state1, 26 * sizeof(uint64_t)) == 0);  // fails
        }

        shake256_inc_finalize(state0);
        shake256_inc_finalize_jazz(state1);
        assert(memcmp(state0, state1, 26 * sizeof(uint64_t)) == 0);  // fails

        shake256_inc_squeeze(out0, OUTLEN, state0);
        shake256_inc_squeeze_jazz(out1, state1);
        assert(memcmp(out0, out1, OUTLEN) == 0);  // fails
    }
}

void test_inc_ref(void) {
    /*
     * Make sure that absorbing bytes incrementally is the same as absorbing
     * them all at once
     */
    uint64_t state_inc[26];
    uint8_t buf[INLEN * NMSG];
    uint8_t in[INLEN];
    uint8_t out_inc[OUTLEN], out[OUTLEN];

    for (int t = 0; t < TESTS; t++) {
        shake256_inc_init(state_inc);

        for (int i = 0; i < NMSG; i++) {
            randombytes(in, INLEN);
            memcpy(buf + i * INLEN, in, INLEN);

            shake256_inc_absorb(state_inc, in, INLEN);
        }

        shake256_inc_finalize(state_inc);
        shake256_inc_squeeze(out_inc, OUTLEN, state_inc);

        shake256(out, OUTLEN, buf, INLEN * NMSG);

        assert(memcmp(out, out_inc, OUTLEN) == 0);
    }
}

void test_shake_absorb_inc(void) {
#define RATE 136
    uint64_t state0[26], state1[26];
    uint8_t in[RATE * 4];

    memset(in, 1, sizeof(in));

    memset(state0, 0, 26 * sizeof(uint64_t));
    memset(state1, 0, 26 * sizeof(uint64_t));
    for (size_t i = 0; i < TESTS; i++) {
        shake256_inc_absorb(state0, in, INLEN);
        shake256_inc_absorb_jazz(state1, in);
        printf("Test %ld \n", i);
        puts("C");
        print_u8((uint8_t*)state0, 26*8);
        puts("Jasmin");
        print_u8((uint8_t*)state1, 26*8);
        puts("-------------------------------------------");

        assert(memcmp(state0, state1, 26 * sizeof(uint64_t)) == 0);  // fails
    }
#undef RATE
}

int main() {
    srand(42);
    // test_shake256();
    // test_shake256_inc();
    // test_inc_ref();
    test_shake_absorb_inc();
    printf("PASS: shake256 = { outlen : %d ; inlen : %d; }\n", OUTLEN, INLEN);
    return 0;
}
