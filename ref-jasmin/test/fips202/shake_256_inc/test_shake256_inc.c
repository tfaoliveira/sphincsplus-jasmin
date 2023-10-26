#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "macros.h"
#include "notrandombytes.c"
#include "print.c"

#ifndef TESTS
#define TESTS 5
#endif

extern void shake256(uint8_t *out, size_t outlen, const uint8_t *in,
                     size_t inlen);  // from fips202.c

extern void shake256_inc_init_jazz(uint64_t *state);
extern void shake256_inc_init(uint64_t *state);  // from fips202.c

extern void shake256_inc_absorb_jazz(uint64_t *state, const uint8_t *in, size_t inlen);
extern void shake256_inc_absorb(uint64_t *state, const uint8_t *in,
                                size_t inlen);  // from fips202.c

extern void shake256_inc_finalize_jazz(uint64_t *state);
extern void shake256_inc_finalize(uint64_t *state);  // from fips202.c

extern void shake256_inc_squeeze_jazz(uint8_t *out, size_t outlen, uint64_t *state);
extern void shake256_inc_squeeze(uint8_t *out, size_t outlen, uint64_t *state);  // from fips202.c

void test_absorb_one_block(void);
void test_absorb_n_blocks(int nblocks);
void test_shake_shake_inc(int nblocks);

void test_absorb_one_block(void) {
    uint64_t state_ref[26], state_jazz[26];
    uint8_t *in;
    uint8_t *out_ref;
    uint8_t *out_jazz;

    for (int i = 0; i < TESTS; i++) {
        for (size_t inlen = 16; inlen < 2048; inlen++) {
            for (size_t outlen = 16; outlen < 2048; outlen++) {
                in = malloc(inlen);
                out_ref = malloc(outlen);
                out_jazz = malloc(outlen);

                memset(out_ref, 0, outlen);
                memset(out_jazz, 0, outlen);

                shake256_inc_init(state_ref);
                shake256_inc_init_jazz(state_jazz);

                assert(memcmp(state_jazz, state_ref, 26 * sizeof(uint64_t)) == 0);

                randombytes(in, inlen);

                shake256_inc_absorb(state_ref, in, inlen);
                shake256_inc_absorb_jazz(state_jazz, in, inlen);

                assert(memcmp(state_jazz, state_ref, 26 * sizeof(uint64_t)) == 0);

                shake256_inc_finalize(state_ref);
                shake256_inc_finalize_jazz(state_jazz);

                assert(memcmp(state_jazz, state_ref, 26 * sizeof(uint64_t)) == 0);

                shake256_inc_squeeze(out_ref, outlen, state_ref);
                shake256_inc_squeeze_jazz(out_jazz, outlen, state_jazz);

                assert(memcmp(out_jazz, out_ref, outlen) == 0);

                free(in);
                free(out_ref);
                free(out_jazz);
            }
        }
    }
}

void test_absorb_n_blocks(int nblocks) {
    uint64_t state_ref[26], state_jazz[26];
    uint8_t *in;
    uint8_t *out_ref;
    uint8_t *out_jazz;

    for (int i = 0; i < TESTS; i++) {
        for (size_t inlen = 16; inlen < 2048; inlen++) {
            for (size_t outlen = 16; outlen < 2048; outlen++) {
                in = malloc(inlen);
                out_ref = malloc(outlen);
                out_jazz = malloc(outlen);

                memset(out_ref, 0, outlen);
                memset(out_jazz, 0, outlen);

                shake256_inc_init(state_ref);
                shake256_inc_init_jazz(state_jazz);

                assert(memcmp(state_jazz, state_ref, 26 * sizeof(uint64_t)) == 0);

                for (int blocks = 0; blocks < nblocks; blocks++) {
                    randombytes(in, inlen);

                    shake256_inc_absorb(state_ref, in, inlen);
                    shake256_inc_absorb_jazz(state_jazz, in, inlen);

                    assert(memcmp(state_jazz, state_ref, 26 * sizeof(uint64_t)) == 0);
                }

                shake256_inc_finalize(state_ref);
                shake256_inc_finalize_jazz(state_jazz);

                assert(memcmp(state_jazz, state_ref, 26 * sizeof(uint64_t)) == 0);

                shake256_inc_squeeze(out_ref, outlen, state_ref);
                shake256_inc_squeeze_jazz(out_jazz, outlen, state_jazz);

                assert(memcmp(out_jazz, out_ref, outlen) == 0);

                free(in);
                free(out_ref);
                free(out_jazz);
            }
        }
    }
}

void test_shake_shake_inc(int nblocks) {
    uint64_t state_inc[26];
    uint8_t *in;
    uint8_t *out_ref;
    uint8_t *out_jazz;
    uint8_t *buf;

    for (int i = 0; i < TESTS; i++) {
        for (size_t inlen = 16; inlen < 2048; inlen++) {
            buf = malloc(nblocks * sizeof(inlen));
            for (size_t outlen = 16; outlen < 2048; outlen++) {
                in = malloc(inlen);
                out_ref = malloc(outlen);
                out_jazz = malloc(outlen);

                memset(out_ref, 0, outlen);
                memset(out_jazz, 0, outlen);

                shake256_inc_init_jazz(state_inc);

                for (int blocks = 0; blocks < nblocks; blocks++) {
                    randombytes(in, inlen);
                    memcpy(buf + i * inlen, in, inlen);
                    shake256_inc_absorb_jazz(state_inc, in, inlen);
                }

                shake256_inc_finalize_jazz(state_inc);

                shake256_inc_squeeze_jazz(out_jazz, outlen, state_inc);
                shake256(out_ref, outlen, buf, nblocks * sizeof(inlen));

                assert(memcmp(out_jazz, out_ref, outlen) == 0);

                free(in);
                free(out_ref);
                free(out_jazz);
            }

            free(buf);
        }
    }
}

int main(void) {
    test_absorb_one_block();

    for (int i = 1; i < 50; i++) {
        test_absorb_n_blocks(i);
        test_shake_shake_inc(i);
    }

    printf("Pass: shake256 inc\n");

    return 0;
}