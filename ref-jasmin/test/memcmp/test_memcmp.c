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

//
// NOTE: The Jasmin implementation of memcpy returns 0 if the regions of memory have the same
// contents
//       and -1 otherwise
//
//       The implementation is constant time

#define memcmp_jazz NAMESPACE1(memcmp_jazz, INLEN)
extern int memcmp_jazz(const uint8_t *a, const uint8_t *b);

extern int memcmp__jazz(const uint8_t *a, const uint8_t *b, size_t n);

void test_memcmp_array(void);
void test_memcmp_ptr(void);

void test_memcmp_array(void) {
    uint8_t a[INLEN], b[INLEN];
    int res;

    // In this tests, a and b are equal so r should be 0
    for (int i = 0; i < TESTS; i++) {
        randombytes(a, INLEN);
        memcpy(b, a, INLEN);

        res = memcmp_jazz(a, b);

        assert(res == 0);
    }

    // In this case, a and b are (probably) different, so r should (probably) be -1
    for (int i = 0; i < TESTS; i++) {
        randombytes(a, INLEN);
        randombytes(b, INLEN);

        res = memcmp_jazz(a, b);

        assert(memcmp(a, b, INLEN) == 0 ? res == 0 : res == -1);
    }
}

void test_memcmp_ptr(void) {
#define MIN_IN_LEN 1
#define MIN_OUT_LEN 1
#define MAX_IN_LEN 100
#define MAX_OUT_LEN 100
    uint8_t *in, *out;

    size_t inlen;
    size_t outlen;

    size_t length;

    int res;

    // In this tests, a and b are equal so r should be 0
    for (int i = 0; i < TESTS; i++) {
        for (inlen = MIN_IN_LEN; inlen < MAX_IN_LEN; inlen++) {
            in = (uint8_t *)malloc(inlen);
            for (outlen = MIN_OUT_LEN; outlen < MAX_OUT_LEN; outlen++) {
                out = (uint8_t *)malloc(outlen);

                // begin test
                memset(in, 0, inlen);
                memset(out, 0, outlen);

                if (inlen > outlen) {
                    length = outlen;  // we compare the minimum of both sizes
                    randombytes(in, length);
                    memcpy(out, in, length);
                    // at this point, the first length bytes of in and out should be equal
                } else {  // outlen >= inlen
                    length = inlen;
                    randombytes(in, length);
                    memcpy(out, in, length);
                }

                res = memcmp__jazz(in, out, length);
                assert(res == 0);

                // end test

                free(out);
            }
            free(in);
        }
    }

    // In this case, a and b are (probably) different, so r should (probably) be -1
    for (int i = 0; i < TESTS; i++) {
        for (inlen = MIN_IN_LEN; inlen < MAX_IN_LEN; inlen++) {
            in = (uint8_t *)malloc(inlen);
            for (outlen = MIN_OUT_LEN; outlen < MAX_OUT_LEN; outlen++) {
                out = (uint8_t *)malloc(outlen);

                // begin test
                memset(in, 0, inlen);
                memset(out, 0, outlen);

                if (inlen > outlen) {
                    length = outlen;  // we compare the minimum of both sizes
                } else {              // outlen >= inlen
                    length = inlen;
                }

                randombytes(in, length);
                randombytes(out, length);

                res = memcmp__jazz(in, out, length);
                assert(memcmp(in, out, length) == 0 ? res == 0 : res == -1);

                // end test

                free(out);
            }
            free(in);
        }
    }

#undef MIN_IN_LEN
#undef MIN_OUT_LEN
#undef MAX_IN_LEN
#undef MAX_OUT_LEN
}

int main(void) {
    test_memcmp_array();
    test_memcmp_ptr();
    printf("PASS: memcmp = { inlen : %d; }\n", INLEN);
    return 0;
}