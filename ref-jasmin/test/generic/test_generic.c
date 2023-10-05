#include <assert.h>
#include <inttypes.h>
#include <stdio.h>

#include "macros.h"
#include "notrandombytes.c"

#ifndef TESTS
#define TESTS 1000
#endif

#ifndef INLEN
#define INLEN 64
#endif

extern void cond_u64_a_below_b_and_a_below_c_jazz(uint64_t a, uint64_t b, uint64_t c);

#define zero_array_u32_jazz NAMESPACE1(zero_array_u32_jazz, INLEN)
extern void zero_array_u32_jazz(uint32_t *);

extern void get_sk_prf_from_sk_jazz(const uint8_t *sk, uint8_t *prf);

void test_zero_array_u32_jazz(void);
// void test_get_sk_prf_from_sk_jazz(void);

void test_zero_array_u32_jazz(void) {
    uint32_t in[INLEN];
    uint32_t zero[INLEN] = {0};

    for (int i = 0; i < TESTS; i++) {
        randombytes1((uint8_t *)in, INLEN);
        zero_array_u32_jazz(in);
        assert(memcmp(in, zero, INLEN) == 0);
    }
}

// void test_get_sk_prf_from_sk_jazz(void) {
//     for (int i = 0; i < TESTS; i++) {
//     }
// }

int main(void) {
    test_zero_array_u32_jazz();
    puts("PASS: generic");
}