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

extern void cond_u64_a_below_b_and_a_below_c_jazz(uint64_t a, uint64_t b, uint64_t c, uint8_t *out);
extern void ull_to_bytes_jazz(uint8_t *out, uint64_t v);

#define zero_array_u32_jazz NAMESPACE1(zero_array_u32_jazz, INLEN)
extern void zero_array_u32_jazz(uint32_t *);

extern void get_sk_prf_from_sk_jazz(const uint8_t *sk, uint8_t *prf);

void test_cond_u64_a_below_b_and_a_below_c(void);
void test_ull_to_bytes(void);
void test_zero_array_u32_jazz(void);
void test_sign_utils(void);

void test_cond_u64_a_below_b_and_a_below_c(void) {
    uint64_t a, b, c;
    uint8_t r;
    for (int i = 0; i < TESTS; i++) {
        randombytes1((uint8_t *)&a, sizeof(uint64_t));
        randombytes1((uint8_t *)&b, sizeof(uint64_t));
        randombytes1((uint8_t *)&c, sizeof(uint64_t));

        cond_u64_a_below_b_and_a_below_c_jazz(a, b, c, &r);
        assert((a < b && a < c) ? (r == 1) : (r == 0));
    }
}

// from C impl
static void ull_to_bytes(unsigned char *out, unsigned int outlen, unsigned long long in) {
    int i;

    /* Iterate over out in decreasing order, for big-endianness. */
    for (i = (signed int)outlen - 1; i >= 0; i--) {
        out[i] = in & 0xff;
        in = in >> 8;
    }
}

void test_ull_to_bytes(void) {
    unsigned char out0[8] = {0};  // uint8_t
    unsigned char out1[8] = {0};  // uint8_t
    unsigned long long v;         // uint64_t

    for (int i = 0; i < TESTS; i++) {
        randombytes1((uint8_t *)&v, sizeof(unsigned long long));
        ull_to_bytes(out0, 8, v);
        ull_to_bytes_jazz(out1, v);
        assert(memcmp(out0, out1, 8) == 0);
    }
}

void test_zero_array_u32_jazz(void) {
    uint32_t in[INLEN];
    uint32_t zero[INLEN] = {0};

    for (int i = 0; i < TESTS; i++) {
        randombytes1((uint8_t *)in, INLEN);
        zero_array_u32_jazz(in);
        assert(memcmp(in, zero, INLEN) == 0);
    }
}

void test_sign_utils(void) {
    for (int i = 0; i < TESTS; i++) {
        // TODO:
    }
}

int main(void) {
    test_cond_u64_a_below_b_and_a_below_c();
    test_ull_to_bytes();
    test_zero_array_u32_jazz();
    test_sign_utils();
    puts("PASS: generic");
}
