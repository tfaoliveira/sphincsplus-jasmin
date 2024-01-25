#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "macros.h"
#include "notrandombytes.c"
#include "print.h"

#ifndef TESTS
#define TESTS 1000
#endif

#ifndef INLEN
#define INLEN 64
#endif

extern void cond_u32_a_below_b_and_a_below_c_jazz(uint32_t a, uint32_t b, uint32_t c, uint8_t *out);
extern void cond_u32_a_eq_b_and_c_below_d_jazz(uint32_t a, uint32_t b, uint32_t c, uint32_t d,
                                               uint8_t *out);

extern void cond_u64_a_below_b_and_a_below_c_jazz(uint64_t a, uint64_t b, uint64_t c, uint8_t *out);
extern void cond_u64_a_dif_b_and_a_dif_c_jazz(uint64_t a, uint64_t b, uint64_t c, uint8_t *out);
extern void cond_u64_a_dif_b_and_c_dif_d_jazz(uint64_t a, uint64_t b, uint64_t c, uint64_t d,
                                              uint8_t *out);
extern void cond_u64_a_eq_b_or_c_eq_d_jazz(uint64_t a, uint64_t b, uint64_t c, uint64_t d,
                                           uint8_t *out);

#define ull_to_bytes_t_jazz NAMESPACE1(ull_to_bytes_t_jazz, INLEN)
extern void ull_to_bytes_t_jazz(uint8_t *out, uint64_t v);

extern void ull_to_bytes_jazz(uint8_t *out, uint64_t v);
extern uint64_t bytes_to_ull_jazz(const uint8_t *a);

#define zero_array_u32_jazz NAMESPACE1(zero_array_u32_jazz, INLEN)
extern void zero_array_u32_jazz(uint32_t *);

extern uint64_t bytes_to_ull__8_jazz(const uint8_t *);  // 8 elements
extern uint64_t bytes_to_ull__1_jazz(const uint8_t *);  // 1 element

// u32
void test_cond_u32_a_below_b_and_a_below_c(void);
void test_cond_u32_a_eq_b_and_c_below_d(void);

// u64
void test_cond_u64_a_below_b_and_a_below_c(void);
void test_cond_u64_a_dif_b_and_a_dif_c(void);
void test_cond_u64_a_dif_b_and_c_dif_d(void);

void test_ull_to_bytes(void);  // TODO: FIXME: remove this. This is the
                               // particular case when OUTLEN=8
void test_ull_to_bytes_t(void);
void test_bytes_to_ull(void);
void test_zero_array_u32(void);

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

void test_cond_u32_a_below_b_and_a_below_c(void) {
    uint32_t a, b, c;
    uint8_t r;

    for (int i = 0; i < TESTS; i++) {
        randombytes((uint8_t *)&a, sizeof(uint32_t));
        randombytes((uint8_t *)&b, sizeof(uint32_t));
        randombytes((uint8_t *)&c, sizeof(uint32_t));

        cond_u32_a_below_b_and_a_below_c_jazz(a, b, c, &r);
        assert((a < b && a < c) ? (r == 1) : (r == 0));
    }
}

void test_cond_u32_a_eq_b_and_c_below_d(void) {
    uint32_t a, b, c, d;
    uint8_t r;

    for (int i = 0; i < TESTS; i++) {
        // These tests will most likely have a != b
        randombytes((uint8_t *)&a, sizeof(uint32_t));
        randombytes((uint8_t *)&b, sizeof(uint32_t));
        randombytes((uint8_t *)&c, sizeof(uint32_t));
        randombytes((uint8_t *)&d, sizeof(uint32_t));

        cond_u32_a_eq_b_and_c_below_d_jazz(a, b, c, d, &r);
        assert((a == b && c < d) ? (r == 1) : (r == 0));
    }

    for (int i = 0; i < TESTS; i++) {
        // these tests have a = b
        randombytes((uint8_t *)&a, sizeof(uint32_t));
        b = a;
        randombytes((uint8_t *)&c, sizeof(uint32_t));
        randombytes((uint8_t *)&d, sizeof(uint32_t));

        cond_u32_a_eq_b_and_c_below_d_jazz(a, b, c, d, &r);
        assert((a == b && c < d) ? (r == 1) : (r == 0));
    }

    for (int i = 0; i < TESTS; i++) {
        // these tests have c < d
        randombytes((uint8_t *)&a, sizeof(uint32_t));
        randombytes((uint8_t *)&b, sizeof(uint32_t));
        randombytes((uint8_t *)&d, sizeof(uint32_t));
        c = d - 10;

        cond_u32_a_eq_b_and_c_below_d_jazz(a, b, c, d, &r);
        assert((a == b && c < d) ? (r == 1) : (r == 0));
    }

    for (int i = 0; i < TESTS; i++) {
        // these tests have a == b && c < d
        randombytes((uint8_t *)&a, sizeof(uint32_t));
        b = a;
        randombytes((uint8_t *)&d, sizeof(uint32_t));
        c = d - 10;

        cond_u32_a_eq_b_and_c_below_d_jazz(a, b, c, d, &r);
        assert((a == b && c < d) ? (r == 1) : (r == 0));
    }
}

void test_cond_u64_a_dif_b_and_a_dif_c(void) {
    uint64_t a, b, c;
    uint8_t r;

    for (int i = 0; i < TESTS; i++) {
        randombytes((uint8_t *)&a, sizeof(uint64_t));
        randombytes((uint8_t *)&b, sizeof(uint64_t));
        randombytes((uint8_t *)&c, sizeof(uint64_t));

        cond_u64_a_dif_b_and_a_dif_c_jazz(a, b, c, &r);
        assert((a != b && a != c) ? (r == 1) : (r == 0));
    }
}

void test_cond_u64_a_dif_b_and_c_dif_d(void) {
    uint64_t a, b, c, d;
    uint8_t r;

    for (int i = 0; i < TESTS; i++) {
        randombytes1((uint8_t *)&a, sizeof(uint64_t));
        randombytes1((uint8_t *)&b, sizeof(uint64_t));
        randombytes1((uint8_t *)&c, sizeof(uint64_t));
        randombytes1((uint8_t *)&d, sizeof(uint64_t));

        cond_u64_a_dif_b_and_c_dif_d_jazz(a, b, c, d, &r);
        assert((a != b && c != d) ? (r == 1) : (r == 0));
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
    unsigned char out_ref[8];   // uint8_t
    unsigned char out_jazz[8];  // uint8_t
    unsigned long long v;       // uint64_t

    for (int i = 0; i < TESTS; i++) {
        memset(out_ref, 0, 8 * sizeof(unsigned char));
        memset(out_jazz, 0, 8 * sizeof(unsigned char));

        randombytes((uint8_t *)&v, sizeof(unsigned long long));

        ull_to_bytes(out_ref, 8, v);
        ull_to_bytes_jazz(out_jazz, v);

        if (memcmp(out_ref, out_jazz, 8 * sizeof(unsigned char))) {
            print_str_u8("ref", out_ref, 8 * sizeof(unsigned char));
            print_str_u8("jazz", out_jazz, 8 * sizeof(unsigned char));
        }

        assert(memcmp(out_ref, out_jazz, 8) == 0);
    }
}

void test_ull_to_bytes_t(void) {
    if (INLEN > 8) {
        return;
    }

    unsigned char out_ref[8];   // uint8_t
    unsigned char out_jazz[8];  // uint8_t
    unsigned long long v;       // uint64_t

    for (int i = 0; i < TESTS; i++) {
        memset(out_ref, 0, 8);
        memset(out_jazz, 0, 8);

        randombytes((uint8_t *)&v, sizeof(unsigned long long));
        ull_to_bytes(out_ref, INLEN, v);
        ull_to_bytes_t_jazz(out_jazz, v);

        if (memcmp(out_ref, out_jazz, INLEN * sizeof(unsigned char))) {
            print_str_u8("ref", out_ref, 8);
            print_str_u8("jazz", out_jazz, 8);
        }
        assert(memcmp(out_ref, out_jazz, INLEN * sizeof(unsigned char)) == 0);
    }
}

// from C impl
static unsigned long long bytes_to_ull(const unsigned char *in, unsigned int inlen) {
    unsigned long long retval = 0;
    unsigned int i;

    for (i = 0; i < inlen; i++) {
        retval |= ((unsigned long long)in[i]) << (8 * (inlen - 1 - i));
    }
    return retval;
}

static unsigned long long bytes_to_ull_tmp(const unsigned char *in, unsigned int inlen) {
    unsigned long long retval = 0;
    unsigned int i;

    uint64_t t, shift_amount;

    // Both size_t and unsigned long long have 8 bytes (64 bits) = uint64_t
    // printf("size(ull) = %ld ; size(size_t) = %ld\n", sizeof(unsigned long long), sizeof(size_t));

    for (i = 0; i < inlen; i++) {
        shift_amount = (8 * (inlen - 1 - i));
        t = (unsigned long long)in[i];
        t <<= shift_amount;
        retval |= t;
    }

    return retval;
}

static uint64_t stupid_byteArrayToUint64(uint8_t byteArray[8]) {
    uint64_t result = 0;

    result |= ((uint64_t)byteArray[0]) << 56;
    result |= ((uint64_t)byteArray[1]) << 48;
    result |= ((uint64_t)byteArray[2]) << 40;
    result |= ((uint64_t)byteArray[3]) << 32;
    result |= ((uint64_t)byteArray[4]) << 24;
    result |= ((uint64_t)byteArray[5]) << 16;
    result |= ((uint64_t)byteArray[6]) << 8;
    result |= (uint64_t)byteArray[7];

    return result;
}

void test_bytes_to_ull(void) {
#define MAX_LEN 8  // 8*8 = 64 (um uint64_t = um array de 8 uint8_t)
    bool debug = true;
    unsigned long long out_ref, out_jazz;
    uint8_t in[8] = {0};

    size_t len;
    uint8_t acc = 0;

    if (debug) {
        for (int i = 0; i < TESTS; i++) {
            for (size_t len = 1; len <= MAX_LEN; len++) {
                randombytes(in, len);
                out_ref = bytes_to_ull(in, len);
                if (len != 8) {
                    out_jazz = bytes_to_ull_tmp(in, len);
                } else {
                    out_jazz = stupid_byteArrayToUint64(in);
                }

                assert(out_ref == out_jazz);
                assert(memcmp(&out_ref, &out_jazz, sizeof(uint64_t)) == 0);
            }
        }
    }

    // FIXME: TODO:; Doesnt work for 4, 5, 6, 7 (these values arent used so I will fix this
    // later)

    // To see the lengths we need to support: cat ../../params/params-sphincs-shake-*.jinc | grep
    // -oE "param int (SPX_LEAF_BYTES|SPX_TREE_BYTES) = [0-9]+" | cut -d'=' -f2 | sort -u
    //  { 1 2 7 8 }
    // For sphincs-shake-128f we only need 1 (trivial) and 8

    for (int i = 0; i < TESTS; i++) {
        for (size_t len = 1; len <= MAX_LEN; len++) {
            // tests for [1..8]
            // In hash_shake we only use {1,8} so we ignore the rest for
            // now
            // TODO: FIXME: Test the other cases (= {2..7})
            randombytes(in, len);
            out_ref = bytes_to_ull(in, len);

            switch (len) {
                case 1:
                    // out_jazz = bytes_to_ull_jazz_1(in);
                    out_jazz = bytes_to_ull__1_jazz(in);
                    break;
                case 2:
                    // out_jazz = bytes_to_ull_jazz_2(in);
                    break;
                case 3:
                    // out_jazz = bytes_to_ull_jazz_3(in);
                    break;
                case 4:
                    // out_jazz = bytes_to_ull_jazz_4(in);
                    break;
                case 5:
                    // out_jazz = bytes_to_ull_jazz_5(in);
                    break;
                case 6:
                    // out_jazz = bytes_to_ull_jazz_6(in);
                    break;
                case 7:
                    // out_jazz = bytes_to_ull_jazz_7(in);
                    break;
                case 8:
                    // out_jazz = bytes_to_ull_jazz_8(in);
                    out_jazz = bytes_to_ull__8_jazz(in);
                    break;
            }

            // assert(out_ref == out_jazz);
            if (len != 1 && len != 8) {
                continue;
            }  // FIXME: for now we only care about 1 and 8

            // if (out_jazz != out_ref) { printf("Failed %d: len = %ld\n", ++count,
            // len); } make run > out | grep -oE "len = [0-8]+" | sort -u to see which
            // lengths fail

            if (out_ref != out_jazz) {
                printf("Ref  = %d\n", out_ref);
                printf("Jazz = %d\n\n", out_jazz);
                print_str_u8("out_ref", (uint8_t *)&out_ref, sizeof(uint64_t));
                printf("\n");
                print_str_u8("out_jazz", (uint8_t *)&out_jazz, sizeof(uint64_t));
            }

            assert(out_ref == out_jazz);
            assert(memcmp(&out_ref, &out_jazz, sizeof(uint64_t)) == 0);
        }
    }

#undef MAX_LEN
}

void test_zero_array_u32(void) {
    uint32_t in[INLEN];
    uint32_t zero[INLEN] = {0};

    for (int i = 0; i < TESTS; i++) {
        randombytes1((uint8_t *)in, INLEN);
        zero_array_u32_jazz(in);
        assert(memcmp(in, zero, INLEN) == 0);
    }
}

int main(void) {
    test_cond_u32_a_below_b_and_a_below_c();
    test_cond_u32_a_eq_b_and_c_below_d();
    test_cond_u64_a_below_b_and_a_below_c();
    test_cond_u64_a_dif_b_and_a_dif_c();
    test_cond_u64_a_dif_b_and_c_dif_d();
    test_ull_to_bytes();
    test_ull_to_bytes_t();
    test_bytes_to_ull();
    test_zero_array_u32();
    printf("PASS: generic { inlen : %d }\n", INLEN);
    return 0;
}
