#include <assert.h>
#include <immintrin.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "print.h"
#include "randombytes.h"

#ifndef TESTS
#define TESTS 1000
#endif

extern void mm256_set_epi32_jazz(const void *);

__m256i mm256_set_epi32_jazz_wrapper(uint32_t e0, uint32_t e1, uint32_t e2, uint32_t e3, uint32_t e4, uint32_t e5,
                                     uint32_t e6, uint32_t e7);

void test_mm256_set_epi32_jazz(void);

__m256i mm256_set_epi32_jazz_wrapper(uint32_t e0, uint32_t e1, uint32_t e2, uint32_t e3, uint32_t e4, uint32_t e5,
                                     uint32_t e6, uint32_t e7) {
    __m256i res;

    void *args[9];

    args[0] = (void *)&e0;
    args[1] = (void *)&e1;
    args[2] = (void *)&e2;
    args[3] = (void *)&e3;
    args[4] = (void *)&e4;
    args[5] = (void *)&e5;
    args[6] = (void *)&e6;
    args[7] = (void *)&e7;
    args[8] = (void *)&res;

    mm256_set_epi32_jazz(args);

    return res;
}

void test_mm256_set_epi32_jazz(void) {
    uint32_t e0, e1, e2, e3, e4, e5, e6, e7;
    __m256i res_ref, res_jazz;

    for (int i = 0; i < TESTS; i++) {
        memset(&res_ref, 0, sizeof(__m256i));
        memset(&res_jazz, 0, sizeof(__m256i));

        randombytes((uint8_t *)&e0, sizeof(uint32_t));
        randombytes((uint8_t *)&e1, sizeof(uint32_t));
        randombytes((uint8_t *)&e2, sizeof(uint32_t));
        randombytes((uint8_t *)&e3, sizeof(uint32_t));
        randombytes((uint8_t *)&e4, sizeof(uint32_t));
        randombytes((uint8_t *)&e5, sizeof(uint32_t));
        randombytes((uint8_t *)&e6, sizeof(uint32_t));
        randombytes((uint8_t *)&e7, sizeof(uint32_t));

        res_ref = _mm256_set_epi32(e0, e1, e2, e3, e4, e5, e6, e7);
        res_jazz = mm256_set_epi32_jazz_wrapper(e0, e1, e2, e3, e4, e5, e6, e7);

        if (memcmp(&res_ref, &res_jazz, sizeof(__m256i)) != 0) {
            print_str_u8("e0", (uint8_t *)&e0, sizeof(uint32_t));
            print_str_u8("e1", (uint8_t *)&e1, sizeof(uint32_t));
            print_str_u8("e2", (uint8_t *)&e2, sizeof(uint32_t));
            print_str_u8("e3", (uint8_t *)&e3, sizeof(uint32_t));
            print_str_u8("e4", (uint8_t *)&e4, sizeof(uint32_t));
            print_str_u8("e5", (uint8_t *)&e5, sizeof(uint32_t));
            print_str_u8("e6", (uint8_t *)&e6, sizeof(uint32_t));
            print_str_u8("e7", (uint8_t *)&e7, sizeof(uint32_t));

            puts("\n\n");

            print_str_u8("ref", (uint8_t *)&res_ref, sizeof(__m256i));
            print_str_u8("jazz", (uint8_t *)&res_jazz, sizeof(__m256i));
        }

        assert(memcmp(&res_ref, &res_jazz, sizeof(__m256i)) == 0);
    }
}

int main(void) {
    test_mm256_set_epi32_jazz();
    puts("[mm256_set_epi32_jazz] Pass");
    return 0;
}