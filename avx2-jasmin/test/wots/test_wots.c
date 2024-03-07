#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "api.h"
#include "context.h"
#include "hash.h"
#include "hashx4.h"
#include "print.h"
#include "utils.h"
#include "utilsx4.h"
#include "wots.h"
#include "wotsx4.h"

#ifndef TESTS
#define TESTS 10000
#endif

extern void wots_checksum_jazz(uint32_t *csum_base_w, const uint32_t *msg_base_w);
extern void chain_lengths_jazz(uint32_t *lengths, const uint8_t *msg);

void test_wots_checksum(void) {
    bool debug = true;

    uint32_t csum_base_w_ref[SPX_WOTS_LEN2], csum_base_w_jazz[SPX_WOTS_LEN2];
    uint32_t msg_base_w[SPX_WOTS_LEN];

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("[%s]: Wots Checksum: Test %d/%d\n", xstr(PARAMS), i, TESTS);
        }

        memset((uint8_t *)csum_base_w_ref, 0, SPX_WOTS_LEN2 * sizeof(uint32_t));
        memset((uint8_t *)csum_base_w_jazz, 0, SPX_WOTS_LEN2 * sizeof(uint32_t));

        randombytes((uint8_t *)msg_base_w, SPX_WOTS_LEN * sizeof(uint32_t));

        wots_checksum(csum_base_w_ref, msg_base_w);
        wots_checksum_jazz(csum_base_w_jazz, msg_base_w);

        if (memcmp(csum_base_w_ref, csum_base_w_jazz, SPX_WOTS_LEN2 * sizeof(uint32_t)) != 0) {
            print_str_u8("ref", (uint8_t *)csum_base_w_ref, SPX_WOTS_LEN2 * sizeof(uint32_t));
            print_str_u8("jazz", (uint8_t *)csum_base_w_jazz, SPX_WOTS_LEN2 * sizeof(uint32_t));
        }

        assert(memcmp(csum_base_w_ref, csum_base_w_jazz, SPX_WOTS_LEN2 * sizeof(uint32_t)) == 0);
    }
}

void test_chain_lengths(void) {
    bool debug = true;

    unsigned int lengths_ref[SPX_WOTS_LEN];
    uint32_t lengths_jazz[SPX_WOTS_LEN];
    uint8_t msg[SPX_N];

    for (int t = 0; t < TESTS; t++) {
        if (debug) {
            printf("[%s]: Chain Lengths: Test %d/%d\n", xstr(PARAMS), t, TESTS);
        }

        memset(lengths_ref, 0, SPX_WOTS_LEN * sizeof(unsigned int));
        memset(lengths_jazz, 0, SPX_WOTS_LEN * sizeof(uint32_t));
        randombytes(msg, SPX_N);

        chain_lengths(lengths_ref, msg);
        chain_lengths_jazz(lengths_jazz, msg);

        assert(memcmp(lengths_ref, lengths_jazz, SPX_WOTS_LEN * sizeof(uint32_t)) == 0);
    }
}

void test_api(void) {
    bool debug = true;

#define MAX_MESSAGE_LENGTH 1024
#define TESTS 100

    uint8_t secret_key[CRYPTO_SECRETKEYBYTES];
    uint8_t public_key[CRYPTO_PUBLICKEYBYTES];

    uint8_t signature[CRYPTO_BYTES];
    size_t signature_length;

    uint8_t message[MAX_MESSAGE_LENGTH];

    for (int i = 0; i < TESTS; i++) {
        for (size_t message_length = 1; message_length < MAX_MESSAGE_LENGTH; message_length++) {
            if (debug) {
                printf("[%s]: Test %d/%d [Len=%ld]\n", xstr(PARAMS), i, TESTS, message_length);
            }

            randombytes(message, message_length);
            crypto_sign_keypair(public_key, secret_key);
            crypto_sign_signature(signature, &signature_length, message, message_length, secret_key);
            assert(signature_length == CRYPTO_BYTES);
            assert(crypto_sign_verify(signature, signature_length, message, message_length, public_key) == 0);
        }
    }

#undef MESSAGE_LENGTH
}

int main(void) {
    test_wots_checksum();  // Same as ref-jasmin
    test_chain_lengths();  // Same as ref-jasmin
    test_api();
    return 0;
}
