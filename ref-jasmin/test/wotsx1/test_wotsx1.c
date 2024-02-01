#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "context.h"
#include "macros.h"
#include "merkle.h"
#include "notrandombytes.c"
#include "params.h"
#include "print.c"

#ifndef HASH
#define HASH shake
#endif

#ifndef PARAM
#define PARAM 128f
#endif

#ifndef THASH
#define THASH simple
#endif

#ifndef TESTS
#define TESTS 100
#endif

int main(void) {
    bool debug = true;

#define MAX_MESSAGE_LENGTH 1024

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
            // assert(crypto_sign_verify(signature, signature_length, message, message_length, public_key) == 0);
            crypto_sign_verify(signature, signature_length, message, message_length, public_key);
        }
    }

#undef MESSAGE_LENGTH

    printf("Pass treehash_wots : { params : %s ; thash : %s }\n", xstr(PARAMS), xstr(THASH));
    return 0;
}
