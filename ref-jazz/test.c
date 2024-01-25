#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "api.h"
#include "context.h"
#include "macros.h"
#include "merkle.h"
#include "params.h"
#include "print.h"
#include "randombytes.h"

#ifndef TESTS
#define TESTS 100
#endif

#ifndef MAX_MLEN
#define MAX_MLEN 128
#endif

int main(void) {
    uint8_t secret_key[CRYPTO_SECRETKEYBYTES];
    uint8_t public_key[CRYPTO_PUBLICKEYBYTES];

    uint8_t signature[CRYPTO_BYTES];
    size_t signature_length;

    uint8_t message[MAX_MLEN];
    size_t message_length;

    for (int i = 0; i < TESTS; i++) {
        for (message_length = 1; message_length < MAX_MLEN; message_length++) {
            printf("[Test %d] Msg Len: %ld/%d\n", i, message_length, MAX_MLEN);
            randombytes(message, message_length);
            crypto_sign_keypair(public_key, secret_key);
            crypto_sign_signature(signature, &signature_length, message, message_length, secret_key);
            assert(crypto_sign_verify(signature, signature_length, message, message_length, public_key) == 0);
        }
    }

    printf("Pass: %s\n", xstr(PARAMS));
    return 0;
}