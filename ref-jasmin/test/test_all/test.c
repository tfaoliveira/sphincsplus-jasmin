#include "api.h"

#ifndef PARAMS
#define PARAMS sphincs-shake-128f
#endif

#ifndef MAX_MESSAGE_LENGTH
#define MAX_MESSAGE_LENGTH 1024
#endif

#ifndef TESTS
#define TESTS 100
#endif


int main(void) {
    uint8_t secret_key[CRYPTO_SECRETKEYBYTES];
    uint8_t public_key[CRYPTO_PUBLICKEYBYTES];

    uint8_t signature[CRYPTO_BYTES];
    size_t signature_length;

    uint8_t message[MAX_MESSAGE_LENGTH];
    size_t message_length;

    for (int i = 0; i < TESTS; i++) {
        for (message_length = 1; message_length < MAX_MESSAGE_LENGTH; message_length++) {
            printf("[Test %d] Msg Len: %ld/%d\n", i, message_length, MAX_MESSAGE_LENGTH);
            randombytes(message, message_length);
            crypto_sign_keypair(public_key, secret_key);
            crypto_sign_signature(signature, &signature_length, message, message_length, secret_key);
            assert(crypto_sign_verify(signature, signature_length, message, message_length, public_key) == 0);
        }
    }

    printf("Pass: %s\n", xstr(PARAMS));

    return 0;
}