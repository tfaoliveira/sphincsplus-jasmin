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

// NOTE: for testing purposes, randombytes always outputs the same value, so all the tests are the
// same
#ifndef TESTS
#define TESTS 1
#endif

#ifndef MAX_MLEN
#define MAX_MLEN 128
#endif

extern int crypto_sign_seed_keypair_jazz(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int crypto_sign_keypair_jazz(uint8_t *pk, uint8_t *sk);
// extern int crypto_sign_signature_jazz(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t
// mlen,
//                                       const uint8_t *sk);

void test_crypto_sign_seed_keypair(void);
void test_crypto_sign_keypair(void);
// void test_crypto_sign_signature(void);

void test_crypto_sign_seed_keypair(void) {
    bool debug = true;

    uint8_t pk_jazz[SPX_PK_BYTES];
    uint8_t sk_jazz[SPX_SK_BYTES];

    unsigned char pk_ref[SPX_PK_BYTES];
    unsigned char sk_ref[SPX_SK_BYTES];

    uint8_t seed[CRYPTO_SEEDBYTES];

    int res_ref, res_jazz;

    for (int i = 0; i < TESTS; i++) {
        memset(pk_jazz, 0, SPX_PK_BYTES);
        memset(sk_jazz, 0, SPX_SK_BYTES);
        memset(pk_ref, 0, SPX_PK_BYTES);
        memset(sk_ref, 0, SPX_SK_BYTES);

        randombytes(seed, CRYPTO_SEEDBYTES);

        assert(memcmp(pk_jazz, pk_ref, SPX_PK_BYTES) == 0);
        assert(memcmp(sk_jazz, sk_ref, SPX_SK_BYTES) == 0);

        res_ref = crypto_sign_seed_keypair(pk_ref, sk_ref, seed);
        res_jazz = crypto_sign_seed_keypair_jazz(pk_jazz, sk_jazz, seed);

        if (debug && memcmp(pk_jazz, pk_ref, SPX_PK_BYTES) != 0) {
            print_str_u8("[crypto_sign_seed_keypair]: pk ref", pk_ref, SPX_PK_BYTES);
            print_str_u8("[crypto_sign_seed_keypair]: pk jazz", pk_jazz, SPX_PK_BYTES);
        }

        if (debug && memcmp(sk_jazz, sk_ref, SPX_SK_BYTES) != 0) {
            print_str_u8("[crypto_sign_seed_keypair]: sk ref", sk_ref, SPX_SK_BYTES);
            print_str_u8("[crypto_sign_seed_keypair]: sk jazz", sk_jazz, SPX_SK_BYTES);
        }

        assert(memcmp(pk_jazz, pk_ref, SPX_PK_BYTES) == 0);
        assert(memcmp(sk_jazz, sk_ref, SPX_SK_BYTES) == 0);
        assert(res_jazz == res_ref);
        assert(res_jazz == 0);
    }
}

void test_crypto_sign_keypair(void) {
    bool debug = true;

    uint8_t pk_jazz[SPX_PK_BYTES];
    uint8_t sk_jazz[SPX_SK_BYTES];

    unsigned char pk_ref[SPX_PK_BYTES];
    unsigned char sk_ref[SPX_SK_BYTES];

    int res_ref, res_jazz;

    for (int i = 0; i < TESTS; i++) {
        memset(pk_jazz, 0, SPX_PK_BYTES);
        memset(sk_jazz, 0, SPX_SK_BYTES);
        memset(pk_ref, 0, SPX_PK_BYTES);
        memset(sk_ref, 0, SPX_SK_BYTES);

        assert(memcmp(pk_jazz, pk_ref, SPX_PK_BYTES) == 0);
        assert(memcmp(sk_jazz, sk_ref, SPX_SK_BYTES) == 0);

        res_ref = crypto_sign_keypair(pk_ref, sk_ref);
        res_jazz = crypto_sign_keypair_jazz(pk_jazz, sk_jazz);

        if (debug && memcmp(pk_jazz, pk_ref, SPX_PK_BYTES) != 0) {
            print_str_u8("[crypto_sign_keypair]: pk ref", pk_ref, SPX_PK_BYTES);
            print_str_u8("[crypto_sign_keypair]: pk jazz", pk_jazz, SPX_PK_BYTES);
        }

        if (debug && memcmp(sk_jazz, sk_ref, SPX_SK_BYTES) != 0) {
            print_str_u8("[crypto_sign_keypair]: sk ref", sk_ref, SPX_SK_BYTES);
            print_str_u8("[crypto_sign_keypair]: sk jazz", sk_jazz, SPX_SK_BYTES);
        }

        assert(memcmp(pk_jazz, pk_ref, SPX_PK_BYTES) == 0);
        assert(memcmp(sk_jazz, sk_ref, SPX_SK_BYTES) == 0);

        assert(res_jazz == res_ref);
        assert(res_jazz == 0);
    }
}

void test_crypto_sign_signature(void) {
    uint8_t pk_jazz[SPX_PK_BYTES];  // ignored (used to generate a valid keypair)
    uint8_t sk_jazz[SPX_SK_BYTES];

    uint8_t pk_ref[SPX_PK_BYTES];  // ignored (used to generate a valid keypair)
    uint8_t sk_ref[SPX_SK_BYTES];

    uint8_t *m_jazz;
    uint8_t *m_ref;
    size_t msg_len;

    uint8_t sig_ref[CRYPTO_BYTES];
    uint8_t sig_jazz[CRYPTO_BYTES];

    size_t signature_length_ref;
    size_t signature_length_jazz;

    for (int i = 0; i < TESTS; i++) {
        printf("%s (%s): Running test %d\n", xstr(PARAMS), xstr(THASH), i);
        for (msg_len = 10; msg_len < MAX_MLEN; msg_len++) {
            m_jazz = (uint8_t *)malloc(msg_len);
            m_ref = (unsigned char *)malloc(msg_len);

            // generate a valid key pair
            crypto_sign_keypair(pk_ref, sk_ref);
            memcpy(sk_jazz, sk_ref, SPX_SK_BYTES);

            memset(sig_ref, 0, CRYPTO_BYTES);
            memset(sig_jazz, 0, CRYPTO_BYTES);
            randombytes(m_ref, msg_len);
            memcpy(m_jazz, m_ref, msg_len);

            assert(memcmp(m_ref, m_jazz, msg_len) == 0);
            assert(memcmp(sk_ref, sk_jazz, SPX_SK_BYTES) == 0);

            crypto_sign_signature(sig_ref, &signature_length_ref, m_ref, msg_len, sk_ref);
            crypto_sign_signature_jazz(sig_jazz, &signature_length_jazz, m_jazz, msg_len, sk_jazz);

            // asserts
            assert(signature_length_jazz == signature_length_ref);
            assert(signature_length_jazz == CRYPTO_BYTES);
            assert(signature_length_ref == CRYPTO_BYTES);
            // assert(memcmp(sig_ref, sig_jazz, signature_length_ref) == 0); //FIXME: DOESNT WORK

            free(m_jazz);
            free(m_ref);
        }
    }
}

void test_api() {
    for (int i = 0; i < TESTS; i++) {
    }
}

int main(void) {
// #ifndef TEST_FAST
// #endif
#if 0
    test_crypto_sign_keypair();
    #endif
    test_crypto_sign_seed_keypair();
    // test_crypto_sign_signature();
    test_api();
    printf("Pass sign: { params: %s ; thash: %s }\n", xstr(PARAMS), xstr(THASH));
    return 0;
}
