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

#ifndef KEY_GEN_TESTS
#define KEY_GEN_TESTS 1000
#endif

#ifndef MAX_MLEN
#define MAX_MLEN 128
#endif

int fors_sign_test_number = 0;
int fors_pk_from_sig_test_number = 0;

extern int crypto_sign_seed_keypair_jazz(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int crypto_sign_keypair_jazz(uint8_t *pk, uint8_t *sk);
extern int crypto_sign_signature_jazz(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
#if 0
extern int crypto_sign_jazz(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int crypto_sign_open_jazz(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *pk);
#endif
extern int crypto_sign_verify_jazz(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);

/*
void test_crypto_sign_seed_keypair(void);
void test_crypto_sign_keypair(void);
void test_crypto_sign_signature(void);
void test_crypto_sign_verify(void);
void test_crypto_sign(void);
void test_crypto_sign_open(void);
*/

static void flip_bits(uint8_t *array, size_t len, size_t num_bits_to_flip) {
    size_t random_index;
    for (size_t i = 0; i < num_bits_to_flip; ++i) {
        // Generate a random index within the array
        randombytes((uint8_t *)&random_index, sizeof(size_t));
        random_index = random_index % (len * sizeof(uint8_t) * 8);

        // Calculate the byte index and bit index within that byte
        size_t byte_index = random_index / 8;
        size_t bit_index = random_index % 8;

        // Flip the selected bit using bitwise XOR
        array[byte_index] ^= (1 << bit_index);
    }
}

void test_crypto_sign_seed_keypair(void) {
    bool debug = true;

    uint8_t pk_jazz[SPX_PK_BYTES];
    uint8_t sk_jazz[SPX_SK_BYTES];

    unsigned char pk_ref[SPX_PK_BYTES];
    unsigned char sk_ref[SPX_SK_BYTES];

    uint8_t seed[CRYPTO_SEEDBYTES];

    int res_ref, res_jazz;

    for (int i = 0; i < KEY_GEN_TESTS; i++) {
        if (debug) {
            printf("[%s %s]: Key gen (w/ seed): Test %d/%d\n", xstr(PARAMS), xstr(THASH), i, KEY_GEN_TESTS);
        }

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

    for (int i = 0; i < KEY_GEN_TESTS; i++) {
        if (debug) {
            printf("[%s %s]: Key gen: Test %d/%d\n", xstr(PARAMS), xstr(THASH), i, KEY_GEN_TESTS);
        }

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
    bool debug = true;

    uint8_t pk_jazz[SPX_PK_BYTES];  // ignored (used to generate a valid keypair)
    uint8_t sk_jazz[SPX_SK_BYTES];

    uint8_t pk_ref[SPX_PK_BYTES];  // ignored (used to generate a valid keypair)
    uint8_t sk_ref[SPX_SK_BYTES];

    uint8_t m_jazz[MAX_MLEN] = {0};
    uint8_t m_ref[MAX_MLEN] = {0};
    size_t msg_len;

    uint8_t sig_ref[CRYPTO_BYTES];
    uint8_t sig_jazz[CRYPTO_BYTES];

    size_t signature_length_ref;
    size_t signature_length_jazz;

    for (int i = 0; i < TESTS; i++) {
        for (msg_len = 1; msg_len <= MAX_MLEN; msg_len++) {
            if (debug) {
                printf("[%s %s]: Sign Signature: Test %d/%d [len=%d]\n", xstr(PARAMS), xstr(THASH), i, TESTS, msg_len);
            }

            // generate a valid key pair
            crypto_sign_keypair(pk_ref, sk_ref);
            memcpy(sk_jazz, sk_ref, SPX_SK_BYTES);

            memset(sig_ref, 0, CRYPTO_BYTES);
            memset(sig_jazz, 0, CRYPTO_BYTES);

            randombytes(m_ref, msg_len);
            memcpy(m_jazz, m_ref, msg_len);

            signature_length_ref = 0;
            signature_length_jazz = 0;

            assert(memcmp(m_ref, m_jazz, msg_len) == 0);
            assert(memcmp(sk_ref, sk_jazz, SPX_SK_BYTES) == 0);

            resetrandombytes();
            resetrandombytes1();

            crypto_sign_signature(sig_ref, &signature_length_ref, m_ref, msg_len, sk_ref);
            crypto_sign_signature_jazz(sig_jazz, &signature_length_jazz, m_jazz, msg_len, sk_jazz);

            assert(signature_length_jazz == signature_length_ref);
            assert(signature_length_jazz == CRYPTO_BYTES);

            assert(memcmp(sig_ref, sig_jazz, CRYPTO_BYTES) == 0);
        }
    }
}

void test_crypto_sign_verify(void) {
    bool debug = true;

    uint8_t pk[SPX_PK_BYTES];
    uint8_t sk[SPX_SK_BYTES];

    uint8_t m[MAX_MLEN] = {0};
    size_t msg_len;

    uint8_t sig[CRYPTO_BYTES];
    uint8_t sig_jazz[CRYPTO_BYTES];
    size_t signature_length;

    int res_ref, res_jazz;

    // Test valid signatures
    for (int i = 0; i < TESTS; i++) {
        for (msg_len = 1; msg_len <= MAX_MLEN; msg_len++) {
            if (debug) {
                printf("[%s %s]: Verify valid signatures: Test %d/%d [len=%d]\n", xstr(PARAMS), xstr(THASH), i, TESTS,
                       msg_len);
            }

            // Generate a valid key pair
            crypto_sign_keypair(pk, sk);

            // Generate a random message and the respective signature
            randombytes(m, msg_len);

            // Generate a valid signature
            crypto_sign_signature(sig, &signature_length, m, msg_len, sk);

            // Verify the signature and compare Jasmin & reference implementations
            res_ref = crypto_sign_verify(sig, signature_length, m, msg_len, pk);
            res_jazz = crypto_sign_verify_jazz(sig, signature_length, m, msg_len, pk);
            assert(res_ref == res_jazz);
        }
    }

    if (debug) {
        puts("crypto_sign_signature passed the tests on valid signatures");
    }

    for (int i = 0; i < TESTS; i++) {
        for (msg_len = 10; msg_len < MAX_MLEN; msg_len++) {
            if (debug) {
                printf("[%s %s]: Verify invalid signatures: Test %d/%d [len=%d]\n", xstr(PARAMS), xstr(THASH), i, TESTS,
                       msg_len);
            }

            // generate a valid key pair
            crypto_sign_keypair(pk, sk);

            // Generate a random message and the respective signature
            randombytes(m, msg_len);

            // Generate a valid signature
            crypto_sign_signature(sig, &signature_length, m, msg_len, sk);

            // Invalidate the signature by flipping some (= 3) bits
            // TODO: TEST WITH MORE VALUES
            flip_bits(sig, signature_length, 3);

            // Verify the signature and compare Jasmin & reference implementations
            res_ref = crypto_sign_verify(sig, signature_length, m, msg_len, pk);
            res_jazz = crypto_sign_verify_jazz(sig, signature_length, m, msg_len, pk);

            assert(res_ref == res_jazz);
        }
    }

    if (debug) {
        print_green("[DEBUG] ");
        puts("crypto_sign_signature passed the tests on invalid signatures");
    }

    // Test with a invalid keypair
    for (int i = 0; i < TESTS; i++) {
        for (msg_len = 10; msg_len < MAX_MLEN; msg_len++) {
            // generate a valid key pair
            crypto_sign_keypair(pk, sk);

            // Generate a random message
            randombytes(m, msg_len);

            // Generate a valid signature
            crypto_sign_signature(sig, &signature_length, m, msg_len, sk);

            // Invalidate the public key by flipping some (= 3) bits
            // TODO: TEST WITH MORE VALUES
            flip_bits(pk, SPX_PK_BYTES, 3);

            // Verify the signature and compare Jasmin & reference implementations
            res_ref = crypto_sign_verify(sig, signature_length, m, msg_len, pk);
            res_jazz = crypto_sign_verify_jazz(sig, signature_length, m, msg_len, pk);

            assert(res_ref == res_jazz);
        }
    }

    if (debug) {
        print_green("[DEBUG] ");
        puts("crypto_sign_signature passed the tests on invalid keypairs");
    }
}

void test_crypto_sign(void) {
    bool debug = true;

    uint8_t pk_jazz[SPX_PK_BYTES];  // ignored (used to generate a valid keypair)
    uint8_t sk_jazz[SPX_SK_BYTES];

    uint8_t pk_ref[SPX_PK_BYTES];  // ignored (used to generate a valid keypair)
    uint8_t sk_ref[SPX_SK_BYTES];

    uint8_t m_jazz[MAX_MLEN] = {0};
    uint8_t m_ref[MAX_MLEN] = {0};
    
    size_t message_length;

    uint8_t sig_ref[CRYPTO_BYTES];
    uint8_t sig_jazz[CRYPTO_BYTES];

    size_t signature_length_ref;
    size_t signature_length_jazz;

    int res_ref, res_jazz;

    for (int i = 0; i < TESTS; i++) {
    }
}

void test_crypto_sign_open(void) {
    // TODO: improve test
    bool debug = true;

    uint8_t pk_jazz[SPX_PK_BYTES];  // ignored (used to generate a valid keypair)
    uint8_t sk_jazz[SPX_SK_BYTES];

    uint8_t pk_ref[SPX_PK_BYTES];  // ignored (used to generate a valid keypair)
    uint8_t sk_ref[SPX_SK_BYTES];

    uint8_t m_jazz[MAX_MLEN] = {0};
    uint8_t m_ref[MAX_MLEN] = {0};
    size_t msg_len_ref, msg_len_jazz;

    uint8_t sig_ref[CRYPTO_BYTES];
    uint8_t sig_jazz[CRYPTO_BYTES];

    size_t signature_length_ref;
    size_t signature_length_jazz;

    int res_ref, res_jazz;

    for (int i = 0; i < TESTS; i++) {
        for (size_t msg_len = 1; msg_len <= MAX_MLEN; msg_len++) {
            if (debug) {
                printf("[%s %s]: Sign Open: Test %d/%d [len=%d]\n", xstr(PARAMS), xstr(THASH), i, TESTS, msg_len);
            }

            // generate a valid key pair
            crypto_sign_keypair(pk_ref, sk_ref);
            memcpy(pk_jazz, pk_ref, CRYPTO_PUBLICKEYBYTES);
            memcpy(sk_jazz, sk_ref, CRYPTO_SECRETKEYBYTES);

            // Generate a random message
            randombytes(m_ref, msg_len);
            memcpy(m_jazz, m_ref, msg_len);

            signature_length_ref = CRYPTO_BYTES;
            signature_length_jazz = CRYPTO_BYTES;

            memset(sig_ref, 0, CRYPTO_BYTES);
            memset(sig_jazz, 0, CRYPTO_BYTES);

            assert(!memcmp(m_jazz, m_ref, msg_len));
            assert(!memcmp(pk_jazz, pk_ref, CRYPTO_PUBLICKEYBYTES));

            res_ref = crypto_sign_open(m_ref, &msg_len_jazz, sig_ref, signature_length_ref, pk_ref);
            res_jazz = crypto_sign_open(m_jazz, &msg_len_ref, sig_jazz, signature_length_jazz, pk_jazz);

            assert(res_jazz == res_ref);
            assert(msg_len_jazz == msg_len_ref);
        }
    }
}

int main(void) {
    test_crypto_sign_keypair();       // WORKS
    test_crypto_sign_seed_keypair();  // WORKS
    test_crypto_sign_signature(); // WORKS
    test_crypto_sign_verify(); // WORKS
    // test_crypto_sign();
    // test_crypto_sign_open(); 
    printf("Pass sign: { params: %s ; thash: %s }\n", xstr(PARAMS), xstr(THASH));
    return 0;
}
