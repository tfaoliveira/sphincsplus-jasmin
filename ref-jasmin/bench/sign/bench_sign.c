#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "api.h"
#include "cpucycles.c"
#include "params.h"
#include "randombytes.h"

#define str(s) #s
#define xstr(s) str(s)

#define TIMINGS 10000

#ifndef HASH
#define HASH shake
#endif

#ifndef PARAM
#define PARAM 128f
#endif

#ifndef THASH
#define THASH simple
#endif

#ifndef MAX_MLEN
#define MAX_MLEN 128
#endif

extern int crypto_sign_seed_keypair_jazz(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int crypto_sign_keypair_jazz(uint8_t *pk, uint8_t *sk);
extern int crypto_sign_signature_jazz(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int crypto_sign_verify_jazz(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);

static void write_values_keygen(uint64_t values[2][TIMINGS], const char **op_str) {
    // OP = 2; KEY GEN WITH SEED AND WITHOUT SEED
    int op;
    FILE *f;
    char filename[100];

    // write the values for each loop & operation
    for (op = 0; op < 2; op++) {
#ifdef BENCH_JASMIN
        strcat(filename, "bench_jasmin_sphincs_plus_");
#else
        strcat(filename, "bench_ref_sphincs_plus_");
#endif
        strcat(filename, xstr(PARAM));
        strcat(filename, "_");
        strcat(filename, xstr(THASH));
        strcat(filename, "_");
        strcat(filename, op_str[op]);

        f = fopen(filename, "w");

        if (f != NULL) {
            for (size_t i = 0; i < TIMINGS - 1; i++) {
                values[op][i] = values[op][i + 1] - values[op][i];
            }
            // Write the values
            for (size_t i = 0; i < TIMINGS - 1; i++) {
                fprintf(f, "%" PRIu64 "\n", values[op][i]);
            }
            fclose(f);
        }

        // Clear the filename array
        memset(filename, 0, sizeof(filename));
    }
}

int main(void) {
    int i, res;

    uint64_t cycles[TIMINGS];
    uint64_t values_keygen[2][TIMINGS];                 // contains all measurements for keygen
    uint64_t values_sign_verify[2][MAX_MLEN][TIMINGS];  // contains all measurements for other operations

    uint8_t pk[SPX_PK_BYTES];
    uint8_t sk[SPX_SK_BYTES];

    uint8_t seed[CRYPTO_SEEDBYTES];

    uint8_t m[MAX_MLEN] = {0};
    size_t msg_len = 1024;

    uint8_t sig[CRYPTO_BYTES] = {0};
    size_t siglen;

    size_t index;

    char *op_str[] = {"crypto_sign_seed_keypair.csv", "crypto_sign_keypair.csv", "crypto_sign_signature.csv",
                      "crypto_sign_verify.csv"};

    puts("Comecou o warmup");

    for (i = 0; i < 10; i++) {
#ifdef BENCH_JASMIN
        res = crypto_sign_seed_keypair_jazz(pk, sk, seed);
        res = crypto_sign_keypair_jazz(pk, sk);
        res = crypto_sign_signature_jazz(sig, &siglen, m, msg_len, sk);
        res = crypto_sign_verify_jazz(sig, CRYPTO_BYTES, m, msg_len, pk);
#else
        res = crypto_sign_seed_keypair(pk, sk, seed);
        res = crypto_sign_keypair(pk, sk);
        res = crypto_sign_signature(sig, &siglen, m, msg_len, sk);
        res = crypto_sign_verify(sig, CRYPTO_BYTES, m, msg_len, pk);
#endif
    }

    puts("Acabou o warmup");

    // crypto_sign_seed_keypair
    for (i = 0; i < TIMINGS; i++) {
        cycles[i] = cpucycles();

#ifdef BENCH_JASMIN
        res = crypto_sign_seed_keypair_jazz(pk, sk, seed);
#else
        res = crypto_sign_seed_keypair(pk, sk, seed);
#endif
    }
    memcpy(values_keygen[0], cycles, sizeof(cycles));

    // crypto_sign_keypair
    for (i = 0; i < TIMINGS; i++) {
        cycles[i] = cpucycles();

#ifdef BENCH_JASMIN
        res = crypto_sign_keypair_jazz(pk, sk);
#else
        res = crypto_sign_keypair(pk, sk);
#endif
    }
    memcpy(values_keygen[1], cycles, sizeof(cycles));

    write_values_keygen(values_keygen, op_str);

    // Sign
    for (int mlen = 1; mlen <= MAX_MLEN; mlen++) {
        for (i = 0; i < TIMINGS; i++) {
            cycles[i] = cpucycles();
            #ifdef BENCH_JASMIN
            res = crypto_sign_signature_jazz(sig, &siglen, m, msg_len, sk);
#else
            res = crypto_sign_signature(sig, &siglen, m, msg_len, sk);
#endif

        }
        index = mlen - 1;
        for (size_t j = 0; j < TIMINGS; j++) {
            values_sign_verify[0][index][j] = cycles[j];
        }  // memcpy(values_sign_verify[0][index], cycles, sizeof(cycles)); causes a segfault
    }

    // Verify
    for (int mlen = 1; mlen <= MAX_MLEN; mlen++) {
        for (i = 0; i < TIMINGS; i++) {
            cycles[i] = cpucycles();
#ifdef BENCH_JASMIN
            res = crypto_sign_verify_jazz(sig, siglen, m, msg_len, sk);
#else
            res = crypto_sign_verify(sig, CRYPTO_BYTES, m, msg_len, sk);
#endif
        }
        index = mlen - 1;
        for (size_t j = 0; j < TIMINGS; j++) {
            values_sign_verify[1][index][j] = cycles[j];
        }  // memcpy(values_sign_verify[1][index], cycles, sizeof(cycles)); causes a segfault
    }

    printf("Benchmarks for %s %s\n", xstr(PARAMS), xstr(THASH));
    return 0;
}