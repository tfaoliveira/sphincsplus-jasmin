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
#define _xstr(s, e) str(s) #e

#define TIMINGS 10000
#define OP 2

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

void write_values(uint64_t values[OP][TIMINGS], uint64_t results[OP], char *op_str[OP]) {
    int op;
    uint64_t min;
    FILE *f;

    const char *filename_preffix = "values_";

    // write the values for each loop & operation
    for (op = 0; op < OP; op++) {
        // FIXME: filname should be args[1]
        char filename[100];
        strcpy(filename, filename_preffix);  // Copy the prefix
        strcat(filename, xstr(PARAM));
        strcat(filename, xstr(THASH));
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
    int i, op, res;

    char *op_str[OP] = {_xstr(crypto_sign_seed_keypair, .csv), _xstr(crypto_sign_keypair, .csv)};

    uint64_t cycles[TIMINGS];
    uint64_t values[OP][TIMINGS];  // contains all the measurements
    uint64_t results[OP];          // only contains the median

    uint8_t pk[SPX_PK_BYTES];
    uint8_t sk[SPX_SK_BYTES];

    uint8_t seed[CRYPTO_SEEDBYTES];

    // uint8_t m[MAX_MLEN] = {0};
    // size_t msg_len;

    // uint8_t sig[CRYPTO_BYTES] = {0};

    for (i = 0; i < 10; i++) {
        res = crypto_sign_seed_keypair_jazz(pk, sk, seed);
        res = crypto_sign_keypair_jazz(pk, sk);
    }

    op = 0;

    // crypto_sign_seed_keypair
    for (i = 0; i < TIMINGS; i++) {
        cycles[i] = cpucycles();
        res = crypto_sign_seed_keypair_jazz(pk, sk, seed);
    }

    memcpy(values[op], cycles, sizeof(cycles));

    // crypto_sign_keypair
    for (i = 0; i < TIMINGS; i++) {
        cycles[i] = cpucycles();
        res = crypto_sign_keypair_jazz(pk, sk);
    }

    memcpy(values[op], cycles, sizeof(cycles));

    write_values(values, results, op_str);

    printf("Benchmarks for %s %s\n", xstr(PARAMS), xstr(THASH));
    return 0;
}