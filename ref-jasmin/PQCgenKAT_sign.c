
//
//  PQCgenKAT_sign.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "rng.h"

#include "macros.h"

#define MAX_MARKER_LEN 50

#define KAT_SUCCESS 0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR -3
#define KAT_CRYPTO_FAILURE -4

uint8_t *__jasmin_syscall_randombytes__(uint8_t *x, uint64_t xlen) {
    randombytes(x, xlen);
    return x;
}

extern int crypto_sign_keypair_jazz(uint8_t *pk, uint8_t *sk);
extern int crypto_sign_signature_jazz(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int crypto_sign_verify_jazz(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);

#define crypto_sign_keypair crypto_sign_keypair_jazz

int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk)
{
    size_t siglen;

    crypto_sign_signature_jazz(sm, &siglen, m, (size_t)mlen, sk);

    memmove(sm + SPX_BYTES, m, mlen);
    *smlen = siglen + mlen;

    return 0;
}

int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk)
{
    /* The API caller does not necessarily know what size a signature should be
       but SPHINCS+ signatures are always exactly SPX_BYTES. */
    if (smlen < SPX_BYTES) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }

    *mlen = smlen - SPX_BYTES;

    if (crypto_sign_verify_jazz(sm, SPX_BYTES, sm + SPX_BYTES, (size_t)*mlen, pk)) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }

    /* If verification was successful, move the message to the right place. */
    memmove(m, sm + SPX_BYTES, *mlen);

    return 0;
}

int FindMarker(FILE *infile, const char *marker);
int ReadHex(FILE *infile, unsigned char *A, int Length, char *str);
void fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);

char AlgName[] = "My Alg Name";

int main(void) {
    char fn_req[32], fn_rsp[32];
    FILE *fp_req, *fp_rsp;
    unsigned char seed[48];
    unsigned char msg[3300];
    unsigned char entropy_input[48];
    unsigned char *m, *sm, *m1;
    unsigned long long mlen, smlen, mlen1;
    int count;
    int done;
    unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    int ret_val;

    // Create the REQUEST file
    sprintf(fn_req, "PQCsignKAT_%d.req", CRYPTO_SECRETKEYBYTES);
    if ((fp_req = fopen(fn_req, "w")) == NULL) {
        printf("Couldn't open <%s> for write\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }
    sprintf(fn_rsp, "PQCsignKAT_%d.rsp", CRYPTO_SECRETKEYBYTES);
    if ((fp_rsp = fopen(fn_rsp, "w")) == NULL) {
        printf("Couldn't open <%s> for write\n", fn_rsp);
        return KAT_FILE_OPEN_ERROR;
    }

    for (int i = 0; i < 48; i++) entropy_input[i] = (unsigned char)i;

    randombytes_init(entropy_input, NULL);
    for (int i = 0; i < 100; i++) {
        printf("Kat #%d\n", i);
        
        fprintf(fp_req, "count = %d\n", i);
        randombytes(seed, 48);
        fprintBstr(fp_req, "seed = ", seed, 48);
        mlen = (unsigned long long int)(33 * (i + 1));
        fprintf(fp_req, "mlen = %llu\n", mlen);
        randombytes(msg, mlen);
        fprintBstr(fp_req, "msg = ", msg, mlen);
        fprintf(fp_req, "pk =\n");
        fprintf(fp_req, "sk =\n");
        fprintf(fp_req, "smlen =\n");
        fprintf(fp_req, "sm =\n\n");
    }
    fclose(fp_req);

    // Create the RESPONSE file based on what's in the REQUEST file
    if ((fp_req = fopen(fn_req, "r")) == NULL) {
        printf("Couldn't open <%s> for read\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }

    fprintf(fp_rsp, "# %s\n\n", CRYPTO_ALGNAME);
    done = 0;
    do {
        if (FindMarker(fp_req, "count = "))
            ret_val = fscanf(fp_req, "%d", &count);
        else {
            done = 1;
            break;
        }
        fprintf(fp_rsp, "count = %d\n", count);

        if (!ReadHex(fp_req, seed, 48, "seed = ")) {
            printf("ERROR: unable to read 'seed' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintBstr(fp_rsp, "seed = ", seed, 48);

        randombytes_init(seed, NULL);

        if (FindMarker(fp_req, "mlen = "))
            ret_val = fscanf(fp_req, "%llu", &mlen);
        else {
            printf("ERROR: unable to read 'mlen' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintf(fp_rsp, "mlen = %llu\n", mlen);

        m = (unsigned char *)calloc(mlen, sizeof(unsigned char));
        m1 = (unsigned char *)calloc(mlen + CRYPTO_BYTES, sizeof(unsigned char));
        sm = (unsigned char *)calloc(mlen + CRYPTO_BYTES, sizeof(unsigned char));

        if (!ReadHex(fp_req, m, (int)mlen, "msg = ")) {
            printf("ERROR: unable to read 'msg' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintBstr(fp_rsp, "msg = ", m, mlen);

        // Generate the public/private keypair
        if ((ret_val = crypto_sign_keypair(pk, sk)) != 0) {
            printf("crypto_sign_keypair returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        fprintBstr(fp_rsp, "pk = ", pk, CRYPTO_PUBLICKEYBYTES);
        fprintBstr(fp_rsp, "sk = ", sk, CRYPTO_SECRETKEYBYTES);

        if ((ret_val = crypto_sign(sm, &smlen, m, mlen, sk)) != 0) {
            printf("[%s]: crypto_sign returned <%d>\n", xstr(PARAMS), ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        fprintf(fp_rsp, "smlen = %llu\n", smlen);
        fprintBstr(fp_rsp, "sm = ", sm, smlen);
        fprintf(fp_rsp, "\n");

        if ((ret_val = crypto_sign_open(m1, &mlen1, sm, smlen, pk)) != 0) {
            printf("[%s]: crypto_sign_open returned <%d>\n", xstr(PARAMS), ret_val);
            return KAT_CRYPTO_FAILURE;
        }

        if (mlen != mlen1) {
            printf("[%s] crypto_sign_open returned bad 'mlen': Got <%llu>, expected <%llu>\n", xstr(PARAMS), mlen1, mlen);
            return KAT_CRYPTO_FAILURE;
        }

        if (memcmp(m, m1, mlen)) {
            printf("[%s] crypto_sign_open returned bad 'm' value\n", xstr(PARAMS));
            return KAT_CRYPTO_FAILURE;
        }

        free(m);
        free(m1);
        free(sm);

    } while (!done);

    fclose(fp_req);
    fclose(fp_rsp);

    return KAT_SUCCESS;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int FindMarker(FILE *infile, const char *marker) {
    char line[MAX_MARKER_LEN];
    size_t i, len;
    int curr_line;

    len = strlen(marker);
    if (len > MAX_MARKER_LEN - 1) len = MAX_MARKER_LEN - 1;

    for (i = 0; i < len; i++) {
        curr_line = fgetc(infile);
        line[i] = (char)curr_line;
        if (curr_line == EOF) return 0;
    }
    line[len] = '\0';

    while (1) {
        if (!strncmp(line, marker, len)) return 1;

        for (i = 0; i < len - 1; i++) line[i] = line[i + 1];
        curr_line = fgetc(infile);
        line[len - 1] = (char)curr_line;
        if (curr_line == EOF) return 0;
        line[len] = '\0';
    }

    // shouldn't get here
    return 0;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int ReadHex(FILE *infile, unsigned char *A, int Length, char *str) {
    int i, ch, started;
    unsigned char ich;

    if (Length == 0) {
        A[0] = 0x00;
        return 1;
    }
    memset(A, 0x00, (size_t)Length);
    started = 0;
    if (FindMarker(infile, str))
        while ((ch = fgetc(infile)) != EOF) {
            if (!isxdigit(ch)) {
                if (!started) {
                    if (ch == '\n')
                        break;
                    else
                        continue;
                } else
                    break;
            }
            started = 1;
            if ((ch >= '0') && (ch <= '9'))
                ich = (unsigned char)(ch - '0');
            else if ((ch >= 'A') && (ch <= 'F'))
                ich = (unsigned char)(ch - 'A' + 10);
            else if ((ch >= 'a') && (ch <= 'f'))
                ich = (unsigned char)(ch - 'a' + 10);
            else  // shouldn't ever get here
                ich = 0;

            for (i = 0; i < Length - 1; i++) A[i] = (unsigned char)((A[i] << 4) | (A[i + 1] >> 4));
            A[Length - 1] = (unsigned char)((A[Length - 1] << 4) | ich);
        }
    else
        return 0;

    return 1;
}

void fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L) {
    unsigned long long i;

    fprintf(fp, "%s", S);

    for (i = 0; i < L; i++) fprintf(fp, "%02X", A[i]);

    if (L == 0) fprintf(fp, "00");

    fprintf(fp, "\n");
}