#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "macros.h"
#include "notrandombytes.c"
#include "print.c"

#define TESTS 50
#define OUTLEN 32

extern void shake256(uint8_t *output, size_t outlen, const uint8_t *input,
                     size_t inlen);  // from fips202.c

extern void shake256_inc_init(uint64_t *state);  // from fips202.c

extern void shake256_inc_absorb(uint64_t *s_inc, const uint8_t *input,
                                size_t inlen);  // from fips202.c

extern void shake256_inc_finalize(uint64_t *s_inc);  // from fips202.c

extern void shake256_inc_squeeze(uint8_t *output, size_t outlen,
                                 uint64_t *s_inc);  // from fips202.c

void test_one_big_absorb(void);
void test_more_absorbs(size_t num_msg);
void test_hash_shake(void);

void test_one_big_absorb(void) {
    uint64_t state_inc[26];
    uint8_t out_inc[OUTLEN], out[OUTLEN];
    uint8_t *in;

    for (int i = 0; i < TESTS; i++) {
        for (size_t msg_len = 10; msg_len < 1024; msg_len += 10) {
            shake256_inc_init(state_inc);
            in = malloc(msg_len);
            randombytes(in, msg_len);

            shake256_inc_absorb(state_inc, in, msg_len);
            shake256_inc_finalize(state_inc);
            shake256_inc_squeeze(out_inc, OUTLEN, state_inc);

            shake256(out, OUTLEN, in, msg_len);

            free(in);

            assert(memcmp(out, out_inc, OUTLEN) == 0);
        }
    }
}

void test_more_absorbs(size_t num_msg) {  // number of messages to absorb
    uint64_t state_inc[26];
    uint8_t out_inc[OUTLEN], out[OUTLEN];
    uint8_t *in;
    uint8_t *buf;

    for (int i = 0; i < TESTS; i++) {
        for (size_t msg_len = 10; msg_len < 2078; msg_len += 10) {
            shake256_inc_init(state_inc);
            in = malloc(msg_len);
            buf = malloc(num_msg * msg_len);

            for (size_t j = 0; j < num_msg; j++) {
                randombytes(in, msg_len);
                memcpy(buf + j * msg_len, in, msg_len);
                shake256_inc_absorb(state_inc, in, msg_len);
            }

            shake256_inc_finalize(state_inc);
            shake256_inc_squeeze(out_inc, OUTLEN, state_inc);

            shake256(out, OUTLEN, buf, msg_len * num_msg);

            free(in);
            free(buf);

            assert(memcmp(out, out_inc, OUTLEN) == 0);
        }
    }
}

static void gen_message_random_shake(uint8_t *R, const uint8_t *sk_prf, const uint8_t *optrand,
                                     const uint8_t *m) {
#define MSG_LEN 10
#define SPX_N 16
    uint8_t buf[2 * SPX_N + MSG_LEN];
    memcpy(buf, sk_prf, SPX_N);
    memcpy(buf + SPX_N, optrand, SPX_N);
    memcpy(buf + 2 * SPX_N, m, MSG_LEN);
    shake256(R, SPX_N, buf, 2 * SPX_N + MSG_LEN);
#undef MSG_LEN
#undef SPX_N
}

static void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                               const unsigned char *optrand, const unsigned char *m,
                               unsigned long long mlen, const void *ctx) {
#define SPX_N 16
    mlen = 10;

    (void)ctx;
    uint64_t s_inc[26];

    shake256_inc_init(s_inc);
    shake256_inc_absorb(s_inc, sk_prf, SPX_N);
    shake256_inc_absorb(s_inc, optrand, SPX_N);
    shake256_inc_absorb(s_inc, m, mlen);
    shake256_inc_finalize(s_inc);
    shake256_inc_squeeze(R, SPX_N, s_inc);

#undef SPX_N
}

void test_hash_shake(void) {
#define MSG_LEN 10
#define SPX_N 16
    uint8_t optrand[SPX_N], sk_prf[SPX_N];
    uint8_t R0[SPX_N], R1[SPX_N];
    uint8_t message[MSG_LEN];
    const void* ctx;

    for (int i = 0; i < TESTS; i++) {
        randombytes(optrand, SPX_N);
        randombytes(sk_prf, SPX_N);
        randombytes(message, MSG_LEN);

        memset(R0, 0, SPX_N);
        memset(R1, 0, SPX_N);

        gen_message_random(R0, sk_prf, optrand, message, MSG_LEN, ctx);
        gen_message_random_shake(R1, sk_prf, optrand, message);

        assert(memcmp(R0, R1, SPX_N) == 0);
    }

#undef MSG_LEN
#undef SPX_N
}

int main(void) {
    test_one_big_absorb();  // works

    // Test absorbing from 2 to 15 messages
    for (size_t i = 2; i < 16; i++) {
        test_more_absorbs(i);  // works
    }

    test_hash_shake();

    printf("Pass: shake 256 inc\n");
    return 0;
}