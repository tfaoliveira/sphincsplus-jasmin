#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "context.h"
#include "macros.h"
#include "notrandombytes.c"
#include "params.h"
#include "print.c"
#include "thash.h"

extern void thash_4x_jazz(const void *args);

void thash_4x_jazz(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3, const uint8_t *in0, const uint8_t *in1,
                   const uint8_t *in2, const uint8_t *in3, const spx_ctx *ctx, uint32_t *addrx4) {
    void *args[10];

    args[0] = (void *)out0;
    args[1] = (void *)out1;
    args[2] = (void *)out2;
    args[3] = (void *)out3;
    args[4] = (void *)in0;
    args[5] = (void *)in1;
    args[6] = (void *)in2;
    args[7] = (void *)in3;
    args[8] = (void *)ctx->pub_seed;
    args[9] = (void *)addrx4;

    thash_jazz(args);
}

void test_thash_4x(void) {
    spx_ctx ctx;
    uint32_t addrx4[4*8];

}

int main(void) {
    printf("PASS: thash = { params: %s, thash: %s, inblocks : %d }\n", xstr(PARAMS), xstr(THASH), INBLOCKS);

    return 0;
}