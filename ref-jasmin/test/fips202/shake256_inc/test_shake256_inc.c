#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "macros.h"
#include "notrandombytes.c"
#include "print.c"

#ifndef OUTLEN
#define OUTLEN 1
#endif

#ifndef INLEN
#define INLEN 1
#endif

#ifndef TESTS
#define TESTS 10
#endif

extern void shake256(uint8_t *out, size_t outlen, const uint8_t *in,
                     size_t inlen);  // from fips202.c

extern void shake256_inc_init_jazz(uint64_t *state);
extern void shake256_inc_init(uint64_t *state);  // from fips202.c

#define shake256_inc_absorb_template_jazz NAMESPACE1(shake256_inc_absorb_template_jazz, INLEN)
extern void shake256_inc_absorb_template_jazz(uint64_t *state, const uint8_t *in);
extern void shake256_inc_absorb_jazz(uint64_t *state, const uint8_t *in, size_t inlen);
extern void shake256_inc_absorb(uint64_t *state, const uint8_t *in,
                                size_t inlen);  // from fips202.c

extern void shake256_inc_finalize_jazz(uint64_t *state);
extern void shake256_inc_finalize(uint64_t *state);  // from fips202.c

#define shake256_inc_squeeze_template_jazz NAMESPACE1(shake256_inc_squeeze_template_jazz, OUTLEN)
extern void shake256_inc_squeeze_template_jazz(uint8_t *out, uint64_t *state);
extern void shake256_inc_squeeze_jazz(uint8_t *out, size_t outlen, uint64_t *state);
extern void shake256_inc_squeeze(uint8_t *out, size_t outlen, uint64_t *state);  // from fips202.c

void test_shake_inc_templates(int nblocks);
void test_absorb_n_blocks(int nblocks);
void test_shake_shake_inc(int nblocks);

// /////////////////////////////////////////////////////////////////////////////
#if 1
// note: do not remove me; integrate with debub macro && assert
void dump_test_env_state(
  char *str,
  size_t inlen,
  size_t outlen,
  uint64_t state_jazz[26],
  uint64_t state_ref[26]
)
{
  printf("debug: %s\n", str);
  printf("inlen  : %zu\n", inlen);
  printf("outlen : %zu\n", outlen);

  print_str_u8("state_jazz", (uint8_t*) state_jazz, 26*sizeof(uint64_t));
  print_str_u8("state_ref ", (uint8_t*) state_ref,  26*sizeof(uint64_t));
  printf("\n\n");
}
#endif
// /////////////////////////////////////////////////////////////////////////////

void test_shake_inc_templates(int nblocks) {
  uint64_t state_ref[26], state_jazz[26];
  uint8_t in[INLEN];
  uint8_t out_ref[OUTLEN], out_jazz[OUTLEN];

  for (int i = 0; i < TESTS; i++) {
    memset(out_jazz, 0, OUTLEN);
    memset(out_ref, 0, OUTLEN);

    shake256_inc_init(state_ref);
    shake256_inc_init_jazz(state_jazz);

    // check if states are equal
    assert(memcmp(state_jazz, state_ref, 26 * sizeof(uint64_t)) == 0);

    // absorb block times
    for (int blocks = 0; blocks < nblocks; blocks++)
    {
      randombytes(in, INLEN);

      // absorb
      shake256_inc_absorb(state_ref, in, INLEN);
      shake256_inc_absorb_template_jazz(state_jazz, in);

      // check if states are equal
      assert(memcmp(state_jazz, state_ref, 26 * sizeof(uint64_t)) == 0);
    }

    // finalize
    shake256_inc_finalize(state_ref);
    shake256_inc_finalize_jazz(state_jazz);

    // check if states are equal
    assert(memcmp(state_jazz, state_ref, 26 * sizeof(uint64_t)) == 0);

    // squeeze
    shake256_inc_squeeze(out_ref, OUTLEN, state_ref);
    shake256_inc_squeeze_template_jazz(out_jazz, state_jazz);
    
    // check if states & outputs are equal
    assert(memcmp(state_jazz, state_ref, 26 * sizeof(uint64_t)) == 0);
    assert(memcmp(out_jazz, out_ref, OUTLEN) == 0);
  } 
}


void test_absorb_n_blocks(int nblocks)
{
  #define MAXIN (257)
  #define MAXOUT (136*3+1)

  uint64_t state_ref[26], state_jazz[26];
  uint8_t in[MAXIN];
  uint8_t out_ref[MAXOUT];
  uint8_t out_jazz[MAXOUT];

  for (int i = 0; i < TESTS; i++)
  {
    for (size_t inlen = 1; inlen < MAXIN; inlen++)
    {
      for (size_t outlen = 1; outlen < MAXOUT; outlen++)
      {
        // init
        shake256_inc_init(state_ref);
        shake256_inc_init_jazz(state_jazz);

        // check if states are equal
        assert(memcmp(state_jazz, state_ref, 26 * sizeof(uint64_t)) == 0);

        // absorb block times
        for (int blocks = 0; blocks < nblocks; blocks++)
        {
          randombytes(in, inlen);

          // absorb
          shake256_inc_absorb(state_ref, in, inlen);
          shake256_inc_absorb_jazz(state_jazz, in, inlen);

          // check if states are equal
          assert(memcmp(state_jazz, state_ref, 26 * sizeof(uint64_t)) == 0);
        }

        // finalize
        shake256_inc_finalize(state_ref);
        shake256_inc_finalize_jazz(state_jazz);

        // check if states are equal
        assert(memcmp(state_jazz, state_ref, 26 * sizeof(uint64_t)) == 0);

        // squeeze
        shake256_inc_squeeze(out_ref, outlen, state_ref);
        shake256_inc_squeeze_jazz(out_jazz, outlen, state_jazz);

        // check if outs are equal
        assert(memcmp(out_jazz, out_ref, outlen) == 0);
      }
    }
  }

  #undef MAXIN
  #undef MAXOUT
}

void test_shake_shake_inc(int nblocks)
{
  #define MAXIN (257)
  #define MAXOUT (136*3+1)

  uint64_t state_inc[26];
  uint8_t in[MAXIN];
  uint8_t out_ref[MAXOUT];
  uint8_t out_jazz[MAXOUT];
  uint8_t buf[MAXIN*nblocks]; // vla

  for (int i = 0; i < TESTS; i++)
  {
    for (size_t inlen = 1; inlen < MAXIN; inlen++)
    {
      for (size_t outlen = 1; outlen < MAXOUT; outlen++)
      {
        shake256_inc_init_jazz(state_inc);

        for (int blocks = 0; blocks < nblocks; blocks++)
        {
          randombytes(in, inlen);
          memcpy(buf + blocks * inlen, in, inlen);
          shake256_inc_absorb_jazz(state_inc, in, inlen);
        }

        shake256_inc_finalize_jazz(state_inc);

        shake256_inc_squeeze_jazz(out_jazz, outlen, state_inc);
        shake256(out_ref, outlen, buf, nblocks * inlen);

        assert(memcmp(out_jazz, out_ref, outlen) == 0);
      }
    }
  }

  #undef MAXIN
  #undef MAXOUT
}

int main(void)
{
  printf("INLEN: %d OUTLEN: %d\n", INLEN, OUTLEN);

  // should take roughly 2 to 3 minutes for i={0..8}
  for (int i = 0; i <= 8 ; i++)
  {
    test_shake_inc_templates(i);

    test_absorb_n_blocks(i);
    printf("PASS: shake256 inc (inc vs inc) : %d blocks\n", i);

    test_shake_shake_inc(i);
    printf("PASS: shake256 inc (inc vs one) : %d blocks\n", i);
  }

  printf("\n");

  return 0;
}
