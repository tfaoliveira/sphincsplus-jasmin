# ------------------------------------------------------------------------------

AS       ?= as
CC       ?= clang
CFLAGS   ?= -O3 -Wall -Wextra -Wpedantic -Werror -std=c99 \
	          -Wundef -Wshadow -Wcast-align -Wpointer-arith -Wmissing-prototypes \
	          -fstrict-aliasing -fno-common -pipe -g
# NOTE: -Wvla was removed for CFLAGS due to the usage of SPX_VLA

JASMIN   ?= jasminc

# ------------------------------------------------------------------------------
default: bin/test_shake256_ptr
run: bin/test_shake256_ptr.out

.PRECIOUS: bin/test_shake256_ptr.s
bin/test_shake256_ptr.s: test_shake256_ptr.jazz | bin/
	$(JASMIN) -I Sphincs:../../../ -nowarning $< -o $@

bin/test_shake256_ptr: bin/test_shake256_ptr.s | bin/
	$(CC) $(CFLAGS) -o $@ -I../../common -I../../ test_shake256_ptr.c $< ../../../fips202.c

bin/test_shake256_ptr.out: bin/test_shake256_ptr
	@./$<

bin/:
	mkdir -p bin/

.PHONY: clean
clean:
	rm -fr bin/