# ------------------------------------------------------------------------------
AS       ?= as
CC       ?= clang
CFLAGS   ?= -w #-O3 -Wall -Wextra -Wpedantic -Werror -std=c99 \
	          -Wundef -Wshadow -Wcast-align -Wpointer-arith -Wmissing-prototypes \
	          -fstrict-aliasing -fno-common -pipe -g
# NOTE: -Wvla was removed for CFLAGS due to the usage of SPX_VLA

JASMIN   ?= jasminc
JFLAGS   ?= -nowarning ${JADDFLAGS}

# ------------------------------------------------------------------------------
default: bin/test_shake256_ptr
run: bin/test_shake256_ptr.out
obj_files: bin/test_shake256_ptr.o
checkct: bin/test_shake256_ptr.check

%.o: %.s
	$(AS) $< -o $@

.PRECIOUS: bin/test_shake256_ptr.s
bin/test_shake256_ptr.s: test_shake256_ptr.jazz | bin/
	$(JASMIN) $(JFLAGS) -I Sphincs:../../../ $< -o $@

bin/test_shake256_ptr: bin/test_shake256_ptr.s | bin/
	$(CC) $(CFLAGS) -o $@ -I../../common -I../../ test_shake256_ptr.c $< ../../../fips202.c

bin/test_shake256_ptr.check: test_shake256_ptr.jazz | bin/
	$(JASMIN) $(JFLAGS) -I Sphincs:../../../ -checkCT -infer $^ > $@

bin/test_shake256_ptr.out: bin/test_shake256_ptr
	@./$<

bin/:
	mkdir -p bin/

.PHONY: clean
clean:
	rm -fr bin/