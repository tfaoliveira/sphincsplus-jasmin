# ------------------------------------------------------------------------------
AS       ?= as
CC       ?= clang
CFLAGS   ?= -O3 #-Wall -Wextra -Wpedantic -Werror -std=c99 \
	          -Wundef -Wshadow -Wcast-align -Wpointer-arith -Wmissing-prototypes \
	          -fstrict-aliasing -fno-common -pipe -g

# NOTE: -Wvla was removed for CFLAGS due to the usage of SPX_VLA

JASMIN       ?= jasminc
JPP          ?= ../../scripts/jpp
PREPROCESSOR ?= ../../scripts/preprocessor

# ------------------------------------------------------------------------------

default: bin/test_shake256_inc
run: bin/test_shake256_inc.out
jpp_files: bin/test_shake256_inc.jpp

$(JPP_FILES):
.PRECIOUS: bin/test_shake256_inc.jpp
bin/test_shake256_inc.jpp: | bin/
	cp test_shake256_inc.jazz $@
	$(JPP) -I Sphincs:../../../ -in $@ -out $@
	$(PREPROCESSOR) --input_file $@ --output_file $@


.PRECIOUS: bin/test_shake256_inc.s
bin/test_shake256_inc.s: bin/test_shake256_inc.jpp | bin/
	$(JASMIN) -I Sphincs:../../../ -nowarning $< -o $@

bin/test_shake256_inc: bin/test_shake256_inc.s | bin/
	$(CC) $(CFLAGS) -o $@ -I../../common -I../../ test_shake256_inc.c $< ../../../fips202.c

bin/test_shake256_inc.out: bin/test_shake256_inc
	@./$<

bin/:
	mkdir -p bin/

.PHONY: clean
clean:
	rm -fr bin/
