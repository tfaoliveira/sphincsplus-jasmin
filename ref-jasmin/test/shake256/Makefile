# ------------------------------------------------------------------------------
AS     ?= as
CC     ?= clang
CFLAGS ?= -O3 -Wall -Wextra -Wpedantic -Wvla -Werror -std=c99 \
	        -Wundef -Wshadow -Wcast-align -Wpointer-arith -Wmissing-prototypes \
	        -fstrict-aliasing -fno-common -pipe -g
JASMIN ?= jasminc
JPP    ?= ../scripts/jpp
JASMINPP  ?= ../scripts/preprocessor

# ------------------------------------------------------------------------------
# -- note: to add more tests, update the following list. as an example, to test
#          for 128 bytes of output and 1024 bytes of input, add '128_1024' after
#          the last element of TLIST
TLIST      := 32_64 32_96 32_128 32_768 32_2208 64_64

TESTS      := $(addprefix bin/test_shake256_, $(TLIST))
OUT        := $(addsuffix .out, $(TESTS))
GET_OUTLEN  = $(word 1, $(subst _, ,$*))
GET_INLEN   = $(word 2, $(subst _, ,$*))

# ------------------------------------------------------------------------------
default: $(TESTS)
run: $(OUT)

.PRECIOUS: bin/test_shake256_%.jpp
bin/test_shake256_%.jpp:
	$(JPP) -I Sphincs:../../ -in test_shake256.jazz -out $@
	$(JASMINPP) --input_file $@ --output_file $@ --task "fn:shake256_inc_absorb_jazz p:INLEN:$(GET_INLEN)" "fn:shake256_inc_squeeze_jazz p:OUTLEN:$(GET_OUTLEN)" "fn:shake256 p:OUTLEN:$(GET_OUTLEN) p:INLEN:$(GET_INLEN)" 

.PRECIOUS: bin/test_shake256_%.s
bin/test_shake256_%.s: bin/test_shake256_%.jpp
	jasminc -nowarning $< -o $@
	
$(TESTS):
bin/test_shake256_%: bin/test_shake256_%.s | bin/
	$(CC) $(CFLAGS) -o $@ -DOUTLEN=$(GET_OUTLEN) -DINLEN=$(GET_INLEN) -I../common test_shake256.c $< ../../fips202.c 

bin/test_shake256_%.out: bin/test_shake256_%
	@./$<

bin/:
	mkdir -p bin/

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/