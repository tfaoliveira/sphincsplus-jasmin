# ------------------------------------------------------------------------------
AS     ?= as
CC     ?= clang
CFLAGS ?= -O3 -Wall -Wextra -Wpedantic -Wvla -Werror -std=c99 \
	        -Wundef -Wshadow -Wcast-align -Wpointer-arith -Wmissing-prototypes \
	        -fstrict-aliasing -fno-common -pipe -g
JASMIN ?= jasminc
JPP    ?= ../scripts/jpp

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
	sed -i -e "s/<OUTLEN,INLEN>/_$(GET_OUTLEN)_$(GET_INLEN)/" $@
	sed -i -e "s/<OUTLEN>/_$(GET_OUTLEN)/" $@
	sed -i -e "s/OUTLEN/$(GET_OUTLEN)/" $@
	sed -i -e "s/<INLEN>/_$(GET_INLEN)/" $@
	sed -i -e "s/INLEN/$(GET_INLEN)/" $@
	sed -i -e "s/<TEST_SHAKE256_OUT,TEST_SHAKE256_IN>/_$(GET_OUTLEN)_$(GET_INLEN)/" $@
	sed -i -e "s/TEST_SHAKE256_OUT/$(GET_OUTLEN)/" $@
	sed -i -e "s/TEST_SHAKE256_IN/$(GET_INLEN)/" $@

.PRECIOUS: bin/test_shake256_%.s
bin/test_shake256_%.s: bin/test_shake256_%.jpp
	jasminc $< -o $@

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
