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

OUTLEN_LIST := 33 34 63 64 65 
INLEN_LIST := 135 136 137 271 272 273 407 408 409

TLIST := $(foreach O,$(OUTLEN_LIST), $(foreach I,$(INLEN_LIST), $(O)_$(I)))

# ------------------------------------------------------------------------------
TESTS      := $(addprefix bin/test_shake256_inc_, $(TLIST))
OUT        := $(addsuffix .out, $(TESTS))

GET_OUTLEN  = $(word 1, $(subst _, ,$*))
GET_INLEN   = $(word 2, $(subst _, ,$*))

# ------------------------------------------------------------------------------
JPP_FILES := $(addsuffix .jpp, $(TESTS))

# ------------------------------------------------------------------------------

default: $(TESTS)
run: $(OUT)
jpp_files: $(JPP_FILES)


$(JPP_FILES):
.PRECIOUS: bin/test_shake256_inc_%.jpp
bin/test_shake256_inc_%.jpp: | bin/
	cp test_shake256_inc.jazz $@
	$(JPP) -I Sphincs:../../../ -in $@ -out $@
	$(PREPROCESSOR) --input_file $@ --output_file $@ --task "fn:shake256_inc_absorb_template_jazz p:INLEN:$(GET_INLEN)" "fn:shake256_inc_squeeze_template_jazz p:OUTLEN:$(GET_OUTLEN)"


.PRECIOUS: bin/test_shake256_inc_%.s
bin/test_shake256_inc_%.s: bin/test_shake256_inc_%.jpp | bin/
	$(JASMIN) -I Sphincs:../../../ -nowarning $< -o $@

bin/test_shake256_inc_%: bin/test_shake256_inc_%.s | bin/
	$(CC) $(CFLAGS) -o $@ -DOUTLEN=$(GET_OUTLEN) -DINLEN=$(GET_INLEN) -I../../common -I../../ test_shake256_inc.c $< ../../../fips202.c

bin/test_shake256_inc_%.out: bin/test_shake256_inc_%
	@./$<

bin/:
	mkdir -p bin/

.PHONY: clean
clean:
	rm -fr bin/
