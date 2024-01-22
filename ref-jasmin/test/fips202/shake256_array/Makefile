# ------------------------------------------------------------------------------
AS       ?= as
CC       ?= clang
CFLAGS   ?= -O3 -Wall -Wextra -Wpedantic -Werror -std=c99 \
	          -Wundef -Wshadow -Wcast-align -Wpointer-arith -Wmissing-prototypes \
	          -fstrict-aliasing -fno-common -pipe -g

# NOTE: -Wvla was removed for CFLAGS due to the usage of SPX_VLA

JASMIN       ?= jasminc
JFLAGS       ?= -nowarning
JPP          ?= ../../scripts/jpp
PREPROCESSOR ?= ../../scripts/preprocessor

# ------------------------------------------------------------------------------
# 5m
OUTLEN_LIST ?= 1 31 32 33 63 64 65 95 96 97 127 128 129 135 136 137 159 160\
161 191 192 193 223 224 225 255 256 257 270 271 272

INLEN_LIST  ?= 1 31 32 33 63 64 65 95 96 97 127 128 129 135 136 137 159 160\
161 191 192 193 223 224 225 255 256 257 270 271 272

TLIST := $(foreach O,$(OUTLEN_LIST), $(foreach I,$(OUTLEN_LIST), $(O)_$(I)))

# ------------------------------------------------------------------------------
TESTS      := $(addprefix bin/test_fips202_, $(TLIST))
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
.PRECIOUS: bin/test_fips202_%.jpp
bin/test_fips202_%.jpp: | bin/
	cp test_fips202.jazz $@
	$(JPP) -I Sphincs:../../../ -in $@ -out $@
	$(PREPROCESSOR) --input_file $@ --output_file $@ --task "fn:shake256  p:OUTLEN:$(GET_OUTLEN) p:INLEN:$(GET_INLEN)"

.PRECIOUS: bin/test_fips202_%.s
bin/test_fips202_%.s: bin/test_fips202_%.jpp
	$(JASMIN) $(JFLAGS) $< -o $@

$(TESTS):
bin/test_fips202_%: bin/test_fips202_%.s | bin/
	$(CC) $(CFLAGS) -o $@ -DOUTLEN=$(GET_OUTLEN) -DINLEN=$(GET_INLEN) -I../../common -I../../../ \
test_fips202.c $< ../../../fips202.c

bin/test_fips202_%.out: bin/test_fips202_%
	@./$<

bin/:
	mkdir -p bin/

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/
