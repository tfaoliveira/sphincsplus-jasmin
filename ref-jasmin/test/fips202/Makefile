# ------------------------------------------------------------------------------
AS       ?= as
CC       ?= clang
CFLAGS   ?= -O3 -Wall -Wextra -Wpedantic -Werror -std=c99 \
	          -Wundef -Wshadow -Wcast-align -Wpointer-arith -Wmissing-prototypes \
	          -fstrict-aliasing -fno-common -pipe -g

# NOTE: -Wvla was removed for CFLAGS due to the usage of SPX_VLA

JASMIN   ?= jasminc
JPP      ?= ../scripts/jpp
PREPROCESSOR ?= ../scripts/preprocessor

# ------------------------------------------------------------------------------

# inlen focused
#OUTLEN_LIST := 1
#INLEN_LIST := $(shell seq 1 280)

# outlen focused
#OUTLEN_LIST := $(shell seq 1 280)
#INLEN_LIST := 1

# wookie
#OUTLEN_LIST := 32 64 
#INLEN_LIST := 1024 2048

# some more
OUTLEN_LIST := $(shell seq 1 32) 33 34 63 64 65 
INLEN_LIST := 1 135 136 137 271 272 273 407 408 409

TLIST := $(foreach O,$(OUTLEN_LIST), $(foreach I,$(INLEN_LIST), $(O)_$(I)))

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
	$(JPP) -I Sphincs:../../ -in $@ -out $@
	$(PREPROCESSOR) --input_file $@ --output_file $@ --task "fn:shake256  p:OUTLEN:$(GET_OUTLEN) p:INLEN:$(GET_INLEN)"

.PRECIOUS: bin/test_fips202_%.s
bin/test_fips202_%.s: bin/test_fips202_%.jpp
	jasminc -nowarning $< -o $@

$(TESTS):
bin/test_fips202_%: bin/test_fips202_%.s | bin/
	$(CC) $(CFLAGS) -o $@ -DOUTLEN=$(GET_OUTLEN) -DINLEN=$(GET_INLEN) -I../common -I../../ \
test_fips202.c $< ../../fips202.c

bin/test_fips202_%.out: bin/test_fips202_%
	@./$<

bin/:
	mkdir -p bin/

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/
