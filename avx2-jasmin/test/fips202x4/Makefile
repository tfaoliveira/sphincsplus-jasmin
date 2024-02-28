
# -*- Makefile -*-

AS     ?= as
CC     ?= clang
CFLAGS ?= -w -march=native #-Wall -Wextra -Wpedantic -Wmissing-prototypes -O3 -std=c99 -march=native -fomit-frame-pointer -flto

JASMIN       ?= jasminc
JFLAGS       ?= -nowarning ${JADDFLAGS}
JPP          ?= ../scripts/jpp
PREPROCESSOR ?= ../scripts/preprocessor

# Both INLEN and OUTLEN
LEN_LIST  ?= 1 31 32 33 63 64 65 95 96 97 127 128 129 135 136 137 159 160 \
161 191 192 193 223 224 225 255 256 257 270 271 272

OUTLEN_LIST ?= 136 137 159 160 161 191 192 193 223 224 225 255 256 257 270 271 272

TLIST := $(foreach O,$(OUTLEN_LIST), $(foreach I,$(OUTLEN_LIST), $(O)_$(I)))
TESTS := $(addprefix bin/test_fips202_4x_, $(TLIST))
OUT   := $(addsuffix .out, $(TESTS))

GET_OUTLEN = $(word 2, $(subst _, ,$*))
GET_INLEN  = $(word 3, $(subst _, ,$*))

JPP_FILES := $(addsuffix .jpp, $(TESTS))
ASM_FILES := $(JPP_FILES:.jpp=.s)
OBJ_FILES := $(ASM_FILES:.s=.o)

default: $(TESTS)
run: $(OUT)

jpp_files: $(JPP_FILES)
asm_files: $(ASM_FILES)
obj_files: $(OBJ_FILES)

checkct: $(patsubst %.jpp,%.check,$(JPP_FILES))

%.o: %.s
	$(AS) $< -o $@


SOURCES := ../../fips202x4.c

$(JPP_FILES):
.PRECIOUS: bin/test_fips202_4x_%.jpp
bin/test_fips202_4x_%.jpp: | bin/
	cp test_fips202x4.jazz $@
	$(JPP) -in $@ -out $@
	$(PREPROCESSOR) --input_file $@ --output_file $@ \
	--task "fn:keccak_absorb4x_jazz p:INLEN:$(word 2, $(subst _, ,$*))" \
	       "fn:shake256_squeezeblocks_4x_jazz p:OUTLEN:$(word 1, $(subst _, ,$*))" \
			"fn:shake256_x4_jazz p:OUTLEN:$(word 1, $(subst _, ,$*)) p:INLEN:$(word 2, $(subst _, ,$*))"

.PRECIOUS: bin/test_fips202_4x_%.s
bin/test_fips202_4x_%.s: bin/test_fips202_4x_%.jpp
	$(JASMIN) $(JFLAGS) $< -o $@

$(TESTS):
bin/test_fips202_%: bin/test_fips202_%.s | bin/
	$(CC) $(CFLAGS) -o $@ -DOUTLEN=$(GET_OUTLEN) -DINLEN=$(GET_INLEN) \
	-DDEBUG \
	-I../common/ -I../../ -I../../keccak4x ../common/print.c ../common/notrandombytes.c \
	test_fips202x4.c $<  $(SOURCES)

bin/test_fips202_%.out: bin/test_fips202_%
	@./$<

%.check: %.jpp
	$(JASMIN) $(JFLAGS) -checkCT -infer $< > $@

bin/:
	mkdir -p $@

.PHONY: clean
clean:
	rm -rf bin/
