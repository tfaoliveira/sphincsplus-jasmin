# -*- Makefile -*-

AS     ?= as
CC     ?= clang
CFLAGS ?= -w -march=native #-Wall -Wextra -Wpedantic -Wmissing-prototypes -O3 -std=c99 -march=native -fomit-frame-pointer -flto

# ------------------------------------------------------------------------------

JASMIN       ?= jasminc
JFLAGS       ?= -nowarning ${JADDFLAGS}
JPP          ?= ../scripts/jpp
PREPROCESSOR ?= ../scripts/preprocessor

# ------------------------------------------------------------------------------

HASH_LIST   := shake
PARAMS_LIST := 128f 128s 192f 192s 256f 256s


TLIST := $(foreach H,$(HASH_LIST), $(foreach P,$(PARAMS_LIST), $(H)_$(P)))

GET_HASH  = $(word 1, $(subst _, ,$*))
GET_PARAM = $(word 2, $(subst _, ,$*))

TESTS := $(addprefix bin/test_hash4x_, $(TLIST))
OUT   := $(addsuffix .out, $(TESTS))

# ------------------------------------------------------------------------------

JPP_FILES := $(addsuffix .jpp, $(TESTS))
ASM_FILES := $(JPP_FILES:.jpp=.s)
OBJ_FILES := $(ASM_FILES:.s=.o)

default: $(TESTS)
run: $(OUT)

jpp_files: $(JPP_FILES)
asm_files: $(ASM_FILES)
obj_files: $(OBJ_FILES)

checkct: $(patsubst %.jpp,%.check,$(JPP_FILES))

# ------------------------------------------------------------------------------

%.check: %.jpp
	$(JASMIN) $(JFLAGS) -checkCT -infer $< > $@

%.o: %.s
	$(AS) $< -o $@

# ------------------------------------------------------------------------------

$(JPP_FILES):
.PRECIOUS: bin/test_hash4x_%.jpp
bin/test_hash4x_%.jpp: | bin/
	cp test_hash4x.jazz $@
	sed -i "1 i\from Sphincs require \"params/params-sphincs-$(GET_HASH)-$(GET_PARAM).jinc\"" $@
	$(JPP) -I Sphincs:../../ -in $@ -out $@
	$(PREPROCESSOR) --input_file $@ --output_file $@

.PRECIOUS: bin/test_hash4x_%.s
bin/test_hash4x_%.s: bin/test_hash4x_%.jpp
	$(JASMIN) $(JFLAGS) $< -o $@

$(TESTS):
bin/test_hash4x_%: bin/test_hash4x_%.s | bin/
	$(CC) $(CFLAGS) -o $@ -DPARAMS=sphincs-$(GET_HASH)-$(GET_PARAM) \
	-I../common/ -I../../params ../common/print.c ../common/notrandombytes.c \
	test_hash4x.c $< 

bin/test_hash4x_%.out: bin/test_hash4x_%
	@./$<


# ------------------------------------------------------------------------------

bin/:
	mkdir -p $@

.PHONY: clean
clean:
	rm -rf bin/

# ------------------------------------------------------------------------------

debug:
	echo $(TESTS)