# -*- Makefile -*-

# ------------------------------------------------------------------------------
AS       ?= as
CC       ?= clang
CFLAGS   ?= -w -march=native #-Wall -Wextra -Wpedantic -Wmissing-prototypes -O3 -std=c99 -march=native -fomit-frame-pointer -flto

JASMIN       ?= jasminc
JFLAGS       ?= -lazy-regalloc -nowarning ${JADDFLAGS}
JPP          ?= ../scripts/jpp
PREPROCESSOR ?= ../scripts/preprocessor

# ------------------------------------------------------------------------------

HASH_LIST     := shake
PARAMS_LIST   := 128f 128s 192f 192s 256f 256s
THASH_LIST    := simple robust 

TLIST := $(foreach H,$(HASH_LIST), $(foreach P,$(PARAMS_LIST), $(foreach T,$(THASH_LIST),$(H)_$(P)_$(T))))

# ------------------------------------------------------------------------------

TESTS := $(addprefix bin/test_fors_, $(TLIST))
OUT   := $(addsuffix .out, $(TESTS))

GET_HASH  = $(word 1, $(subst _, ,$*))
GET_PARAM = $(word 2, $(subst _, ,$*))
GET_THASH = $(word 3, $(subst _, ,$*))

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

%.o: %.s
	$(AS) $< -o $@

%.check: %.jpp
	$(JASMIN) $(JFLAGS) -checkCT -infer $< > $@

# ------------------------------------------------------------------------------

SOURCES = ../../keccak4x/KeccakP-1600-times4-SIMD256.c ../../fips202x4.c ../../fips202.c \
          ../../hash_$(GET_HASH)x4.c ../../hash_$(GET_HASH).c \
		  ../../thash_$(GET_HASH)_$(GET_THASH)x4.c ../../thash_$(GET_HASH)_$(GET_THASH).c \
		  ../../fors.c ../../utilsx4.c \
          ../../address.c ../../utils.c

TEST_FLAGS := 

$(JPP_FILES):
.PRECIOUS: bin/test_fors_%.jpp
bin/test_fors_%.jpp: | bin/
	cp test_fors.jazz $@
	sed -i "1 i\from Sphincs require \"params/params-sphincs-$(GET_HASH)-$(GET_PARAM).jinc\"" $@
	sed -i "2 i\from Sphincs require \"thash/thash_$(GET_HASH)_$(GET_THASH).jtmpl\"" $@
	sed -i "2 i\from Sphincs require \"thash_4x/thash_4x_$(GET_HASH)_$(GET_THASH).jtmpl\"" $@
	$(JPP) -I Sphincs:../../ -in $@ -out $@
	$(PREPROCESSOR) --input_file $@ --output_file $@

.PRECIOUS: bin/test_fors_%.s
bin/test_fors_%.s: bin/test_fors_%.jpp
	$(JASMIN) $(JFLAGS) $< -o $@

$(TESTS):
bin/test_fors_%: bin/test_fors_%.s | bin/
	$(CC) $(CFLAGS) -o $@ \
	-DPARAMS=sphincs-$(GET_HASH)-$(GET_PARAM) -DTHASH=$(GET_THASH) $(TEST_FLAGS) \
	-I../common/ -I../../ -I../../keccak4x ../common/print.c ../common/notrandombytes.c \
	test_fors.c $< $(SOURCES)

bin/test_fors_%.out: bin/test_fors_%
	@./$<


# ------------------------------------------------------------------------------

bin/:
	mkdir -p bin/

.PHONY: clean
clean:
	rm -fr bin/

.PHONY: clean_executables
clean_executables:
	find bin/ -type f -executable -delete
