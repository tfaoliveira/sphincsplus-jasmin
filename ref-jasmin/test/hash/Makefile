# ------------------------------------------------------------------------------
AS       ?= as
CC       ?= clang
CFLAGS   ?= -w #-O3 -Wall -Wextra -Wpedantic -Werror -std=c99 \
	          -Wundef -Wshadow -Wcast-align -Wpointer-arith -Wmissing-prototypes \
	          -fstrict-aliasing -fno-common -pipe -g

# NOTE: -Wvla was removed for CFLAGS due to the usage of SPX_VLA

JASMIN       ?= jasminc
JFLAGS       ?= -nowarning ${JADDFLAGS}
JPP          ?= ../../../submodules/jasmin-preprocessor/jpp
PREPROCESSOR ?= ../../../submodules/jasmin-preprocessor/preprocessor

# ------------------------------------------------------------------------------

HASH_LIST   := shake
PARAMS_LIST := 128f 128s 192f 192s 256f 256s
THASH_LIST  := simple robust

TLIST := $(foreach H,$(HASH_LIST), $(foreach P,$(PARAMS_LIST), $(foreach T,$(THASH_LIST), $(H)_$(P)_$(T))))

# ------------------------------------------------------------------------------

TESTS := $(addprefix bin/test_hash_, $(TLIST))
OUT   := $(addsuffix .out, $(TESTS))

GET_HASH  = $(word 1, $(subst _, ,$*))
GET_PARAM = $(word 2, $(subst _, ,$*))
GET_THASH = $(word 3, $(subst _, ,$*))

# ------------------------------------------------------------------------------

JPP_FILES := $(addsuffix .jpp, $(TESTS))
ASM_FILES := $(JPP_FILES:.jpp=.s)
OBJ_FILES := $(ASM_FILES:.s=.o)

# ------------------------------------------------------------------------------

SOURCES = ../../hash_$(GET_HASH).c ../../fips202.c ../../utils.c \
		  ../../address.c ../../thash_$(GET_HASH)_$(GET_THASH).c ../../utilsx1.c \
		  ../../merkle.c ../../wots.c ../../wotsx1.c ../../sign.c ../../wrappers.c \
		  ../../fors.c

TEST_FLAGS = -DTEST_HASH_PRF_ADDR -DTEST_HASH_GEN_MESSAGE_RANDOM -DTEST_HASH_MESSAGE

# ------------------------------------------------------------------------------

default: $(TESTS)
run: $(OUT)

jpp_files: $(JPP_FILES)
asm_files: $(ASM_FILES)
obj_files: $(OBJ_FILES)

checkct: $(patsubst %.jpp,%.check,$(JPP_FILES))

%.check: %.jpp
	$(JASMIN) $(JFLAGS) -checkCT -infer $< > $@

# ------------------------------------------------------------------------------

%.o: %.s
	$(AS) $< -o $@

# ------------------------------------------------------------------------------

$(JPP_FILES):
.PRECIOUS: bin/test_hash_%.jpp
bin/test_hash_%.jpp: | bin/
	cp test_hash.jazz $@
	sed -i "1 i\from Sphincs require \"params/params-sphincs-$(GET_HASH)-$(GET_PARAM).jinc\"" $@
	$(JPP) -I Sphincs:../../ -in $@ -out $@
	$(PREPROCESSOR) --input_file $@ --output_file $@ 

.PRECIOUS: bin/test_hash_%.s
bin/test_hash_%.s: bin/test_hash_%.jpp
	$(JASMIN) $(JFLAGS) $< -o $@

$(TESTS):
bin/test_hash_%: bin/test_hash_%.s | bin/
	$(CC) $(CFLAGS) -o $@ -DPARAMS=sphincs-$(GET_HASH)-$(GET_PARAM) \
	$(TEST_FLAGS) -I../common -I../../ -I../../params test_hash.c $< $(SOURCES)

bin/test_hash_%.out: bin/test_hash_%
	@./$<

bin/:
	mkdir -p bin/

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/
