# ------------------------------------------------------------------------------
AS       ?= as
CC       ?= clang
CFLAGS   ?= -w #-O3 -Wall -Wextra -Wpedantic #-Werror -std=c99 \
	          -Wundef -Wshadow -Wcast-align -Wpointer-arith \
	          -fstrict-aliasing -fno-common -pipe -g

# NOTE: -Wvla was removed for CFLAGS due to the usage of SPX_VLA
# Ignore Compilation Warnings for now

JASMIN       ?= jasminc
JFLAGS       ?= -nowarning -g ${JADDFLAGS} # -lazy-regalloc
JPP          ?= ../scripts/jpp
PREPROCESSOR ?= ../scripts/preprocessor

# ------------------------------------------------------------------------------

HASH_LIST   := shake
PARAMS_LIST := 128f 128s 192f 192s 256f 256s
THASH_LIST  := simple robust

TLIST := $(foreach H,$(HASH_LIST), $(foreach P,$(PARAMS_LIST), $(foreach T,$(THASH_LIST), $(H)_$(P)_$(T))))

# ------------------------------------------------------------------------------
TESTS := $(addprefix bin/test_wots_, $(TLIST))
OUT   := $(addsuffix .out, $(TESTS))

GET_HASH       = $(word 1, $(subst _, ,$*))
GET_PARAM      = $(word 2, $(subst _, ,$*))
GET_THASH      = $(word 3, $(subst _, ,$*))

# ------------------------------------------------------------------------------

JPP_FILES := $(addsuffix .jpp, $(TESTS))
ASM_FILES := $(JPP_FILES:.jpp=.s)

# ------------------------------------------------------------------------------

SOURCES = $(filter-out ../../hash_%.c ../../thash_%.c ../../PQCgenKAT_sign.c ../../rng.c, $(wildcard ../../*.c)) \
          ../../hash_$(GET_HASH).c ../../thash_$(GET_HASH)_$(GET_THASH).c

TEST_FLAGS = -DTEST_WOTS_BASE_W -DTEST_WOTS_GEN_CHAIN -DTEST_WOTS_CHECKSUM -DTEST_WOTS_CHAIN_LENGTHS -DTEST_WOTS_PK_FROM_SIG 

# ------------------------------------------------------------------------------

default: $(TESTS)
run: $(OUT)

jpp_files: $(JPP_FILES)
asm_files: $(ASM_FILES)

$(JPP_FILES):
.PRECIOUS: bin/test_wots_%.jpp
bin/test_wots_%.jpp: | bin/
	cp test_wots.jazz $@
	sed -i "1 i\from Sphincs require \"params/params-sphincs-$(GET_HASH)-$(GET_PARAM).jinc\"" $@
	sed -i "2 i\from Sphincs require \"thash/thash_$(GET_HASH)_$(GET_THASH).jtmpl\"" $@
	$(JPP) -I Sphincs:../../ -in $@ -out $@
	$(PREPROCESSOR) --input_file $@ --output_file $@

.PRECIOUS: bin/test_wots_%.s
bin/test_wots_%.s: bin/test_wots_%.jpp
	$(JASMIN) $(JFLAGS) $< -o $@

$(TESTS):
bin/test_wots_%: bin/test_wots_%.s | bin/
	$(CC) $(CFLAGS) -o $@ -DPARAMS=sphincs-$(GET_HASH)-$(GET_PARAM) $(TEST_FLAGS) \
	-I../common -I../../ -I../../params test_wots.c $< $(SOURCES)

bin/test_wots_%.out: bin/test_wots_%
	@./$<

bin/:
	mkdir -p bin/

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/
