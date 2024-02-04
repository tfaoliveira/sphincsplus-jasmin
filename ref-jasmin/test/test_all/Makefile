# -*- Makefile -*-

CC       ?= clang
CFLAGS   ?= -w

# ------------------------------------------------------------------------------

JASMIN       ?= jasminc
JFLAGS       ?= -nowarning -g ${JADDFLAGS}
JPP          ?= ../scripts/jpp
PREPROCESSOR ?= ../scripts/preprocessor

# ------------------------------------------------------------------------------

HASH_LIST   := shake
PARAMS_LIST := 128f 128s 192f 192s 256f 256s
THASH_LIST  := simple robust

TLIST := $(foreach H,$(HASH_LIST), $(foreach P,$(PARAMS_LIST), $(foreach T,$(THASH_LIST), $(H)_$(P)_$(T))))

# ------------------------------------------------------------------------------

TESTS := $(addprefix bin/test_sign_, $(TLIST))
OUT   := $(addsuffix .out, $(TESTS))

GET_HASH       = $(word 1, $(subst _, ,$*))
GET_PARAM      = $(word 2, $(subst _, ,$*))
GET_THASH      = $(word 3, $(subst _, ,$*))

# ------------------------------------------------------------------------------

# Assembly files we need to compile
ASM_FILES :=

# TODO: replace with filter out . wildcard
SOURCES := ../../wots.c ../../fips202.c ../../utils.c ../../address.c  ../../utilsx1.c ../../fors.c \
			../../merkle.c ../../sign.c ../../wotsx1.c ../../wrappers.c

TEST_FLAGS :=

# ------------------------------------------------------------------------------

default: $(TESTS)
run: $(OUT)

$(TESTS):
bin/test_%: $(ASM_FILES) | bin/
	$(CC) $(CFLAGS) -o $@ -DPARAMS=sphincs-$(GET_HASH)-$(GET_PARAM) $(TEST_FLAGS) \
	-I../common -I../../ -I../../params test.c $< \
	../../hash_$(GET_HASH).c ../../thash_$(GET_HASH)_$(GET_THASH).c \
	$(SOURCES) $(ASM_FILES)


# TODO:

bin/test_%.out: bin/test_%
	@./$<


bin/:
	mkdir -p $@

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/
