# ------------------------------------------------------------------------------
CC       ?= clang
CFLAGS   ?= -w #-O3 -Wall -Wextra -Wpedantic -Werror -std=c99 \
	          -Wundef -Wshadow -Wcast-align -Wpointer-arith \
	          -fstrict-aliasing -fno-common -pipe -g

# Supress all compilation warnings for now

# NOTE: -Wvla was removed for CFLAGS due to the usage of SPX_VLA

JASMIN       ?= jasminc
JFLAGS       ?= -wunusedvar -wduplicatevar # -lazy-regalloc
JPP          ?= ../scripts/jpp
PREPROCESSOR ?= ../scripts/preprocessor

# ------------------------------------------------------------------------------

HASH_LIST     := shake
PARAMS_LIST   := 128f # 128s 192f 192s 256f 256s
THASH_LIST    := simple # robust

TLIST := $(foreach H,$(HASH_LIST), $(foreach P,$(PARAMS_LIST), $(foreach T,$(THASH_LIST), $(H)_$(P)_$(T))))

# ------------------------------------------------------------------------------
TESTS      := $(addprefix bin/test_sign_, $(TLIST))
OUT        := $(addsuffix .out, $(TESTS))

GET_HASH       = $(word 1, $(subst _, ,$*))
GET_PARAM      = $(word 2, $(subst _, ,$*))
GET_THASH      = $(word 3, $(subst _, ,$*))
GET_MSG_LEN    = $(word 4, $(subst _, ,$*))

# ------------------------------------------------------------------------------

ASM_FILES := $(wildcard asm/*.s)

# ------------------------------------------------------------------------------
default: $(TESTS)
run: $(OUT)

$(TESTS):
bin/test_sign_%: bin/ asm/
	$(CC) $(CFLAGS) -o $@ \
	-DPARAMS=sphincs-$(GET_HASH)-$(GET_PARAM) -DTHASH=$(GET_THASH) \
-I../common -I../../ -I../../params \
test_sign.c ../../hash_$(GET_HASH).c ../../merkle.c \
../../wots.c ../../wotsx1.c ../../fips202.c ../../utils.c \
../../address.c ../../thash_$(GET_HASH)_$(GET_THASH).c \
../../utilsx1.c ../../fors.c ../../sign_2.c $(ASM_FILES)

bin/test_sign_%.out: bin/test_sign_%
	@./$<

bin/:
	mkdir -p bin/

asm/:
	./compile_asm.sh

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/ asm/

debug:
	@echo $(ASM_FILES)