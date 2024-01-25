# -*- Makefile -*-

CC       ?= clang
CFLAGS   ?= -w # -O3 -Wall -Wextra -Werror -std=c99 \
			  -Wshadow -Wcast-align -Wpointer-arith \
	          -fstrict-aliasing -fno-common -pipe -g #-Wundef -Wpedantic
# Only for shake 
HASH_LIST     := shake
PARAMS_LIST   := 128f
THASH_LIST    := simple #robust

TLIST := $(foreach H,$(HASH_LIST), $(foreach P,$(PARAMS_LIST), $(foreach T,$(THASH_LIST), $(H)_$(P)_$(T))))

TESTS := $(addprefix bin/test_sign_, $(TLIST))
OUT   := $(addsuffix .out, $(TESTS))

GET_HASH  = $(word 1, $(subst _, ,$*))
GET_PARAM = $(word 2, $(subst _, ,$*))
GET_THASH = $(word 3, $(subst _, ,$*))

ASM_FILES    = $(filter-out thash%, $(wildcard asm/*.s)) # FIXME: Replace the script with rules
C_FILES      = $(filter-out thash%, $(wildcard *.c))
HEADER_FILES = $(wildcard *.h)

default: asm/ $(TESTS)
run: $(OUT)

$(TESTS):
bin/test_sign_%: bin/ asm/
	$(CC) $(CFLAGS) -o $@ \
	-DPARAMS=sphincs-$(GET_HASH)-$(GET_PARAM) \
	-I . -I common -I params \
	$(ASM_FILES) $(C_FILES) $(HEADER_FILES)

bin/test_sign_%.out: bin/test_sign_%
	@./$<

bin/:
	mkdir -p $@

asm/:
	mkdir -p $@ && ./compile_asm.sh

.PHONY: clean
clean:
	rm -fr bin/ asm/
