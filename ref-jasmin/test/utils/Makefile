# ------------------------------------------------------------------------------
AS       ?= as
CC       ?= clang
CFLAGS   ?= -O3 -Wall -Wextra -Wpedantic -Werror -std=c99 \
	          -Wundef -Wshadow -Wcast-align -Wpointer-arith -Wmissing-prototypes \
	          -fstrict-aliasing -fno-common -pipe -g

# NOTE: -Wvla was removed for CFLAGS due to the usage of SPX_VLA

JASMIN   ?= jasminc
JPP      ?= ../scripts/jpp
JASMINPP ?= ../scripts/preprocessor

# ------------------------------------------------------------------------------

HASH_LIST     := shake
PARAMS_LIST   := 128f 128s 192f 192s 256f 256s
THASH_LIST    := simple # robust
INBLOCKS_LIST := $(shell seq 1 4) 64 100

TLIST := $(foreach H,$(HASH_LIST), $(foreach P,$(PARAMS_LIST), $(foreach T,$(THASH_LIST), $(foreach N,$(INBLOCKS_LIST),$(H)_$(P)_$(T)_$(N)))))

# ------------------------------------------------------------------------------
TESTS      := $(addprefix bin/test_thash_, $(TLIST))
OUT        := $(addsuffix .out, $(TESTS))

GET_HASH     = $(word 1, $(subst _, ,$*))
GET_PARAM    = $(word 2, $(subst _, ,$*))
GET_THASH    = $(word 3, $(subst _, ,$*))
GET_INBLOCKS = $(word 4, $(subst _, ,$*))

# ------------------------------------------------------------------------------
JPP_FILES := $(addsuffix .jpp, $(TESTS))

# ------------------------------------------------------------------------------
# -- testing stuff
entry: bin/test_utils.jpp

bin/test_utils.jpp: | bin/
	cp test_utils.jazz $@
	$(JPP) -I Sphincs:../../ -in $@ -out $@
	$(JASMINPP) --input_file $@ --output_file $@

# ------------------------------------------------------------------------------

bin/:
	mkdir -p bin/

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/
