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

HASH_LIST     := shake
PARAMS_LIST   := 128f 128s 192f 192s 256f 256s
THASH_LIST    := simple robust
INBLOCKS_LIST := $(shell seq 1 4) 64 100

TLIST := $(foreach H,$(HASH_LIST), $(foreach P,$(PARAMS_LIST), $(foreach T,$(THASH_LIST), $(foreach N,$(INBLOCKS_LIST),$(H)_$(P)_$(T)_$(N)))))

# ------------------------------------------------------------------------------
TESTS      := $(addprefix bin/test_thash_, $(TLIST))
OUT        := $(addsuffix .out, $(TESTS))

GET_HASH     = $(word 1, $(subst _, ,$*))
GET_PARAM    = $(word 2, $(subst _, ,$*))

GET_PARAMS   = sphincs-$(GET_HASH)-$(GET_PARAM)
GET_THASH    = $(word 3, $(subst _, ,$*))
GET_INBLOCKS = $(word 4, $(subst _, ,$*))

# ------------------------------------------------------------------------------
JPP_FILES := $(addsuffix .jpp, $(TESTS))

# ------------------------------------------------------------------------------
default: $(TESTS)
run: $(OUT)
jpp_files: $(JPP_FILES)

$(JPP_FILES):
.PRECIOUS: bin/test_thash_%.jpp
bin/test_thash_%.jpp: | bin/
	cp test_thash.jazz $@
	sed -i "1 i\from Sphincs require \"params/params-sphincs-$(GET_HASH)-$(GET_PARAM).jinc\"" $@
	sed -i "2 i\from Sphincs require \"thash/thash_$(GET_HASH)_$(GET_THASH).jtmpl\"" $@
	$(JPP) -I Sphincs:../../ -in $@ -out $@
	$(PREPROCESSOR) --input_file $@ --output_file $@ \
	--task "fn:thash p:INBLOCKS:$(GET_INBLOCKS)" "fn:thash_in_u64_jazz p:INBLOCKS:$(GET_INBLOCKS)"

.PRECIOUS: bin/test_thash_%.s
bin/test_thash_%.s: bin/test_thash_%.jpp
	$(JASMIN) $< -o $@

$(TESTS):
bin/test_thash_%: bin/test_thash_%.s | bin/
	$(CC) $(CFLAGS) -o $@ -DPARAMS=$(GET_PARAMS) -DTHASH=$(GET_THASH) -DINBLOCKS=$(GET_INBLOCKS) \
-I../common -I../../ -I../../params \
test_thash.c $< ../../thash_$(GET_HASH)_$(GET_THASH).c ../../fips202.c

bin/test_thash_%.out: bin/test_thash_%
	@./$<

bin/:
	mkdir -p bin/

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/
