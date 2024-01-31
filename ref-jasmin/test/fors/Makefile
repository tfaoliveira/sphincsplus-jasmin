# ------------------------------------------------------------------------------
AS       ?= as
CC       ?= clang
CFLAGS   ?= -w # -O3 -g -Wall -Wextra -Wpedantic #-Werror -std=c99 \
	          -Wundef -Wshadow -Wcast-align -Wpointer-arith \
	          -fstrict-aliasing -fno-common -pipe -g

# NOTE: -Wvla was removed for CFLAGS due to the usage of SPX_VLA
# Ignore compilation warnings for now

JASMIN       ?= jasminc
JFLAGS       ?= -lazy-regalloc -nowarning
JPP          ?= ../scripts/jpp
PREPROCESSOR ?= ../scripts/preprocessor

# ------------------------------------------------------------------------------

HASH_LIST     := shake
PARAMS_LIST   := 128f # 128s 192f 192s 256f 256s
THASH_LIST    := simple robust

TLIST := $(foreach H,$(HASH_LIST), $(foreach P,$(PARAMS_LIST), $(foreach T,$(THASH_LIST),$(H)_$(P)_$(T))))

# ------------------------------------------------------------------------------
TESTS      := $(addprefix bin/test_fors_, $(TLIST))
OUT        := $(addsuffix .out, $(TESTS))

GET_HASH       = $(word 1, $(subst _, ,$*))
GET_PARAM      = $(word 2, $(subst _, ,$*))
GET_THASH      = $(word 3, $(subst _, ,$*))

# ------------------------------------------------------------------------------

JPP_FILES := $(addsuffix .jpp, $(TESTS))
ASM_FILES := $(JPP_FILES:.jpp=.s)

# ------------------------------------------------------------------------------
default: $(TESTS)
run: $(OUT)
jpp_files: $(JPP_FILES)
asm_files: $(ASM_FILES)

$(JPP_FILES):
.PRECIOUS: bin/test_fors_%.jpp
bin/test_fors_%.jpp: | bin/
	cp test_fors.jazz $@
	sed -i "1 i\from Sphincs require \"params/params-sphincs-$(GET_HASH)-$(GET_PARAM).jinc\"" $@
	sed -i "2 i\from Sphincs require \"thash/thash_$(GET_HASH)_$(GET_THASH).jtmpl\"" $@
	$(JPP) -I Sphincs:../../ -in $@ -out $@
	$(PREPROCESSOR) --workers 8 --input_file $@ --output_file $@

.PRECIOUS: bin/test_fors_%.s
bin/test_fors_%.s: bin/test_fors_%.jpp
	$(JASMIN) $(JFLAGS) $< -o $@

$(TESTS):
bin/test_fors_%: bin/test_fors_%.s | bin/
	$(CC) $(CFLAGS) -o $@ \
	-DPARAMS=sphincs-$(GET_HASH)-$(GET_PARAM) -DTHASH=$(GET_THASH) \
-DTEST_FORS_TREEHASH -DTEST_FORS \
-I../common -I../../ -I../../params \
test_fors.c $< ../../hash_$(GET_HASH).c ../../fips202.c ../../utils.c \
../../address.c ../../thash_$(GET_HASH)_$(GET_THASH).c ../../utilsx1.c \
../../merkle.c ../../wots.c ../../wotsx1.c ../../sign.c 

bin/test_fors_%.out: bin/test_fors_%
	@./$<

bin/:
	mkdir -p bin/

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/

debug:
	echo $(TESTS)