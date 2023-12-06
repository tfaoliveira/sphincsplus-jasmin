# ------------------------------------------------------------------------------
AS       ?= as
CC       ?= clang
CFLAGS   ?= -O3 -Wall -Wextra -Wpedantic -Werror -std=c99 \
	          -Wundef -Wshadow -Wcast-align -Wpointer-arith -Wmissing-prototypes \
	          -fstrict-aliasing -fno-common -pipe -g

# NOTE: -Wvla was removed for CFLAGS due to the usage of SPX_VLA

JASMIN   ?= jasminc
JFLAGS   ?= -lazy-regalloc -nowarning
JPP      ?= ../scripts/jpp
PREPROCESSOR ?= ../scripts/preprocessor

# ------------------------------------------------------------------------------

HASH_LIST     := shake
PARAMS_LIST   := 128f 128s 192f 192s 256f 256s
IN_LEN_LIST  := $(shell seq 1 100)

TLIST := $(foreach H,$(HASH_LIST),$(foreach P,$(PARAMS_LIST),$(foreach L,$(IN_LEN_LIST),$(H)_$(P)_$(L))))

# ------------------------------------------------------------------------------
TESTS      := $(addprefix bin/test_generic_, $(TLIST))
OUT        := $(addsuffix .out, $(TESTS))

GET_HASH       = $(word 1, $(subst _, ,$*))
GET_PARAM      = $(word 2, $(subst _, ,$*))
GET_INLEN      = $(word 3, $(subst _, ,$*))
# ------------------------------------------------------------------------------

JPP_FILES := $(addsuffix .jpp, $(TESTS))

# ------------------------------------------------------------------------------

default: $(TESTS)
run: $(OUT)
jpp_files: $(JPP_FILES)

$(JPP_FILES):
.PRECIOUS: bin/test_generic_%.jpp
bin/test_generic_%.jpp: | bin/
	cp test_generic.jazz $@
	sed -i "1 i\from Sphincs require \"params/params-sphincs-$(GET_HASH)-$(GET_PARAM).jinc\"" $@
	$(JPP) -I Sphincs:../../ -in $@ -out $@
	$(PREPROCESSOR) --input_file $@ --output_file $@ --task "fn:zero_array_u32_jazz p:INLEN:$(GET_INLEN)" "fn:mem_eq_u8_jazz p:LEN:$(GET_INLEN)" "fn:ull_to_bytes_t_jazz p:OUTLEN:$(GET_INLEN)"


.PRECIOUS: bin/test_generic_%.s
bin/test_generic_%.s: bin/test_generic_%.jpp
	$(JASMIN) $(JFLAGS) $< -o $@

$(TESTS):
bin/test_generic_%: bin/test_generic_%.s | bin/
	$(CC) $(CFLAGS) -o $@ -DINLEN=$(GET_INLEN) -DPARAMS=sphincs-$(GET_HASH)-$(GET_PARAM) \
-I../common -I../../ -I../../params \
test_generic.c ../common/print.c $<

bin/test_generic_%.out: bin/test_generic_%
	@./$<

bin/:
	mkdir -p bin/

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/
