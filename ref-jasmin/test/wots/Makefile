# ------------------------------------------------------------------------------
AS       ?= as
CC       ?= clang
CFLAGS   ?= -O3 -Wall -Wextra -Wpedantic #-Werror -std=c99 \
	          -Wundef -Wshadow -Wcast-align -Wpointer-arith \
	          -fstrict-aliasing -fno-common -pipe -g

# NOTE: -Wvla was removed for CFLAGS due to the usage of SPX_VLA

JASMIN   ?= jasminc
JPP      ?= ../scripts/jpp
JASMINPP ?= ../scripts/preprocessor

# ------------------------------------------------------------------------------

HASH_LIST     := shake
PARAMS_LIST   := 128f 128s 192f 192s 256f 256s
THASH_LIST    := simple
MSG_LEN_LIST  := $(shell seq 1 4) 64 100

TLIST := $(foreach H,$(HASH_LIST), $(foreach P,$(PARAMS_LIST), $(foreach T,$(THASH_LIST), $(foreach L,$(MSG_LEN_LIST),$(H)_$(P)_$(T)_$(L)))))

# ------------------------------------------------------------------------------
TESTS      := $(addprefix bin/test_wots_, $(TLIST))
OUT        := $(addsuffix .out, $(TESTS))

GET_HASH       = $(word 1, $(subst _, ,$*))
GET_PARAM      = $(word 2, $(subst _, ,$*))
GET_THASH      = $(word 3, $(subst _, ,$*))
GET_MSG_LEN    = $(word 4, $(subst _, ,$*))

# ------------------------------------------------------------------------------
JPP_FILES := $(addsuffix .jpp, $(TESTS))

# ------------------------------------------------------------------------------
default: $(TESTS)
run: $(OUT)
jpp_files: $(JPP_FILES)

$(JPP_FILES):
.PRECIOUS: bin/test_wots_%.jpp
bin/test_wots_%.jpp: | bin/
	cp test_wots.jazz $@
	sed -i "1 i\from Sphincs require \"params/params-sphincs-$(GET_HASH)-$(GET_PARAM).jinc\"" $@
	sed -i "2 i\from Sphincs require \"thash/thash_$(GET_HASH)_$(GET_THASH).jtmpl\"" $@
	$(JPP) -I Sphincs:../../ -in $@ -out $@
	$(JASMINPP) --input_file $@ --output_file $@ --task "fn:wots_pk_from_sig_jazz p:MSG_LEN:$(GET_MSG_LEN)" "fn:chain_lengths_jazz p:MSG_LEN:$(GET_MSG_LEN)"

.PRECIOUS: bin/test_wots_%.s
bin/test_wots_%.s: bin/test_wots_%.jpp
	jasminc -lazy-regalloc -nowarning $< -o $@

$(TESTS):
bin/test_wots_%: bin/test_wots_%.s | bin/
	$(CC) $(CFLAGS) -o $@ -DPARAMS=sphincs-$(GET_HASH)-$(GET_PARAM) -DMSG_LEN=$(GET_MSG_LEN) \
-I../common -I../../ -I../../params \
test_wots.c $< ../../hash_$(GET_HASH).c ../../wots.c ../../fips202.c ../../utils.c ../../address.c ../../thash_$(GET_HASH)_$(GET_THASH).c ../../utilsx1.c

bin/test_wots_%.out: bin/test_wots_%
	@./$<

bin/:
	mkdir -p bin/

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/
