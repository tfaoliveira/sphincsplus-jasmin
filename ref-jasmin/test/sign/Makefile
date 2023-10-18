# ------------------------------------------------------------------------------
AS       ?= as
CC       ?= clang
CFLAGS   ?= -O3 -Wall -Wextra -Wpedantic #-Werror -std=c99 \
	          -Wundef -Wshadow -Wcast-align -Wpointer-arith \
	          -fstrict-aliasing -fno-common -pipe -g

# NOTE: -Wvla was removed for CFLAGS due to the usage of SPX_VLA

JASMIN   ?= jasminc
JPP      ?= ../scripts/jpp
PREPROCESSOR ?= ../scripts/preprocessor

# ------------------------------------------------------------------------------

HASH_LIST     := shake
PARAMS_LIST   := 128f 128s 192f 192s 256f 256s
THASH_LIST    := simple
MSG_LEN_LIST  := $(shell seq 1 4) 64 100

TLIST := $(foreach H,$(HASH_LIST), $(foreach P,$(PARAMS_LIST), $(foreach T,$(THASH_LIST), $(foreach L,$(MSG_LEN_LIST),$(H)_$(P)_$(T)_$(L)))))

# ------------------------------------------------------------------------------
TESTS      := $(addprefix bin/test_sign_, $(TLIST))
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
.PRECIOUS: bin/test_sign_%.jpp
bin/test_sign_%.jpp: | bin/
	cp test_sign.jazz $@
	sed -i "1 i\from Sphincs require \"params/params-sphincs-$(GET_HASH)-$(GET_PARAM).jinc\"" $@
	sed -i "2 i\from Sphincs require \"thash/thash_$(GET_HASH)_$(GET_THASH).jtmpl\"" $@
	$(JPP) -I Sphincs:../../ -in $@ -out $@
	$(PREPROCESSOR) --workers 8 -d --input_file $@ --output_file $@ --task "fn:crypto_sign_open_jazz p:MSG_LEN:$(GET_MSG_LEN) p:SIG_LEN:$(GET_MSG_LEN)"

.PRECIOUS: bin/test_sign_%.s
bin/test_sign_%.s: bin/test_sign_%.jpp
	jasminc -nowarning $< -o $@

$(TESTS):
bin/test_sign_%: bin/test_sign_%.s | bin/
	touch $@
# 	$(CC) $(CFLAGS) -o $@ -DPARAMS=sphincs-$(GET_HASH)-$(GET_PARAM) -DMSG_LEN=$(GET_MSG_LEN) \
-I../common -I../../ -I../../params \
test_sign.c $< ../../hash_$(GET_HASH).c ../../wots.c ../../wotsx1.c ../../fips202.c ../../utils.c ../../address.c ../../thash_$(GET_HASH)_$(GET_THASH).c ../../utilsx1.c \
../../fors.c ../../sign.c

bin/test_sign_%.out: bin/test_sign_%
	@./$<

bin/:
	mkdir -p bin/

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/
