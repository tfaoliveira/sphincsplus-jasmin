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
MSG_LEN_LIST  := $(shell seq 1 4) 64 # 100 128 256 512 1024

TLIST := $(foreach H,$(HASH_LIST), $(foreach P,$(PARAMS_LIST), $(foreach T,$(THASH_LIST), $(foreach L,$(MSG_LEN_LIST),$(H)_$(P)_$(T)_$(L)))))

# ------------------------------------------------------------------------------
TESTS      := $(addprefix bin/test_hash_, $(TLIST))
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
.PRECIOUS: bin/test_hash_%.jpp
bin/test_hash_%.jpp: | bin/
	cp test_hash.jazz $@
	sed -i "1 i\from Sphincs require \"params/params-sphincs-$(GET_HASH)-$(GET_PARAM).jinc\"" $@
	$(JPP) -I Sphincs:../../ -in $@ -out $@
	$(PREPROCESSOR) --input_file $@ --output_file $@ --task "fn:gen_msg_random_jazz p:MSG_LEN:$(GET_MSG_LEN)" "fn:hash_message_jazz p:MSG_LEN:$(GET_MSG_LEN)"

.PRECIOUS: bin/test_hash_%.s
bin/test_hash_%.s: bin/test_hash_%.jpp
	$(JASMIN) -nowarning $< -o $@

$(TESTS):
bin/test_hash_%: bin/test_hash_%.s | bin/
	$(CC) $(CFLAGS) -o $@ -DMSG_LEN=$(GET_MSG_LEN) -DPARAMS=sphincs-$(GET_HASH)-$(GET_PARAM) \
-I../common -I../../ -I../../params \
test_hash.c $< ../../hash_$(GET_HASH).c ../../fips202.c ../../utils.c ../../address.c ../../thash_$(GET_HASH)_$(GET_THASH).c

bin/test_hash_%.out: bin/test_hash_%
	@./$<

bin/:
	mkdir -p bin/

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/
