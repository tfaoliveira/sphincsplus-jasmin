# ------------------------------------------------------------------------------
AS       ?= as
CC       ?= clang
CFLAGS   ?= -w # -O3 -Wall -Wextra -Wpedantic -Werror -std=c99 \
	          -Wundef -Wshadow -Wcast-align -Wpointer-arith -Wmissing-prototypes \
	          -fstrict-aliasing -fno-common -pipe -g

# NOTE: -Wvla was removed for CFLAGS due to the usage of SPX_VLA

JASMIN       ?= jasminc
JFLAGS       ?= -nowarning ${JADDFLAGS}
JPP          ?= ../scripts/jpp
PREPROCESSOR ?= ../scripts/preprocessor

# ------------------------------------------------------------------------------

HASH_LIST     := shake
PARAMS_LIST   := 128f 128s 192f 192s 256f 256s
THASH_LIST    := simple robust

# note on THASH
# - address.c requires code from utils.c which requires code from thash_*.c
# - even though address.c only uses code from utils that does not depend on thash
#   to keep things simple we include it in testing this way. In principle, there
#   should be no need to add robust to the THASH_LIST when available as it would
#   only repeat the ~same tests

TLIST := $(foreach H,$(HASH_LIST), $(foreach P,$(PARAMS_LIST), $(foreach T,$(THASH_LIST), $(H)_$(P)_$(T))))

# ------------------------------------------------------------------------------
SOURCES := $(filter-out ../../thash_%.c, $(wildcard ../../*.c))

TESTS      := $(addprefix bin/test_address_, $(TLIST))
OUT        := $(addsuffix .out, $(TESTS))

GET_HASH     = $(word 1, $(subst _, ,$*))
GET_PARAM    = $(word 2, $(subst _, ,$*))
GET_THASH    = $(word 3, $(subst _, ,$*))

# ------------------------------------------------------------------------------
JPP_FILES := $(addsuffix .jpp, $(TESTS))

# ------------------------------------------------------------------------------
default: $(TESTS)
run: $(OUT)
jpp_files: $(JPP_FILES)

$(JPP_FILES):
.PRECIOUS: bin/test_address_%.jpp
bin/test_address_%.jpp: | bin/
	cp test_address.jazz $@
	sed -i "1 i\from Sphincs require \"params/params-sphincs-$(GET_HASH)-$(GET_PARAM).jinc\"" $@
	$(JPP) -I Sphincs:../../ -in $@ -out $@

.PRECIOUS: bin/test_address_%.s
bin/test_address_%.s: bin/test_address_%.jpp
	$(JASMIN) $(JFLAGS) $< -o $@

$(TESTS):
bin/test_address_%: bin/test_address_%.s | bin/
	$(CC) $(CFLAGS) -o $@ -DPARAMS=sphincs-$(GET_HASH)-$(GET_PARAM) -DTEST_ADDRESS \
	-I../common -I../../ -I../../params \
	test_address.c $< ../../thash_$(GET_HASH)_$(GET_THASH).c $(SOURCES)

bin/test_address_%.out: bin/test_address_%
	@./$<

bin/:
	mkdir -p bin/

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/
