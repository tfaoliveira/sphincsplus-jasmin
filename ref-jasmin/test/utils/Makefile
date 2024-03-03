# ------------------------------------------------------------------------------
AS       ?= as
CC       ?= clang
CFLAGS   ?= -w #-O3 -Wall -Wextra -Wpedantic -Werror -std=c99 \
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
THASH_LIST    := simple # robust

TLIST := $(foreach H,$(HASH_LIST), $(foreach P,$(PARAMS_LIST), $(foreach T,$(THASH_LIST),$(H)_$(P)_$(T))))

# ------------------------------------------------------------------------------

TESTS := $(addprefix bin/test_utils_, $(TLIST))
OUT   := $(addsuffix .out, $(TESTS))

GET_HASH  = $(word 1, $(subst _, ,$*))
GET_PARAM = $(word 2, $(subst _, ,$*))

GET_PARAMS   = sphincs-$(GET_HASH)-$(GET_PARAM)
GET_THASH    = $(word 3, $(subst _, ,$*))
GET_INBLOCKS = $(word 4, $(subst _, ,$*))

# ------------------------------------------------------------------------------

JPP_FILES := $(addsuffix .jpp, $(TESTS))
ASM_FILES := $(JPP_FILES:.jpp=.s)
OBJ_FILES := $(ASM_FILES:.s=.o)

# ------------------------------------------------------------------------------

SOURCES := $(filter-out ../../thash_%.c ../../utils.c ../../rng.c ../../PQCgenKAT_sign.c, $(wildcard ../../*.c))

TEST_FLAGS = -DTEST_COMPUTE_ROOT

# ------------------------------------------------------------------------------

default: $(TESTS)
run: $(OUT)

jpp_files: $(JPP_FILES)
asm_files: $(ASM_FILES)
obj_files: $(OBJ_FILES)

# ------------------------------------------------------------------------------

%.o: %.s
	$(AS) $< -o $@


# ------------------------------------------------------------------------------

$(JPP_FILES):
.PRECIOUS: bin/test_utils_%.jpp
bin/test_utils_%.jpp: | bin/
	cp test_utils.jazz $@
	sed -i "1 i\from Sphincs require \"params/params-sphincs-$(GET_HASH)-$(GET_PARAM).jinc\"" $@
	sed -i "2 i\from Sphincs require \"thash/thash_$(GET_HASH)_$(GET_THASH).jtmpl\"" $@
	$(JPP) -I Sphincs:../../ -in $@ -out $@
	$(PREPROCESSOR) --input_file $@ --output_file $@

.PRECIOUS: bin/test_utils_%.s
bin/test_utils_%.s: bin/test_utils_%.jpp
	$(JASMIN) $(JFLAGS) $< -o $@

$(TESTS):
bin/test_utils_%: bin/test_utils_%.s | bin/
	$(CC) $(CFLAGS) -o $@ -DPARAMS=$(GET_PARAMS) -DTHASH=$(GET_THASH) $(TEST_FLAGS) \
	-I../common -I../../ -I../../params \
	test_utils.c $< ../../thash_$(GET_HASH)_$(GET_THASH).c $(SOURCES)

bin/test_utils_%.out: bin/test_utils_%
	@./$<

bin/:
	mkdir -p bin/

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/

