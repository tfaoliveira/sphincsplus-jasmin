# ------------------------------------------------------------------------------
AS       ?= as
CC       ?= clang
CFLAGS   ?= -w # -O3 -Wall -Wextra -Wpedantic #-Werror -std=c99 \
	          -Wundef -Wshadow -Wcast-align -Wpointer-arith \
	          -fstrict-aliasing -fno-common -pipe -g

# Suppress compilation warnings for now

# NOTE: -Wvla was removed for CFLAGS due to the usage of SPX_VLA

JASMIN       ?= jasminc
JFLAGS       ?= -nowarning ${JADDFLAGS} 
JPP          ?= ../../../submodules/jasmin-preprocessor/jpp
PREPROCESSOR ?= ../../../submodules/jasmin-preprocessor/preprocessor

# ------------------------------------------------------------------------------

HASH_LIST     := shake
PARAMS_LIST   := 128f # 128s 192f 192s 256f 256s
THASH_LIST    := simple robust

TLIST := $(foreach H,$(HASH_LIST), $(foreach P,$(PARAMS_LIST), $(foreach T,$(THASH_LIST), $(H)_$(P)_$(T))))

# ------------------------------------------------------------------------------

TESTS := $(addprefix bin/test_wotsx1_, $(TLIST))
OUT   := $(addsuffix .out, $(TESTS))

GET_HASH  = $(word 1, $(subst _, ,$*))
GET_PARAM = $(word 2, $(subst _, ,$*))
GET_THASH = $(word 3, $(subst _, ,$*))

# ------------------------------------------------------------------------------

JPP_FILES := $(addsuffix .jpp, $(TESTS))
ASM_FILES := $(JPP_FILES:.jpp=.s)
OBJ_FILES := $(ASM_FILES:.s=.o)

# ------------------------------------------------------------------------------

SOURCES = $(filter-out ../../hash_%.c ../../thash_%.c, $(wildcard ../../*.c)) \
          ../../hash_$(GET_HASH).c ../../thash_$(GET_HASH)_$(GET_THASH).c


# -DDEBUG_WOTSX1 -DTEST_WOTS_GEN_LEAF to debug just wots gen leaf
# -DDEBUG -DTEST_TREEHASH_WOTS to debug just treehash
TEST_FLAGS := -DTEST_WOTS_GEN_LEAF -DTEST_TREEHASH_WOTS

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
.PRECIOUS: bin/test_wotsx1_%.jpp
bin/test_wotsx1_%.jpp: | bin/
	cp test_wotsx1.jazz $@
	sed -i "1 i\from Sphincs require \"params/params-sphincs-$(GET_HASH)-$(GET_PARAM).jinc\"" $@
	sed -i "2 i\from Sphincs require \"thash/thash_$(GET_HASH)_$(GET_THASH).jtmpl\"" $@
	$(JPP) -I Sphincs:../../ -in $@ -out $@
	$(PREPROCESSOR) --input_file $@ --output_file $@

.PRECIOUS: bin/test_wotsx1_%.s
bin/test_wotsx1_%.s: bin/test_wotsx1_%.jpp
	$(JASMIN) $(JFLAGS) $< -o $@

$(TESTS):
bin/test_wotsx1_%: bin/test_wotsx1_%.s | bin/
	$(CC) $(CFLAGS) -o $@ \
	-DPARAMS=sphincs-$(GET_HASH)-$(GET_PARAM) -DTHASH=$(GET_THASH) $(TEST_FLAGS) \
	-I../common -I../../ -I../../params test_wotsx1.c $< $(SOURCES)

bin/test_wotsx1_%.out: bin/test_wotsx1_%
	@./$<

bin/:
	mkdir -p bin/

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/
