# ------------------------------------------------------------------------------
AS       ?= as
CC       ?= clang
CFLAGS   ?= -w -g #-O3 -Wall -Wextra -Wpedantic -Werror -std=c99 \
	          -Wundef -Wshadow -Wcast-align -Wpointer-arith \
	          -fstrict-aliasing -fno-common -pipe -g

# Supress all compilation warnings for now

# NOTE: -Wvla was removed for CFLAGS due to the usage of SPX_VLA

JASMIN       ?= jasminc
JFLAGS       ?= -nowarning -g ${JADDFLAGS} # -wunusedvar -wduplicatevar 
JPP          ?= ../scripts/jpp
PREPROCESSOR ?= ../scripts/preprocessor

# ------------------------------------------------------------------------------

HASH_LIST   := shake
PARAMS_LIST := 128f 192f 256f # 128s 192s 256s 
THASH_LIST  := simple robust

TLIST := $(foreach H,$(HASH_LIST), $(foreach P,$(PARAMS_LIST), $(foreach T,$(THASH_LIST), $(H)_$(P)_$(T))))

# ------------------------------------------------------------------------------
TESTS := $(addprefix bin/test_sign_, $(TLIST))
OUT   := $(addsuffix .out, $(TESTS))

GET_HASH    = $(word 1, $(subst _, ,$*))
GET_PARAM   = $(word 2, $(subst _, ,$*))
GET_THASH   = $(word 3, $(subst _, ,$*))

# ------------------------------------------------------------------------------

JTMPL_FILES := $(addsuffix .jtmpl, $(TESTS))
JPP_FILES := $(addsuffix .jpp, $(TESTS))
ASM_FILES := $(JPP_FILES:.jpp=.s)
OBJ_FILES := $(ASM_FILES:.s=.o)

SOURCES = ../../hash_$(GET_HASH).c ../../merkle.c ../../wots.c ../../wotsx1.c ../../fips202.c ../../utils.c \
		  ../../address.c ../../thash_$(GET_HASH)_$(GET_THASH).c ../../utilsx1.c ../../fors.c ../../sign.c ../../wrappers.c

# ------------------------------------------------------------------------------
default: $(TESTS)
run: $(OUT)

jtmpl_files: $(JTMPL_FILES)
jpp_files:   $(JPP_FILES)
asm_files:   $(ASM_FILES)
obj_files:   $(OBJ_FILES)

checkct: $(patsubst %.jpp,%.check,$(JPP_FILES))

%.check: %.jpp
	$(JASMIN) $(JFLAGS) -checkCT -infer $< > $@

%.o: %.s
	$(AS) $< -o $@

$(JTMPL_FILES):
.PRECIOUS: bin/test_sign_%.jtmpl
bin/test_sign_%.jtmpl: | bin/
	cp test_sign.jazz $@
	sed -i "1 i\from Sphincs require \"params/params-sphincs-$(GET_HASH)-$(GET_PARAM).jinc\"" $@
	sed -i "2 i\from Sphincs require \"thash/thash_$(GET_HASH)_$(GET_THASH).jtmpl\"" $@
	$(JPP) -I Sphincs:../../ -in $@ -out $@


$(JPP_FILES):
.PRECIOUS: bin/test_sign_%.jpp
bin/test_sign_%.jpp: bin/test_sign_%.jtmpl
	$(PREPROCESSOR) --input_file $< --output_file $@

$(ASM_FILES):
.PRECIOUS: bin/test_sign_%.s
bin/test_sign_%.s: bin/test_sign_%.jpp
	$(JASMIN) $(JFLAGS) $< -o $@

$(TESTS):
bin/test_sign_%: bin/test_sign_%.s | bin/
	$(CC) $(CFLAGS) -o $@ \
	-DPARAMS=sphincs-$(GET_HASH)-$(GET_PARAM) -DTHASH=$(GET_THASH) \
	-DTESTS=10 \
	-I../common -I../../ -I../../params test_sign.c $< $(SOURCES)

bin/test_sign_%.out: bin/test_sign_%
	@./$<

bin/:
	mkdir -p bin/

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/
