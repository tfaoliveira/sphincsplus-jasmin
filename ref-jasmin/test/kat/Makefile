# ------------------------------------------------------------------------------
CC       ?= clang
CFLAGS   ?= -w -g #-O3 -Wall -Wextra -Wpedantic -Werror -std=c99 \
            -Wundef -Wshadow -Wcast-align -Wpointer-arith \
            -fstrict-aliasing -fno-common -pipe -g

# Supress all compilation warnings for now

# NOTE: -Wvla was removed for CFLAGS due to the usage of SPX_VLA

JASMIN       ?= jasminc
JFLAGS       ?= -nowarning ${JADDFLAGS}
JPP          ?= ../scripts/jpp
PREPROCESSOR ?= ../scripts/preprocessor

# ------------------------------------------------------------------------------

HASH_LIST   := shake
PARAMS_LIST := 128f 192f 256f# 128s  192s  256s
THASH_LIST  := simple robust

TLIST := $(foreach H,$(HASH_LIST), $(foreach P,$(PARAMS_LIST), $(foreach T,$(THASH_LIST), $(H)_$(P)_$(T))))

# ------------------------------------------------------------------------------
TESTS := $(addprefix bin/PQC_sign_kat_jasmin_, $(TLIST))
OUT   := $(addsuffix .out, $(TESTS))

GET_HASH    = $(word 1, $(subst _, ,$*))
GET_PARAM   = $(word 2, $(subst _, ,$*))
GET_THASH   = $(word 3, $(subst _, ,$*))

# ------------------------------------------------------------------------------

JPP_FILES := $(addsuffix .jpp, $(TESTS))
ASM_FILES := $(JPP_FILES:.jpp=.s)

# ------------------------------------------------------------------------------
default: $(TESTS)
run: $(OUT)

jpp_files: $(JPP_FILES)
asm_files: $(ASM_FILES)

$(JPP_FILES):
.PRECIOUS: bin/PQC_sign_kat_jasmin_%.jpp
bin/PQC_sign_kat_jasmin_%.jpp: | bin/
	cp ../sign/test_sign.jazz $@
	sed -i "1 i\from Sphincs require \"params/params-sphincs-$(GET_HASH)-$(GET_PARAM).jinc\"" $@
	sed -i "2 i\from Sphincs require \"thash/thash_$(GET_HASH)_$(GET_THASH).jtmpl\"" $@
	$(JPP) -I Sphincs:../../ -in $@ -out $@
	$(PREPROCESSOR) --input_file $@ --output_file $@

.PRECIOUS: bin/PQC_sign_kat_jasmin_%.s
bin/PQC_sign_kat_jasmin_%.s: bin/PQC_sign_kat_jasmin_%.jpp
	$(JASMIN) $(JFLAGS) $< -o $@

$(TESTS):
bin/PQC_sign_kat_jasmin_%: bin/PQC_sign_kat_jasmin_%.s | bin/
	$(CC) $(CFLAGS) -o $@ -DPARAMS=sphincs-$(GET_HASH)-$(GET_PARAM) -DTHASH=$(GET_THASH) \
	-I../common -I../../ -I../../params PQCgenKAT_sign.c rng.c $< -lcrypto

bin/PQC_sign_kat_jasmin_%.out: bin/PQC_sign_kat_jasmin_%
	@./$<

bin/:
	mkdir -p bin/

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/ kats
