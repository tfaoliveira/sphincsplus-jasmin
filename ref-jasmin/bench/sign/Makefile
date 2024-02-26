# -*- Makefile -*-

CC     = gcc
CFLAGS ?= -Wall -Wextra -Wpedantic -Wmissing-prototypes -O3 -std=c99 -march=native -fomit-frame-pointer -flto -O3

JASMIN       ?= jasminc
JFLAGS       ?= -nowarning -g ${JADDFLAGS}
JPP          ?= ../../test/scripts/jpp
PREPROCESSOR ?= ../../test/scripts/preprocessor


HASH_LIST   := shake
PARAMS_LIST := 128f 192f 256f # 128s 192s 256s 
THASH_LIST  := simple robust

TLIST := $(foreach H,$(HASH_LIST), $(foreach P,$(PARAMS_LIST), $(foreach T,$(THASH_LIST), $(H)_$(P)_$(T))))

TESTS := $(addprefix bin/bench_sign_, $(TLIST))
OUT   := $(addsuffix .out, $(TESTS))

GET_HASH    = $(word 1, $(subst _, ,$*))
GET_PARAM   = $(word 2, $(subst _, ,$*))
GET_THASH   = $(word 3, $(subst _, ,$*))

JPP_FILES := $(addsuffix .jpp, $(TESTS))
ASM_FILES := $(JPP_FILES:.jpp=.s)
OBJ_FILES := $(ASM_FILES:.s=.o)

SOURCES = ../../hash_$(GET_HASH).c ../../merkle.c ../../wots.c ../../wotsx1.c ../../fips202.c ../../utils.c \
		  ../../address.c ../../thash_$(GET_HASH)_$(GET_THASH).c ../../utilsx1.c ../../fors.c ../../sign.c ../../wrappers.c

default: $(TESTS)
run: $(OUT)

jpp_files:   $(JPP_FILES)
asm_files:   $(ASM_FILES)

$(JPP_FILES):
.PRECIOUS: bin/bench_sign_%.jpp
bin/bench_sign_%.jpp: | bin/
	cp ../../test/sign/test_sign.jazz $@
	sed -i "1 i\from Sphincs require \"params/params-sphincs-$(GET_HASH)-$(GET_PARAM).jinc\"" $@
	sed -i "2 i\from Sphincs require \"thash/thash_$(GET_HASH)_$(GET_THASH).jtmpl\"" $@
	$(JPP) -I Sphincs:../../ -in $@ -out $@
	$(PREPROCESSOR) --input_file $@ --output_file $@
	

$(ASM_FILES):
.PRECIOUS: bin/bench_sign_%.s
bin/bench_sign_%.s: bin/bench_sign_%.jpp
	$(JASMIN) $(JFLAGS) $< -o $@

$(TESTS):
bin/bench_sign_%: bin/bench_sign_%.s | bin/ csv/
	$(CC) $(CFLAGS) -o $@ \
	-DPARAMS=sphincs-$(GET_HASH)-$(GET_PARAM) -DTHASH=$(GET_THASH) \
	-I../common -I../../ -I../../params bench_sign.c $< $(SOURCES) \
	../common/print.c ../common/macros.h ../common/notrandombytes.c ../../api.h


bin/bench_sign_%.out: bin/bench_sign_%
	@./$<
	mv *.csv csv/

bin/:
	mkdir -p $@

csv/:
	mkdir -p $@

.PHONY: clean
clean:
	rm -rf bin/ csv/

.PHONY: clean_executables
clean_executables:
	find bin/ -type f -executable -delete
