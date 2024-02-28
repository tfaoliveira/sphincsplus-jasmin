
# -*- Makefile -*-

AS     ?= as
CC     ?= clang
CFLAGS ?= -w -march=native #-Wall -Wextra -Wpedantic -Wmissing-prototypes -O3 -std=c99 -march=native -fomit-frame-pointer -flto

JASMIN       ?= jasminc
JFLAGS       ?= -nowarning ${JADDFLAGS}
JPP          ?= ../scripts/jpp
PREPROCESSOR ?= ../scripts/preprocessor

HASH_LIST     := shake
PARAMS_LIST   := 128f 128s 192f 192s 256f 256s
THASH_LIST    := simple robust
INBLOCKS_LIST := $(shell seq 1 4) 64 100

TLIST := $(foreach H,$(HASH_LIST), $(foreach P,$(PARAMS_LIST), $(foreach T,$(THASH_LIST), $(foreach N,$(INBLOCKS_LIST),$(H)_$(P)_$(T)_$(N)))))

TESTS      := $(addprefix bin/test_thash_, $(TLIST))
OUT        := $(addsuffix .out, $(TESTS))

GET_HASH     = $(word 1, $(subst _, ,$*))
GET_PARAM    = $(word 2, $(subst _, ,$*))

GET_PARAMS   = sphincs-$(GET_HASH)-$(GET_PARAM)
GET_THASH    = $(word 3, $(subst _, ,$*))
GET_INBLOCKS = $(word 4, $(subst _, ,$*))

JPP_FILES := $(addsuffix .jpp, $(TESTS))
ASM_FILES := $(JPP_FILES:.jpp=.s)
OBJ_FILES := $(ASM_FILES:.s=.o)

jpp_files: $(JPP_FILES)
asm_files: $(ASM_FILES)
obj_files: $(OBJ_FILES)

$(JPP_FILES):
.PRECIOUS: bin/test_thash_%.jpp
bin/test_thash_%.jpp: | bin/
	cp test_thash_4x.jazz $@
	sed -i "1 i\from Sphincs require \"params/params-sphincs-$(GET_HASH)-$(GET_PARAM).jinc\"" $@
	sed -i "2 i\from Sphincs require \"thash_4x/thash_4x_$(GET_HASH)_$(GET_THASH).jtmpl\"" $@
	$(JPP) -I Sphincs:../../ -in $@ -out $@
	$(PREPROCESSOR) --input_file $@ --output_file $@ --task "fn:thash p:INBLOCKS:$(GET_INBLOCKS)"

$(ASM_FILES):
.PRECIOUS: bin/test_thash_%.s
bin/test_thash_%.s: bin/test_thash_%.jpp
	$(JASMIN) $(JFLAGS) $< -o $@

bin/test_thash_%.out: bin/test_thash_%
	@./$<

bin/:
	mkdir -p $@

.PHONY: clean
clean:
	rm -fr bin/