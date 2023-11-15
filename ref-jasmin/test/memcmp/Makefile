# ------------------------------------------------------------------------------
AS     ?= as
CC     ?= clang
CFLAGS ?= -O3 -Wall -Wextra -Wpedantic -Wvla -Werror -std=c99 \
	        -Wundef -Wshadow -Wcast-align -Wpointer-arith -Wmissing-prototypes \
	        -fstrict-aliasing -fno-common -pipe -g
			
JASMIN ?= jasminc
JPP    ?= ../scripts/jpp
PREPROCESSOR  ?= ../scripts/preprocessor

# ------------------------------------------------------------------------------
MIN_INOUT ?= 1
MAX_INOUT ?= 16

# ------------------------------------------------------------------------------
OUT_u8u8_LIST := $(shell seq $(MIN_INOUT) 1 $(MAX_INOUT))
IN_u8u8_LIST   = $(shell seq $(MIN_INOUT) 1 $(O))
T_u8u8_LIST   := $(foreach O,$(OUT_u8u8_LIST), $(foreach I,$(IN_u8u8_LIST),$(O)_$(I)))

# ------------------------------------------------------------------------------
TESTS  := $(addprefix bin/test_memcmp_u8u8_,  $(T_u8u8_LIST))
OUT    := $(addsuffix .out, $(TESTS))

# ------------------------------------------------------------------------------
default: $(TESTS)

run: $(OUT)

debug:
	echo $(TESTS)

# ------------------------------------------------------------------------------
GET_OUTLEN  = $(word 1, $(subst _, ,$*))
GET_INLEN   = $(word 2, $(subst _, ,$*))

.PRECIOUS: bin/test_memcmp_%.jpp
bin/test_memcmp_%.jpp:
	$(JPP) -I Sphincs:../../ -in test_memcmp.jazz -out $@
	$(PREPROCESSOR) --input_file $@ --output_file $@ --task "fn:memcmp_jazz p:INLEN:$(GET_INLEN)"
	
.PRECIOUS: bin/test_memcmp_%.s
bin/test_memcmp_%.s: bin/test_memcmp_%.jpp
	$(JASMIN) -nowarning $< -o $@

$(TESTS):
bin/test_memcmp_u8u8_%: bin/test_memcmp_%.s | bin/
	$(CC) $(CFLAGS) -o $@ -DOUTLEN=$(GET_OUTLEN) -DINLEN=$(GET_INLEN) -I../common test_memcmp.c $<

bin/test_memcmp_%.out: bin/test_memcmp_%
	@./$<

bin/:
	mkdir -p bin/

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/
