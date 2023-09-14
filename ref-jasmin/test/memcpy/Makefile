# ------------------------------------------------------------------------------
AS     ?= as
CC     ?= clang
CFLAGS ?= -O3 -Wall -Wextra -Wpedantic -Wvla -Werror -std=c99 \
	        -Wundef -Wshadow -Wcast-align -Wpointer-arith -Wmissing-prototypes \
	        -fstrict-aliasing -fno-common -pipe -g
JASMIN ?= jasminc
JPP    ?= ../scripts/jpp
JASMINPP  ?= ../scripts/preprocessor

# ------------------------------------------------------------------------------
MIN_INOUT ?= 1
MAX_INOUT ?= 16

# ------------------------------------------------------------------------------
OUT_u8u8_LIST := $(shell seq $(MIN_INOUT) 1 $(MAX_INOUT))
IN_u8u8_LIST   = $(shell seq $(MIN_INOUT) 1 $(O))
T_u8u8_LIST   := $(foreach O,$(OUT_u8u8_LIST), $(foreach I,$(IN_u8u8_LIST),$(O)_$(I)))

OUT_u8u32_LIST := $(shell seq $(MIN_INOUT) 1 $(MAX_INOUT))
IN_u8u32_LIST   = $(shell seq $(MIN_INOUT) 1 $(O))
T_u8u32_LIST   := $(foreach O,$(OUT_u8u32_LIST), $(foreach I,$(IN_u8u32_LIST),$(shell echo $$(($(O)*4)))_$(I)))

# ------------------------------------------------------------------------------
TESTS_u8u8  := $(addprefix bin/test_memcpy_u8u8_,  $(T_u8u8_LIST))
TESTS_u8u32 := $(addprefix bin/test_memcpy_u8u32_, $(T_u8u32_LIST))
TESTS       := $(TESTS_u8u8) $(TESTS_u8u32)

OUT_u8u8    := $(addsuffix .out, $(TESTS_u8u8))
OUT_u8u32   := $(addsuffix .out, $(TESTS_u8u32))
OUT         := $(addsuffix .out, $(TESTS))

# ------------------------------------------------------------------------------
default: $(TESTS)
default_u8u8: $(TESTS_u8u8)
default_u8u32: $(TESTS_u8u32)

run: $(OUT)
run_u8u8: $(OUT_u8u8)
run_u8u32: $(OUT_u8u32)

# ------------------------------------------------------------------------------
GET_OUTLEN  = $(word 1, $(subst _, ,$*))
GET_INLEN   = $(word 2, $(subst _, ,$*))

.PRECIOUS: bin/test_memcpy_%.jpp
bin/test_memcpy_%.jpp:
	$(JPP) -I Sphincs:../../ -in test_memcpy.jazz -out $@
	$(JASMINPP) --input_file $@ --output_file $@ --task "fn:x_memcpy_u8u8 p:OUTLEN:$(GET_OUTLEN) p:INLEN:$(GET_INLEN)" "fn:x_memcpy_u8u8p p:OUTLEN:$(GET_OUTLEN)" "fn:x_memcpy_u8u32 p:OUTLEN:$(GET_OUTLEN) p:INLEN:$(GET_INLEN)"
	
.PRECIOUS: bin/test_memcpy_%.s
bin/test_memcpy_%.s: bin/test_memcpy_%.jpp
	jasminc $< -o $@

$(TESTS):
bin/test_memcpy_u8u8_%: bin/test_memcpy_%.s | bin/
	$(CC) $(CFLAGS) -o $@ -DOUTLEN=$(GET_OUTLEN) -DINLEN=$(GET_INLEN) -I../common test_memcpy_u8u8.c $<

bin/test_memcpy_u8u32_%: bin/test_memcpy_%.s | bin/
	$(CC) $(CFLAGS) -o $@ -DOUTLEN=$(GET_OUTLEN) -DINLEN=$(GET_INLEN) -I../common test_memcpy_u8u32.c $<

bin/test_memcpy_%.out: bin/test_memcpy_%
	@./$<

bin/:
	mkdir -p bin/

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/
