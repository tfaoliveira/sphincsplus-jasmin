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
MIN_OUTPUTBYTES ?= 0
MAX_OUTPUTBYTES ?= 16

MIN_INPUTBYTES ?= 0
MAX_INPUTBYTES ?= 32

# ------------------------------------------------------------------------------
INPUTBYTES_LIST := $(shell seq $(MIN_INPUTBYTES) $(MAX_INPUTBYTES))
OUTPUTBYTES_LIST := $(shell seq $(MIN_OUTPUTBYTES) $(MAX_OUTPUTBYTES))
TLIST := $(foreach O,$(OUTPUTBYTES_LIST),$(foreach I,$(INPUTBYTES_LIST),$(O)_$(I)))

# ------------------------------------------------------------------------------
TESTS      := $(addprefix bin/test_memcpy_, $(TLIST))
OUT        := $(addsuffix .out, $(TESTS))
GET_OUTLEN  = $(word 1, $(subst _, ,$*))
GET_INLEN   = $(word 2, $(subst _, ,$*))

# ------------------------------------------------------------------------------
default: $(TESTS)
run: $(OUT)

.PRECIOUS: bin/test_memcpy_%.jpp
bin/test_memcpy_%.jpp:
	$(JPP) -I Sphincs:../../ -in test_memcpy.jazz -out $@
	$(JASMINPP) --input_file $@ --output_file $@ --task "fn:x_memcpy_u8u8 p:OUTLEN:$(GET_OUTLEN) p:INLEN:$(GET_INLEN)"

# TODO add more "tasks" to extract 'x_memcpy_u8u32' and 'x_memcpy_u8u8p' when defined

.PRECIOUS: bin/test_memcpy_%.s
bin/test_memcpy_%.s: bin/test_memcpy_%.jpp
	jasminc $< -o $@

$(TESTS):
bin/test_memcpy_%: bin/test_memcpy_%.s | bin/
	$(CC) $(CFLAGS) -o $@ -DOUTLEN=$(GET_OUTLEN) -DINLEN=$(GET_INLEN) -I../common test_memcpy.c $< ../../fips202.c 

bin/test_memcpy_%.out: bin/test_memcpy_%
	@./$<

bin/:
	mkdir -p bin/

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/
