# ------------------------------------------------------------------------------
AS     ?= as
CC     ?= clang
CFLAGS ?= -w # -O3 -Wall -Wextra -Wpedantic -Wvla -Werror -std=c99 \
	        -Wundef -Wshadow -Wcast-align -Wpointer-arith -Wmissing-prototypes \
	        -fstrict-aliasing -fno-common -pipe -g
			
JASMIN        ?= jasminc
JFLAGS        ?= -nowarning ${JADDFLAGS}
JPP           ?= ../scripts/jpp
PREPROCESSOR  ?= ../scripts/preprocessor

# ------------------------------------------------------------------------------
T_LIST = $(shell seq 1 1 50)

# ------------------------------------------------------------------------------
TESTS  := $(addprefix bin/test_memcmp_,  $(T_LIST))
OUT    := $(addsuffix .out, $(TESTS))

GET_INLEN   = $(word 1, $(subst _, ,$*))

# ------------------------------------------------------------------------------
default: $(TESTS)

run: $(OUT)

# ------------------------------------------------------------------------------
.PRECIOUS: bin/test_memcmp_%.jpp
bin/test_memcmp_%.jpp:
	$(JPP) -I Sphincs:../../ -in test_memcmp.jazz -out $@
	$(PREPROCESSOR) --input_file $@ --output_file $@ --task "fn:memcmp_jazz p:INLEN:$(GET_INLEN)"
	
.PRECIOUS: bin/test_memcmp_%.s
bin/test_memcmp_%.s: bin/test_memcmp_%.jpp
	$(JASMIN) $< -o $@

$(TESTS):
bin/test_memcmp_%: bin/test_memcmp_%.s | bin/
	$(CC) $(CFLAGS) -o $@ -DINLEN=$(GET_INLEN) -I../common test_memcmp.c $<

bin/test_memcmp_%.out: bin/test_memcmp_%
	@./$<

bin/:
	mkdir -p bin/

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/
	