# ------------------------------------------------------------------------------
AS     ?= as
CC     ?= clang
CFLAGS ?= -O3 -Wall -Wextra -Wpedantic -Wvla -Werror -std=c99 \
          -Wundef -Wshadow -Wcast-align -Wpointer-arith -Wmissing-prototypes \
          -fstrict-aliasing -fno-common -pipe -g
      
JASMIN ?= jasminc
JFLAGS ?= -nowarning ${JADDFLAGS}
JPP    ?= ../scripts/jpp

# ------------------------------------------------------------------------------

default: bin/test_memset
run: bin/test_memset.out

# ------------------------------------------------------------------------------
.PRECIOUS: bin/test_memset.jpp
bin/test_memset.jpp: bin/
	$(JPP) -I Sphincs:../../ -in test_memset.jazz -out $@
  
.PRECIOUS: bin/test_memset.s
bin/test_memset.s: bin/test_memset.jpp
	$(JASMIN) $(JFLAGS) $< -o $@

bin/test_memset: bin/test_memset.s 
	$(CC) $(CFLAGS) -o $@ -I../common test_memset.c $<

bin/test_memset.out: bin/test_memset
	@./$<

bin/:
	mkdir -p bin/

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/
