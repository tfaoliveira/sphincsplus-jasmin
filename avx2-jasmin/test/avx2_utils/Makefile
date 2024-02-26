# -*- Makefile -*-

CC     ?= clang
CFLAGS ?= -Wall -Wextra -Wpedantic -Wmissing-prototypes -O3 -std=c99 -march=native -fomit-frame-pointer -flto

JASMIN ?= jasminc
JFLAGS ?= -nowarning ${JADDFLAGS}

default: bin/test_avx2_utils
run: bin/test_avx2_utils.out

bin/test_avx2_utils.s: test_avx2_utils.jazz | bin/
	$(JASMIN) $(JFLAGS) -I Sphincs:../../ $< -o $@

bin/test_avx2_utils: bin/test_avx2_utils.s
	$(CC) $(CFLAGS) -o $@ test_avx2_utils.c $< \
	-I../common/ ../common/print.c ../common/notrandombytes.c

bin/test_avx2_utils.out: bin/test_avx2_utils
	@./$<

bin/:
	mkdir -p $@

.PHONY: clean
clean:
	rm -rf bin/