# ------------------------------------------------------------------------------
AS     ?= as
CC     ?= clang
CFLAGS ?= -O3 -Wall -Wextra -Wpedantic -Wvla -Werror -std=c99 \
	        -Wundef -Wshadow -Wcast-align -Wpointer-arith -Wmissing-prototypes \
	        -fstrict-aliasing -fno-common -pipe -g

all: bin/test_shake256_inc
run: bin/test_shake256.out

bin/test_shake256_inc:| bin/
	$(CC) $(CFLAGS) -o $@ -I../common test_shake256_inc.c $< ../../fips202.c 

bin/test_shake256.out: bin/test_shake256_inc
	@./$<

bin/:
	mkdir -p bin/

# ------------------------------------------------------------------------------
.PHONY: clean
clean:
	rm -fr bin/