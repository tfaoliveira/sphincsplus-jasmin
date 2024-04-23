# -*- Makefile -*-

AS ?= as

CC     ?= clang
CFLAGS ?= -Wall -Wextra -Wpedantic -Wmissing-prototypes -O3 -std=c99 -march=native -fomit-frame-pointer -flto -O3

JASMIN       ?= jasminc
JFLAGS       ?= -nowarning -g ${JADDFLAGS}
JPP          ?= ../../test../../submodules/jasmin-preprocessor/jpp
PREPROCESSOR ?= ../../test../../submodules/jasmin-preprocessor/preprocessor

# ----------------------------------------------------------------------------------------------------------------------

HASH_LIST   := shake
PARAMS_LIST := 128f 192f 256f 128s 192s 256s 
THASH_LIST  := simple robust

# ----------------------------------------------------------------------------------------------------------------------

# TODO:

bin/bench_jasmin_wots_%.out: bin/bench_jasmin_wots_% csv/
	@echo "Running benchmarks: $(subst bin/bench_,, $<)"
	@./$<
	@mv *.csv csv/

bin/bench_ref_wots_%.out: bin/bench_ref_wots_% | csv/
	@echo "Running benchmarks: $(subst bin/bench_,, $<)"
	@./$<
	@mv *.csv csv/

# ----------------------------------------------------------------------------------------------------------------------

bin/:
	mkdir -p $@

csv/:
	mkdir -p $@

.PHONY: clean
clean:
	rm -rf bin/ csv/
	rm -rf *.csv # Intermediate files that were not yet moved to csv/

.PHONY: clean_csv
clean_csv:
	rm -rf *.csv csv/

.PHONY: clean_executables
clean_executables:
	find bin/ -type f -executable -delete || true
