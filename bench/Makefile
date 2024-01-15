# -*- Makefile -*-

AS           ?= as
CC           ?= clang
CFLAGS       ?= -w # Wall -Wno-unused-function -march=native -O3 -fomit-frame-pointer -fwrapv -fPIC -fPIE
# Suppress all compiler warnings for now

# JASMIN       ?= jasminc    # FIXME: TODO: This assumes jasmin was already compiled to assembly
# JFLAGS       ?= -nowarning # FIXME: TODO: This assumes jasmin was already compiled to assembly
JPP          ?= ../ref-jasmin/test/scripts/jpp          # FIXME: 
PREPROCESSOR ?= ../ref-jasmin/test/scripts/preprocessor # FIXME: 

# ------------------------------------------------------------------------------

IMPL_LIST     := ref-jasmin # avx2_jasmin
HASH_LIST     := shake
PARAMS_LIST   := 128f 128s 192f 192s 256f 256s
THASH_LIST    := simple robust

BENCH_LIST := $(foreach I,$(IMPL_LIST),$(foreach H,$(HASH_LIST),$(foreach P,$(PARAMS_LIST),$(foreach T,$(THASH_LIST),$(I)_$(H)_$(P)_$(T)))))
OUT        := $(addsuffix .out, $(BENCH_LIST))

GET_IMPL     = $(word 1, $(subst _, ,$*))
GET_HASH     = $(word 2, $(subst _, ,$*))
GET_PARAM    = $(word 3, $(subst _, ,$*))
GET_THASH    = $(word 4, $(subst _, ,$*))

BENCHS      := $(addprefix bin/bench_sign_, $(BENCH_LIST))
OUT         := $(addsuffix .out, $(BENCHS))

BENCH_FILES   = alignedcalloc.c bench.c benchrandombytes.c cpucycles.c increment.c printbench.c stability.c
INCLUDE_API   = ../$(GET_IMPL)/include/api.h
RANDOM_BYTES  = ../ref-jasmin/test/common/randombytes.h ../ref-jasmin/test/common/notrandombytes.c 
IDIRS         = -I../$(GET_IMPL)/include -I../$(GET_IMPL)/test/common -I../$(GET_IMPL)/params -I../$(GET_IMPL)

# ------------------------------------------------------------------------------
default: $(BENCHS)
run: $(OUT)
# ------------------------------------------------------------------------------

.PRECIOUS:  bin/bench_sign_%.s
bin/bench_sign_%.s: bin/
	cp ../$(GET_IMPL)/test/sign/bin/test_sign_$(GET_HASH)_$(GET_PARAM)_$(GET_THASH).s \
	$</bench_sign_$(GET_IMPL)_$(GET_HASH)_$(GET_PARAM)_$(GET_THASH).s

$(BENCH_LIST):
bin/bench_sign_%: bin/bench_sign_%.s | bin/
	$(CC) $(CFLAGS) $(BENCH_FILES) $(IDIRS) $(INCLUDE_API) $(RANDOM_BYTES) \
	$< -o $@ \
	-DPARAMS=sphincs-$(GET_HASH)-$(GET_PARAM)

# ------------------------------------------------------------------------------

bin/bench_sign_%.out: bin/bench_sign_%
	@./$<

bin/:
	mkdir -p bin/

.PHONY: clean
clean:
	rm -fr bin/

debug:
	@echo $(BENCH_LIST)

debug_out:
	@echo $(OUT)
