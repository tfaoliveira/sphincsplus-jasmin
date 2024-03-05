# -*- Makefile -*-

AS ?= as

CC     ?= clang
CFLAGS ?= -Wall -Wextra -Wpedantic -Wmissing-prototypes -O3 -std=c99 -march=native -fomit-frame-pointer -flto -O3

JASMIN       ?= jasminc
JFLAGS       ?= -nowarning -g ${JADDFLAGS}
JPP          ?= ../../test/scripts/jpp
PREPROCESSOR ?= ../../test/scripts/preprocessor

HASH_LIST   := shake
PARAMS_LIST := 128f 192f 256f # 128s 192s 256s 
THASH_LIST  := simple robust

TLIST := $(foreach H,$(HASH_LIST), $(foreach P,$(PARAMS_LIST), $(foreach T,$(THASH_LIST), $(H)_$(P)_$(T))))

JASMIN_TESTS := $(addprefix bin/bench_jasmin_sign_, $(TLIST))
OUT_JASMIN   := $(addsuffix .out, $(JASMIN_TESTS))

REF_TESTS    := $(addprefix bin/bench_ref_sign_, $(TLIST))
OUT_REF      := $(addsuffix .out, $(REF_TESTS))

GET_HASH    = $(word 1, $(subst _, ,$*))
GET_PARAM   = $(word 2, $(subst _, ,$*))
GET_THASH   = $(word 3, $(subst _, ,$*))

JPP_FILES := $(addsuffix .jpp, $(JASMIN_TESTS))
ASM_FILES := $(JPP_FILES:.jpp=.s)

JASMIN_OBJ_FILES := $(ASM_FILES:.s=.o)
REF_OBJ_FILES    := $(addsuffix .o, $(REF_TESTS))

SOURCES = ../../hash_$(GET_HASH).c ../../merkle.c ../../wots.c ../../wotsx1.c ../../fips202.c ../../utils.c \
		  ../../address.c ../../thash_$(GET_HASH)_$(GET_THASH).c ../../utilsx1.c ../../fors.c ../../sign.c 

all:     $(JASMIN_TESTS) $(REF_TESTS) $(JASMIN_OBJ_FILES) $(REF_OBJ_FILES)
default: $(JASMIN_TESTS)

run_ref:    $(OUT_REF)
run_jasmin: $(OUT_JASMIN)
run:        $(OUT_JASMIN) $(OUT_REF)

jpp_files: $(JPP_FILES)
asm_files: $(ASM_FILES)

obj_files:  $(JASMIN_OBJ_FILES) $(REF_OBJ_FILES)
obj_ref:    $(REF_OBJ_FILES)
obj_jasmin: $(JASMIN_OBJ_FILES)

ref:    $(REF_TESTS)
jasmin: $(JASMIN_TESTS)

$(JPP_FILES):
.PRECIOUS: bin/bench_jasmin_sign_%.jpp
bin/bench_jasmin_sign_%.jpp: | bin/
	cp ../../test/sign/test_sign.jazz $@
	sed -i "1 i\from Sphincs require \"params/params-sphincs-$(GET_HASH)-$(GET_PARAM).jinc\"" $@
	sed -i "2 i\from Sphincs require \"thash/thash_$(GET_HASH)_$(GET_THASH).jtmpl\"" $@
	$(JPP) -I Sphincs:../../ -in $@ -out $@
	$(PREPROCESSOR) --input_file $@ --output_file $@

$(ASM_FILES):
.PRECIOUS: bin/bench_jasmin_sign_%.s
bin/bench_jasmin_sign_%.s: bin/bench_jasmin_sign_%.jpp
	$(JASMIN) $(JFLAGS) $< -o $@

$(JASMIN_TESTS):
bin/bench_jasmin_sign_%: bin/bench_jasmin_sign_%.s csv/
	$(CC) $(CFLAGS) -o $@ \
	-DPARAMS=sphincs-$(GET_HASH)-$(GET_PARAM) -DTHASH=$(GET_THASH) -DPARAM=$(GET_PARAM) -DBENCH_JASMIN \
	-I../common -I../../ -I../../params bench_sign.c $< \
	../common/print.c ../common/macros.h ../common/notrandombytes.c ../../api.h

$(REF_OBJ_FILES):
.PRECIOUS: bin/bench_ref_sign_%.o
bin/bench_ref_sign_%.o:
	$(CC) $(CFLAGS) -c -DPARAMS=sphincs-$(GET_HASH)-$(GET_PARAM) -DPARAM=$(GET_PARAM) \
	-I../common ../../sign.c -o $@ 

$(JASMIN_OBJ_FILES):
.PRECIOUS: bin/bench_jasmin_sign_%.o
bin/bench_jasmin_sign_%.o: bin/bench_jasmin_sign_%.s
	$(AS) $(ASFLAGS) $< -o $@

$(REF_TESTS):
bin/bench_ref_sign_%: csv/
	$(CC) $(CFLAGS) -o $@ bench_sign.c -DPARAMS=sphincs-$(GET_HASH)-$(GET_PARAM) -DTHASH=$(GET_THASH) -DPARAM=$(GET_PARAM) \
	-I../common -I../../ -I../../params \
	../../api.h ../common/macros.h $(SOURCES) ../common/notrandombytes.c ../../wrappers.c

bin/bench_jasmin_sign_%.out: bin/bench_jasmin_sign_% csv/
	@echo "Running benchmarks: $(subst bin/bench_,, $<)"
	@./$<
	@mv *.csv csv/

bin/bench_ref_sign_%.out: bin/bench_ref_sign_% | csv/
	@echo "Running benchmarks: $(subst bin/bench_,, $<)"
	@./$<
	@mv *.csv csv/

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
