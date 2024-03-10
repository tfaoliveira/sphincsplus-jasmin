# -*- Makefile -*-

# ------------------------------------------------------------------------------

HASH_LIST   := shake
PARAMS_LIST := 128f 128s 192f 192s 256f 256s
THASH_LIST  := simple robust 

# ------------------------------------------------------------------------------

IMPL_LIST := $(foreach H,$(HASH_LIST), \
              $(foreach P,$(PARAMS_LIST), \
                $(foreach T,$(THASH_LIST),$(H)_$(P)_$(T))))

# TODO: One spec for each implementation

# ------------------------------------------------------------------------------

EASYCRYPT = easycrypt
EC_PARAMS = -I common
EC_FILES := Notation.ec 

# ------------------------------------------------------------------------------

default: typecheck
.PHONY: clean typecheck

typecheck: $(EC_FILES)
	$(foreach dep,$^,$(EASYCRYPT) $(EC_PARAMS) $(dep);)

clean:
	rm -rf *.eco

