# -*- Makefile -*-

AUTO      := $(abspath $(dir $(filter %Makefile,$(MAKEFILE_LIST))))
PARAMS    := $(abspath $(AUTO)/..)
PARAMS_C  := $(shell find $(PARAMS) -name "params-*.h")
PARAMS_EC := $(patsubst %.h,%.ec, $(PARAMS_C))

default: $(PARAMS_EC)

$(PARAMS_EC):
%.ec: %.h
	echo "#include \"$<\"" > $(AUTO)/params.h
	$(CC) -Wall -Werror -o $(AUTO)/params $(AUTO)/params.c
	$(AUTO)/params > $@

.PHONY: clean distclean
clean:
	rm -f $(AUTO)/params $(AUTO)/params.h

distclean: clean
	rm -f $(PARAMS_EC)
