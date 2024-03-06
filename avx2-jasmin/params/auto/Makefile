AUTO     := $(abspath $(dir $(filter %Makefile,$(MAKEFILE_LIST))))
PARAMS   := $(abspath $(AUTO)/..)
PARAMS_C := $(shell find $(PARAMS) -name "params-*.h")
PARAMS_J := $(patsubst %.h,%.jinc, $(PARAMS_C))

default: $(PARAMS_J)
$(PARAMS_J):
%.jinc: %.h
	echo "#include \"$<\"" > $(AUTO)/params.h
	$(CC) -Wall -Werror -o $(AUTO)/params $(AUTO)/params.c
	$(AUTO)/params > $@

.PHONY: clean distclean
clean:
	rm -f $(AUTO)/params $(AUTO)/params.h

distclean: clean
	rm -f $(PARAMS_J)
