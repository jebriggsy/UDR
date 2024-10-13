DIRS = udtproject/udt4 src
TARGETS = all clean

.PHONY: all
.PHONY: clean
.PHONY: test

export arch = AMD64

$(TARGETS): %: $(patsubst %, %.%, $(DIRS))

$(foreach TGT, $(TARGETS), $(patsubst %, %.$(TGT), $(DIRS))):
	$(MAKE) -C $(subst ., , $@)
