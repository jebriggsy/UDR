DIRS = src app
TARGETS = all clean install

.PHONY: all
.PHONY: clean
.PHONY: test

$(TARGETS): %: $(patsubst %, %.%, $(DIRS))

$(foreach TGT, $(TARGETS), $(patsubst %, %.$(TGT), $(DIRS))):
	$(MAKE) -C $(subst ., , $@)
