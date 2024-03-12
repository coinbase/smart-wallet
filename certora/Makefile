default: help

PATCH         = applyHarness.patch
MUNGED_DIR    = ./munged
CONTRACTS_DIR = ../src
file1_origin = ../src/ERC4337Account.sol
file1_munged = ./munged/ERC4337Account.sol
file1_copy = ./munged/ERC4337Account_origin.sol

help:
	@echo "usage:"
	@echo "  make clean:  remove all generated files (those ignored by git)"
	@echo "  make $(MUNGED_DIR): create $(MUNGED_DIR) directory by applying the patch file to $(CONTRACTS_DIR)"
	@echo "  make record: record a new patch file capturing the differences between $(file1_munged) and $(file1_origin)"

munge:
	mkdir -p $(MUNGED_DIR)
	cp $(file1_origin) $(file1_munged)
	cp $(file1_origin) $(file1_copy)
	patch -d $(MUNGED_DIR) < $(PATCH)
	mv $(file1_munged) $(file1_origin)

record:
	diff -uN $(file1_origin) $(file1_munged) | sed 's+\$(file1_origin)/++g' | sed 's+$(file1_munged)++g' > $(PATCH)
#	diff -uN $(file2_origin) $(file2_munged) | sed 's+\$(file2_origin)/++g' | sed 's+$(file2_munged)++g' >> $(PATCH)

revert:
	cp $(file1_origin) $(file1_munged)
	mv $(file1_copy) $(file1_origin)

clean:
	git clean -fdX
	touch $(PATCH)