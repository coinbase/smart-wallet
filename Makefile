all: build-forge-patch build-solc-patch

.PHONY: build-forge-patch
build-forge-patch:
	@echo "Building forge patch..."
	@cd forge-3074-patch && \
		cargo build --bin forge --release && \
		mkdir -p ../bin && \
		cp target/release/forge ../bin/forge
	@echo "Done, patched forge binary is located at `bin/forge` relative to the project root"

.PHONY: build-solc-patch
build-solc-patch:
	@echo "Building solc patch..."
	@cd solidity && \
		mkdir -p build && \
		cd build && \
		cmake .. -DSTRICT_Z3_VERSION=OFF && \
		make && \
		mkdir -p ../../bin && \
		cp solc/solc ../../bin/solc
	@echo "Done, patched solc binary is located at `bin/solc` relative to the project root"

.PHONY: install-huff
install-huff:
	@echo "Installing huff..."
	@curl -L get.huff.sh | bash
	@huffup
	@echo "Done!"

.PHONY: test
test:
	@[[ ! -a ./bin/forge ]] && make build-forge-patch || true
	@./bin/forge test -vvvv --match-path test/Auth.t.sol -w

.PHONY: build
build:
	@[[ ! -a ./bin/forge ]] && make build-forge-patch || true
	@./bin/forge build

.PHONY: fmt
fmt:
	@[[ ! -a ./bin/forge ]] && make build-forge-patch || true
	@./bin/forge fmt

.PHONY: snapshot
snapshot:
	@[[ ! -a ./bin/forge ]] && make build-forge-patch || true
	@./bin/forge snapshot