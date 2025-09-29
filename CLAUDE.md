# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is Coinbase's ERC-4337 compliant smart contract wallet implementation, featuring:
- Multiple owner support (both Ethereum addresses and passkey public keys)
- Cross-chain replayable transactions
- WebAuthn/passkey integration for authentication
- Factory pattern for deterministic deployments

## Key Commands

### Testing
```bash
forge test                    # Run all tests
forge test --match-test <name>  # Run specific test
forge test -vvv              # Run with verbose output
```

### Building & Linting  
```bash
forge build                  # Compile contracts
forge fmt                    # Format Solidity code
```

### Deployment
```bash
make deploy                  # Deploy factory and implementation (requires .env setup)
```

## Core Architecture

### Main Contracts (src/)
- **CoinbaseSmartWallet.sol** - The main wallet implementation inheriting from MultiOwnable, ERC1271, UUPSUpgradeable
- **CoinbaseSmartWalletFactory.sol** - Factory for deterministic wallet creation using LibClone
- **MultiOwnable.sol** - Multi-owner auth system supporting both addresses and public keys
- **ERC1271.sol** - Signature validation with anti-replay protection

### Key Design Patterns
1. **Multi-Owner Architecture**: Owners stored as `bytes` to support both Ethereum addresses and secp256r1 public keys
2. **Cross-Chain Replayability**: Special `executeWithoutChainIdValidation()` function for cross-chain owner updates
3. **Signature Wrapping**: Uses `SignatureWrapper` struct with `ownerIndex` to identify signers
4. **Factory Pattern**: Deterministic deployment via Safe Singleton Factory

### Dependencies
- **account-abstraction**: ERC-4337 interfaces and EntryPoint integration  
- **solady**: Core utilities (LibClone, UUPSUpgradeable, SignatureCheckerLib, Receiver)
- **webauthn-sol**: WebAuthn signature verification for passkeys
- **p256-verifier**: secp256r1 signature verification
- **openzeppelin-contracts**: Standard implementations

### Test Structure
- **test/CoinbaseSmartWallet/**: Core wallet functionality tests
- **test/MultiOwnable/**: Multi-owner system tests  
- **test/mocks/**: Mock contracts for testing
- **SmartWalletTestBase.sol**: Shared test utilities and setup

### Cross-Chain Features
- Uses `REPLAYABLE_NONCE_KEY` for sequential cross-chain operations
- Whitelisted functions: owner management and upgrades via `canSkipChainIdValidation()`
- Chain ID excluded from signature validation for replayable operations

### Development Notes
- Uses Foundry for build/test (foundry.toml config)
- Solidity 0.8.23 with optimizer enabled for deployment profile
- Safe Singleton Factory for consistent cross-chain addresses
- Factory deployed at: `0xBA5ED110eFDBa3D005bfC882d75358ACBbB85842`