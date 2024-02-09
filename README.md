## Overview

ERC-4337 smart account, featuring 
- Multiple owners 
  - secp256r1 public key owners
  - Ethereum address owners
- WebAuthn user operation authentication
- Chain agnostic validation for certain account-altering operations, allowing users to sign once and update on many chains. 

The code started from Solady's [ERC4337](https://github.com/Vectorized/solady/blob/main/src/accounts/ERC4337.sol) implementation and was also influenced by [DaimoAccount](https://github.com/daimo-eth/daimo/blob/master/packages/contract/src/DaimoAccount.sol) and [LightAccount](https://github.com/alchemyplatform/light-account).

For secp256r1 signature validation, we attempt to use the [RIP-7212](https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md) precompile (0x100) and fallback to FreshCryptoLib's [ecdsa_verify](https://github.com/rdubois-crypto/FreshCryptoLib/blob/master/solidity/src/FCL_ecdsa.sol#L40).

The WebAuthn implementation builds on [Daimo's](https://github.com/daimo-eth/p256-verifier/blob/master/src/WebAuthn.sol) and is optimized for calldata size. 

## Permissions
Overview of who should be able to call non-view functions. 
- Only owner or self
  - MultiOwnable.addOwnerAddress
  - MultiOwnable.addOwnerPublicKey
  - MultiOwnable.AddOwnerAddressAtIndex
  - MultiOwnable.addOwnerPublicKeyAtIndex
  - MultiOwnable.removeOwnerAtIndex
  - UUPSUpgradable.upgradeToAndCall
- Only EntryPoint, owner, or self 
  - ERC4337Account.execute
  - ERC4337Account.executeBatch
- Only EntryPoint
  - ERC4337Account.executeWithoutChainIdValidation
  - validateUserOp
