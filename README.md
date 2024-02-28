> [!IMPORTANT]  
> The code in this repository and its dependencies are still under audit. It is not yet recommended for production use.

# Smart Wallet

This repository contains code for a new, [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) compliant smart contract wallet from Coinbase. 

It supports 
- Multiple owners
- Passkey owners and Ethereum address owners
- Cross-chain replayability for owner updates and other actions: sign once, update everywhere. 

## Multiple Owners
Our smart wallet supports up to 256 concurrent owners. Each owner can transact independently, without sign off from any other owner. 

Owners are identified as `bytes` to allow both Ethereum address owners and passkey (Secp256r1) public key owners. 

## Passkey owners and Ethereum address owners
Ethereum address owners can call directly to the smart contract wallet to transact and also transact via user operations. 

In the ERC-4337 context, we expect `UserOperation.signature` to be the ABI encoding of a `SignatureWrapper` struct 
```solidity
struct SignatureWrapper {
    uint8 ownerIndex;
    bytes signatureData;
}
```

Owner index identifies the owner who signed the user operation. This must be passed because secp256r1 verifiers require the public key as an input. This differs from `ecrecover`, which returns the signer address.

We pass an `ownerIndex` rather than the public key itself to optimize for calldata, which is currently the main cost driver on Ethereum layer 2 rollups, like Base. 

If the signer is an Ethereum address, `signatureData` should be the packed ABI encoding of the `r`, `s`, and `v` signature values. 

If the signer is a secp256r1 public key, `signatureData` should be the the ABI encoding of a [`WebAuthnAuth`](https://github.com/base-org/webauthn-sol/blob/main/src/WebAuthn.sol#L15-L34) struct. See [webauthn-sol](https://github.com/base-org/webauthn-sol) for more details. 

## Cross-chain replayability 
If a user changes an owner or upgrade their smart wallet, they likely want this change applied to all instances of your smart wallet, across various chains. Our smart wallet allows users to sign a single user operation which can be permissionlessly replayed on other chains. 

There is a special function, `executeWithoutChainIdValidation`, which can only be called by the `EntryPoint` contract (v0.6). 

In `validateUserOp` we check if this function is being called. If it is, we recompute the userOpHash (which will be used for signature validation) to exclude the chain ID. 

Code excerpt from validateUserOp
```solidity
// 0xbf6ba1fc = bytes4(keccak256("executeWithoutChainIdValidation(bytes)"))
if (userOp.callData.length >= 4 && bytes4(userOp.callData[0:4]) == 0xbf6ba1fc) {
    userOpHash = getUserOpHashWithoutChainId(userOp);
    if (key != REPLAYABLE_NONCE_KEY) {
        revert InvalidNonceKey(key);
    }
} else {
    if (key == REPLAYABLE_NONCE_KEY) {
        revert InvalidNonceKey(key);
    }
}
```

To help keep these cross-chain replayable user operations organized and sequential, we reserve a specific nonce key for only these user operations.

`executeWithoutChainIdValidation` can only be used for calls to self and can only call a whitelisted set of functions. 

```solidity
function executeWithoutChainIdValidation(bytes calldata data) public payable virtual onlyEntryPoint {
    bytes4 selector = bytes4(data[0:4]);
    if (!canSkipChainIdValidation(selector)) {
        revert SelectorNotAllowed(selector);
    }

    _call(address(this), 0, data);
}
```

`canSkipChainIdValidation` can be used to check which functions can be called.

Today, allowed are 
- MultiOwnable.addOwnerPublicKey
- MultiOwnable.addOwnerAddress
- MultiOwnable.addOwnerAddressAtIndex
- MultiOwnable.addOwnerPublicKeyAtIndex
- MultiOwnable.removeOwnerAtIndex
- UUPSUpgradeable.upgradeToAndCall

## Deployments

| Network   | CoinbaseSmartWalletFacotry Address                        |
|-----------|-----------------------------------------|
| Base Sepolia | [0x0bA5ed008013Cc025aA8fc0A730AAda592b55402](https://sepolia.basescan.org/address/0x0bA5ed008013Cc025aA8fc0A730AAda592b55402) |


## Developing 
After cloning the repo, run the tests using Forge, from [Foundry](https://github.com/foundry-rs/foundry?tab=readme-ov-file)
```bash
forge test
```

## Influences
Much of the code in this repository started from Solady's [ERC4337](https://github.com/Vectorized/solady/blob/main/src/accounts/ERC4337.sol) implementation. We were also influenced by [DaimoAccount](https://github.com/daimo-eth/daimo/blob/master/packages/contract/src/DaimoAccount.sol), which pioneered using passkey signers on ERC-4337 accounts, and [LightAccount](https://github.com/alchemyplatform/light-account).
