# Smart Wallet
 
## Branch note: Simulation bytecode for accurate Verification Gas Limit (VGL) estimation (not for merge)

- **Purpose**: Provide simulation-only wallet bytecode that mimics the onchain “valid signature” verification path, so bundlers can estimate Verification Gas Limit (VGL) accurately without manual buffers.
- **Why**: Gas estimation in simulation usually uses invalid passkey signatures against the production wallet bytecode. Invalid signatures trigger different execution paths than real valid signatures onchain (e.g., falling back to FCL instead of using RIP-7212), leading to large deviations in measured gas. This branch supplies bytecode that fakes the “valid signature” path by hard-coding a known‑valid P‑256 vector inside the verifier, ensuring simulation follows the same path as real execution and yields sufficiently accurate VGL for bundler overrides.
- **Scope**: Simulation-only. Not intended for deployment. This branch will not be merged.

### What changed (high level)
- `CoinbaseSmartWallet._isValidSignature` calls `WebAuthn.verifySim`, whose internal signature check uses a fixed valid vector to exercise the RIP-7212 precompile path when available (and FCL fallback otherwise). This produces gas that matches real executions when a valid passkey signature is used onchain.

### Build settings used for bytecode (must match deploy settings)
- Foundry profile: `deploy`
  - `optimizer = true`
  - `optimizer_runs = 999999`
  - `via_ir = true`
  - `evm_version = "prague"`
  - `solc_version = "0.8.23"`

Build and extract the deployed/runtime bytecode:

```bash
FOUNDRY_PROFILE=deploy forge build
FOUNDRY_PROFILE=deploy forge inspect src/CoinbaseSmartWallet.sol:CoinbaseSmartWallet deployedBytecode \
  > snapshots/SimulationOverrides/CoinbaseSmartWallet.runtime.hex
```

- **Output artifact location**: `snapshots/SimulationOverrides/CoinbaseSmartWallet.runtime.hex` (hex-encoded runtime bytecode, prefixed with `0x`).

### Using this in a bundler (simulation overrides)
During `eth_estimateUserOperationGas` for passkey flows:
- Override `CoinbaseSmartWallet` implementation address(es) with the bytecode from `snapshots/SimulationOverrides/CoinbaseSmartWallet.runtime.hex`.
- Provide a dummy signature so calldata and control flow match production, but let `verifySim` ensure the signature path succeeds.

### Notes
- On RIP-7212 chains, simulation follows the precompile success path. On non-7212 chains, it follows FCL. This mirrors real execution and stabilizes VGL estimation across chains.
- WebAuthn library commit pinned in this branch: `amiecorso/webauthn-sol@6ac7461cbb768d77d9798e6160cd05d70dee7586`.


# Smart Wallet

This repository contains code for a new, [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) compliant smart contract wallet from Coinbase. 

It supports 
- Multiple owners
- Passkey owners and Ethereum address owners
- Cross-chain replayability for owner updates and other actions: sign once, update everywhere. 

## Multiple Owners
Our smart wallet supports a practically unlimited number of concurrent owners (max 2^256). Each owner can transact independently, without sign off from any other owner. 

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

> [!WARNING]
> ## EIP-7702 delegation safety
> Do **not** directly delegate to a Coinbase Smart Wallet **implementation** contract via EIP-7702. Delegating directly to an implementation can create a security vulnerability.
> 
> Instead:
> - Use the `EIP7702Proxy` pattern: [base/eip-7702-proxy](https://github.com/base/eip-7702-proxy)
> - See Coinbase Developer Platform docs for further guidance and an example of performing a safe EIP-7702 upgrade: [EIP-7702 FAQs – safe upgrade](https://docs.cdp.coinbase.com/paymaster/need-to-knows/eip-7702-faqs#how-do-i-upgrade-my-wallet-to-7702)

## Deployments
Factory and implementation are deployed via [Safe Singleton Factory](https://github.com/safe-global/safe-singleton-factory), which today will give the same address across 248 chains. See "Deploying" below for instructions on how to deploy to new chains. 
| Version   | Factory Address                        |
|-----------|-----------------------------------------|
| 1.1 | [0xBA5ED110eFDBa3D005bfC882d75358ACBbB85842](https://basescan.org/address/0xBA5ED110eFDBa3D005bfC882d75358ACBbB85842) |
| 1 | [0x0BA5ED0c6AA8c49038F819E587E2633c4A9F428a](https://basescan.org/address/0x0BA5ED0c6AA8c49038F819E587E2633c4A9F428a) |


## Developing 
After cloning the repo, run the tests using Forge, from [Foundry](https://github.com/foundry-rs/foundry?tab=readme-ov-file)
```bash
forge test
```

## Deploying
To deploy on a new chain, in your `.env` set
```bash
#`cast wallet` name
ACCOUNT=
# Node RPC URL
RPC_URL=
# Optional Etherscan API key for contract verification
ETHERSCAN_API_KEY=
```
See [here](https://book.getfoundry.sh/reference/cast/cast-wallet-import) for more details on `cast wallet`.

Then run 
```
make deploy
```

## Influences
Much of the code in this repository started from Solady's [ERC4337](https://github.com/Vectorized/solady/blob/main/src/accounts/ERC4337.sol) implementation. We were also influenced by [DaimoAccount](https://github.com/daimo-eth/daimo/blob/master/packages/contract/src/DaimoAccount.sol), which pioneered using passkey signers on ERC-4337 accounts, and [LightAccount](https://github.com/alchemyplatform/light-account).
