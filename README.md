> [!IMPORTANT]  
> The code in this repository and its dependencies are still under audit. It is not yet recommended for production use.

# Coinbase Smart Wallet

This repository contains code for a new, [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) compliant smart contract wallet from Coinbase. 

It supports 
- Multiple owners
- Passkey owners
- Cross-chain replayability for owner updates and other actions: sign once, update everywhere. 

## Deployments

| Network   | Contract Address                        |
|-----------|-----------------------------------------|
| Base Sepolia | [0x0bA5ed008013Cc025aA8fc0A730AAda592b55402](https://sepolia.basescan.org/address/0x0bA5ed008013Cc025aA8fc0A730AAda592b55402) |


## Developing 
After cloning the repo, run the tests using Forge, from [Foundry](https://github.com/foundry-rs/foundry?tab=readme-ov-file)
```bash
forge test
```

## Influences
Much of the code in this repository started from Solady's [ERC4337](https://github.com/Vectorized/solady/blob/main/src/accounts/ERC4337.sol) implementation. We were also influenced by [DaimoAccount](https://github.com/daimo-eth/daimo/blob/master/packages/contract/src/DaimoAccount.sol), which pioneered using passkey signers on ERC-4337 accounts, and [LightAccount](https://github.com/alchemyplatform/light-account).
