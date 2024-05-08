// SPDX-License-Identifier: MIT
// Adapted from Solady https://github.com/Vectorized/solady/blob/main/test/utils/mocks/MockERC4337.sol
pragma solidity ^0.8.4;

import {CoinbaseSmartWallet} from "../../src/CoinbaseSmartWallet.sol";

/// @dev WARNING! This mock is strictly intended for testing purposes only.
/// Do NOT copy anything here into production code unless you really know what you are doing.
contract MockCoinbaseSmartWallet is CoinbaseSmartWallet {
    constructor(address keyStore, address stateVerifier) CoinbaseSmartWallet(keyStore, stateVerifier) {
        // allow for easier testing
        _getMultiOwnableStorage().ownerCount = 0;
    }
}
