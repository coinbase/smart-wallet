// SPDX-License-Identifier: MIT
// Adapted from Solady https://github.com/Vectorized/solady/blob/main/test/utils/mocks/MockERC4337.sol
pragma solidity ^0.8.4;

import {CoinbaseSmartWallet} from "../../src/CoinbaseSmartWallet.sol";

/// @dev WARNING! This mock is strictly intended for testing purposes only.
/// Do NOT copy anything here into production code unless you really know what you are doing.
contract MockCoinbaseSmartWallet is CoinbaseSmartWallet {
    constructor() {
        // allow for easier testing
        _getMultiOwnableStorage().nextOwnerIndex = 0;
    }

    function _brutalized(address a) private pure returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := or(a, shl(160, 0x0123456789abcdeffedcba98))
        }
    }

    function executeBatch(uint256 filler, Call[] calldata calls) public payable virtual onlyEntryPointOrOwner {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x40, add(mload(0x40), mod(filler, 0x40)))
        }
        for (uint256 i; i < calls.length; i++) {
            _call(calls[i].target, calls[i].value, calls[i].data);
        }
    }
}
