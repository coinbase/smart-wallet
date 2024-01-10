// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {EIP712} from "solady/src/utils/EIP712.sol";

/// @notice ERC1271 mixin with nested EIP-712 approach, supporting multiple owners
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC1271.sol)
/// @author Wilson Cusack
abstract contract ERC1271 is EIP712 {
    bytes32 constant MESSAGE_TYPEHASH = keccak256("CoinbaseSmartAccountMessage(bytes32 message)");

    function isValidSignature(bytes32 hash, bytes calldata signature) public view virtual returns (bytes4 result) {
        if (_validateSignature(_hashTypedData(_messageHash(hash)), signature)) {
            // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
            return 0x1626ba7e;
        }

        return 0xffffffff;
    }

    /// @dev Incase a signer is on multiple accounts, we expect all messages
    /// to be wrapped in an EIP 712 hash that includes the domain hash
    /// EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)
    function replaySafeHash(bytes32 hash) public view returns (bytes32) {
        return _hashTypedData(_messageHash(hash));
    }

    function _messageHash(bytes32 message) internal view virtual returns (bytes32) {
        return keccak256(abi.encode(MESSAGE_TYPEHASH, message));
    }

    /// @dev Implement to vefify signature
    function _validateSignature(bytes32 message, bytes calldata signature) internal view virtual returns (bool);
}
