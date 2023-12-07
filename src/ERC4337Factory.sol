// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {LibClone} from "solady/src/utils/LibClone.sol";
import {ERC4337Account} from "./ERC4337Account.sol";

/// @notice Update version of Solady simple ERC4337 account factory implementation.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC4337Factory.sol)
/// @author Wilson Cusack
contract ERC4337Factory {
    /// @dev Address of the ERC4337 implementation.
    address public immutable implementation;

    constructor(address erc4337) payable {
        implementation = erc4337;
    }

    /// @dev Deploys an ERC4337 account with `salt` and returns its deterministic address.
    function deployDeterministic(bytes[] calldata owners, bytes32 salt)
        public
        payable
        virtual
        returns (address account)
    {
        account = LibClone.deployDeterministicERC1967(msg.value, implementation, keccak256(abi.encode(owners, salt)));
        ERC4337Account(payable(account)).initialize(owners);
    }

    /// @dev Returns the initialization code hash of the ERC4337 account (a minimal ERC1967 proxy).
    /// Used for mining vanity addresses with create2crunch.
    function initCodeHash() public view virtual returns (bytes32 result) {
        result = LibClone.initCodeHashERC1967(implementation);
    }

    function predictDeterministicAddress(bytes[] calldata owners, bytes32 salt)
        external
        view
        returns (address predicted)
    {
        predicted =
            LibClone.predictDeterministicAddress(initCodeHash(), keccak256(abi.encode(owners, salt)), address(this));
    }
}
