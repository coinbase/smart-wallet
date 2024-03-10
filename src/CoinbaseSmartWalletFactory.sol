// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {Clones} from "openzeppelin-contracts/contracts/proxy/Clones.sol";
import {CoinbaseSmartWallet} from "./CoinbaseSmartWallet.sol";

/// @title Coinbase Smart Wallet Factory
/// @notice CoinbaseSmartWallet factory, based on Solady's ERC4337Factory.
/// @author Coinbase (https://github.com/coinbase/smart-wallet)
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC4337Factory.sol)
contract CoinbaseSmartWalletFactory {
    /// @dev Address of the ERC4337 implementation.
    address public immutable implementation;

    error OwnerRequired();

    constructor(address erc4337) payable {
        implementation = erc4337;
    }

    /// @dev Deploys an ERC4337 account and returns its deterministic address.
    /// @param owners the initial set of addresses and or public keys that should be able to control the account
    /// @param nonce the nonce of the account, allowing multiple accounts with the same set of initial owners to exist
    function createAccount(bytes[] calldata owners, uint256 nonce)
        public
        payable
        virtual
        returns (CoinbaseSmartWallet account)
    {
        if (owners.length == 0) {
            revert OwnerRequired();
        }

        bytes32 salt = _getSalt(owners, nonce);
        address accountAddress = Clones.predictDeterministicAddress(implementation, salt, address(this));

        account = CoinbaseSmartWallet(payable(accountAddress));

        if (address(account).code.length > 0) {
            return account;
        }

        Clones.cloneDeterministic(implementation, salt);
        account.initialize{value: msg.value}(owners);
    }

    /// @dev Returns the deterministic address of the account created via `createAccount`.
    function getAddress(bytes[] calldata owners, uint256 nonce) external view returns (address predicted) {
        predicted = Clones.predictDeterministicAddress(implementation, _getSalt(owners, nonce), address(this));
    }

    /// @dev Returns the salt that will be used for deterministic address
    function _getSalt(bytes[] calldata owners, uint256 nonce) internal pure returns (bytes32 salt) {
        salt = keccak256(abi.encode(owners, nonce));
    }
}
