// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
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
        address accountAddress = getAddress(owners, nonce);

        account = CoinbaseSmartWallet(payable(accountAddress));

        if (address(account).code.length > 0) {
            return account;
        }

        new ERC1967Proxy{salt: salt}(implementation, "");
        account.initialize{value: msg.value}(owners);
    }

    /// @dev Returns the deterministic address of the account created via `createAccount`.
    function getAddress(bytes[] calldata owners, uint256 nonce) public view returns (address predicted) {
        predicted = Create2.computeAddress(
            _getSalt(owners, nonce),
            keccak256(abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(implementation, "")))
        );
    }

    /// @dev Returns the salt that will be used for deterministic address
    function _getSalt(bytes[] calldata owners, uint256 nonce) internal pure returns (bytes32 salt) {
        salt = keccak256(abi.encode(owners, nonce));
    }
}
