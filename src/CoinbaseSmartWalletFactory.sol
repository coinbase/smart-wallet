// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {LibClone} from "solady/utils/LibClone.sol";
import {CoinbaseSmartWallet} from "./CoinbaseSmartWallet.sol";

/// @title Coinbase Smart Wallet Factory
///
/// @notice CoinbaseSmartWallet factory, based on Solady's ERC4337Factory.
///
/// @author Coinbase (https://github.com/coinbase/smart-wallet)
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC4337Factory.sol)
contract CoinbaseSmartWalletFactory {
    /// @notice Address of the ERC-4337 implementation used as implementation for new accounts.
    address public immutable implementation;

    /// @notice Thrown when trying to create a new `CoinbaseSmartWallet` account without any owner.
    error OwnerRequired();

    /// @notice Factory constructor used to initialize the implementation address to use for future
    ///         ERC-4337 account deployments.
    ///
    /// @param erc4337 The address of the ERC-4337 implementation used to deploy new cloned accounts.
    constructor(address erc4337) payable {
        implementation = erc4337;
    }

    /// @notice Deploys an ERC-4337 account and returns its deterministic address.
    ///
    /// @dev The account is deployed behind a minimal ERC1967 proxy whose implementation points to
    ///      the registered ERC-4337 `implementation`.
    /// @dev The `owners` parameter is a set of addresses and/or public keys depending on the signature
    ///      scheme used (respectively ERC-1271 or Webauthn authentication).
    ///
    /// @param owners The initial set of owners that should be able to control the account.
    /// @param nonce  The nonce of the account, allowing multiple accounts with the same set of initial
    ///               owners to exist.
    function createAccount(bytes[] calldata owners, uint256 nonce)
        public
        payable
        virtual
        returns (CoinbaseSmartWallet account)
    {
        if (owners.length == 0) {
            revert OwnerRequired();
        }

        (bool alreadyDeployed, address accountAddress) =
            LibClone.createDeterministicERC1967(msg.value, implementation, _getSalt(owners, nonce));

        account = CoinbaseSmartWallet(payable(accountAddress));

        if (alreadyDeployed == false) {
            account.initialize(owners);
        }
    }

    /// @notice Returns the deterministic address of the account created via `createAccount()`.
    ///
    /// @param owners The initial set of owners provided to `createAccount()`.
    /// @param nonce  The nonce provided to `createAccount()`.
    ///
    /// @return predicted The predicted account deployment address.
    function getAddress(bytes[] calldata owners, uint256 nonce) external view returns (address predicted) {
        predicted = LibClone.predictDeterministicAddress(initCodeHash(), _getSalt(owners, nonce), address(this));
    }

    /// @notice Returns the initialization code hash of the account (a minimal ERC1967 proxy).
    ///
    /// @return result The initialization code hash.
    function initCodeHash() public view virtual returns (bytes32 result) {
        result = LibClone.initCodeHashERC1967(implementation);
    }

    /// @notice Returns the deterministic salt for a specific set of `owners` and `nonce`.
    ///
    /// @param owners The initial set of owners provided to `createAccount()`.
    /// @param nonce  The nonce provided to `createAccount()`.
    ///
    /// @return salt The computed salt.
    function _getSalt(bytes[] calldata owners, uint256 nonce) internal pure returns (bytes32 salt) {
        salt = keccak256(abi.encode(owners, nonce));
    }
}
