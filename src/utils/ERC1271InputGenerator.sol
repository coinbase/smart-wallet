// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {CoinbaseSmartWallet} from "../CoinbaseSmartWallet.sol";

/// @title ERC1271 Input Generator
///
/// @notice Helper contract for generating an ERC-1271 input hash to sign for deployed and undeployed
///         CoinbaseSmartWallet. May be useful for generating ERC-6492 compliant signatures.
///         Inspired by Ambire's DeploylessUniversalSigValidator
///         https://github.com/AmbireTech/signature-validator/blob/d5f84f5fc00bfdf79b80205b983a8258b6d1b3ea/contracts/DeploylessUniversalSigValidator.sol.
///
/// @dev This contract is not meant to ever actually be deployed, only mock deployed and used via a static eth_call.
///
/// @author Coinbase (https://github.com/coinbase/smart-wallet)
contract ERC1271InputGenerator {
    /// @notice Thrown when call to `accountFactory` with `factoryCalldata` fails.
    error AccountDeploymentFailed();

    /// @notice Thrown when the address returned from call to `accountFactory` does not
    ///         match passed account
    ///
    /// @param account  The passed account
    /// @param returned The returned account
    error ReturnedAddressDoesNotMatchAccount(address account, address returned);

    /// @notice Computes and returns the expected ERC-1271 replay-safe hash for a CoinbaseSmartWallet.
    ///
    /// @dev `accountFactory` can be any address if the account is already deployed.
    /// @dev `factoryCalldata` can be 0x if the account is already deployed.
    /// @dev If calling with solidity, the `replaySafeHash` will be `<returned address>.code`.
    ///
    /// @param account         The account that will receive the ERC-1271 `isValidSignature` call.
    /// @param hash            The hash the wallet was asked to sign.
    /// @param accountFactory  The factory that will be used to deploy the account (if not already deployed).
    /// @param factoryCalldata The calldata that will be used to deploy the account (if not already deployed).
    constructor(CoinbaseSmartWallet account, bytes32 hash, address accountFactory, bytes memory factoryCalldata) {
        // This allows us to get a replay-safe hash on any deployed or undeployed account
        // in a single eth_call, i.e. without deploying the contract. We do this by calling replaySafeHash on a deployed
        // account,
        // or by simulating the deployment of an undeployed account and then calling replaySafeHash on it.
        bytes32 replaySafeHash = _coinbaseSmartWallet1271Input(account, hash, accountFactory, factoryCalldata);
        assembly {
            // store replay safe hash
            mstore(0x80, replaySafeHash)
            // return replay safe hash
            return(0x80, 0x20)
        }
    }

    /// @notice Helper method to get a replay-safe hash from the given `account` by calling its `replaySafeHash()`
    ///         method.
    ///
    ///
    /// @dev Deploys the account if not already deployed before calling `replaySafeHash` on it.
    /// @dev Implements ERC-6492, see https://eips.ethereum.org/EIPS/eip-6492.
    ///
    /// @param account         The account that will receive the ERC-1271 `isValidSignature` call.
    /// @param hash            The hash the wallet was asked to sign.
    /// @param accountFactory  The factory that will be used to deploy the account (if not already deployed).
    /// @param factoryCalldata The calldata that will be used to deploy the account (if not already deployed).
    ///
    /// @return The replay-safe hash.
    function _coinbaseSmartWallet1271Input(
        CoinbaseSmartWallet account,
        bytes32 hash,
        address accountFactory,
        bytes memory factoryCalldata
    ) internal returns (bytes32) {
        // If the account is already deployed, call and return replaySafeHash.
        if (address(account).code.length > 0) {
            return account.replaySafeHash(hash);
        }

        // Deploy the account.
        (bool success, bytes memory result) = accountFactory.call(factoryCalldata);
        if (!success) {
            revert AccountDeploymentFailed();
        }

        address returnAddress = abi.decode(result, (address));
        if (returnAddress != address(account)) {
            revert ReturnedAddressDoesNotMatchAccount(address(account), returnAddress);
        }

        // Call and return replaySafeHash on the now-deployed account.
        return account.replaySafeHash(hash);
    }
}
