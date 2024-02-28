// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {CoinbaseSmartWallet} from "../CoinbaseSmartWallet.sol";

/// @notice Helper contract for generating an ERC-1271 input hash to sign for deployed and undeployed CoinbaseSmartWallet.
/// May be useful for generating ERC-6492 compliant signatures.
/// Inspired by Ambire's DeploylessUniversalSigValidator (https://github.com/AmbireTech/signature-validator/blob/main/contracts/DeploylessUniversalSigValidator.sol)
/// @dev This contract is not meant to ever actually be deployed, only mock deployed and used via a static eth_call
/// @author Coinbase (https://github.com/coinbase/smart-wallet)
contract ERC1271InputGenerator {
    /// @notice Computes and returns the expected ERC-1271 input hash for a CoinbaseSmartWallet
    ///
    /// @dev If calling with solidity, replaySafeHash will be `<returned address>.code`
    ///
    /// @param account the account that will receive the ERC-1271 isValidSignature call
    /// @param hash the hash the wallet was asked to sign
    /// @param accountFactory the factory that will be used to deploy the account if it is not already deployed
    /// can be any address if account is deployed
    /// @param factoryCalldata the calldata that will be used to deploy the account if it is not already deployed
    /// can be 0x if account is deployed
    constructor(CoinbaseSmartWallet account, bytes32 hash, address accountFactory, bytes memory factoryCalldata) {
        // This allows us to get a replay-safe hash on any deployed or undeployed account
        // in a single eth_call, i.e. without deploying the contract. We do this by calling replaySafeHash on a deployed account,
        // or by simulating the deployment of an undeployed account and then calling replaySafeHash on it.
        bytes32 replaySafeHash = _coinbaseSmartWallet1271Input(account, hash, accountFactory, factoryCalldata);
        assembly {
            // store replay safe hash
            mstore(0x80, replaySafeHash)
            // return replay safe hash
            return(0x80, 0x20)
        }
    }

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
        (bool success,) = accountFactory.call(factoryCalldata);
        require(success, "CoinbaseSmartWallet1271InputGenerator: deployment");

        // Call and return replaySafeHash on the now-deployed account.
        return account.replaySafeHash(hash);
    }
}
