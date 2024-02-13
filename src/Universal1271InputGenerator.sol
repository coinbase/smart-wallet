// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import {ERC4337Account} from "./ERC4337Account.sol";

/// @notice Helper contract to generate replay-safe hashes to sign for for ERC-1271 signature validation.
/// Inspired by Ambire's DeploylessUniversalSigValidator (https://github.com/AmbireTech/signature-validator/blob/main/contracts/DeploylessUniversalSigValidator.sol)
/// @author Lukas Rosario
contract Universal1271InputGenerator {
    constructor(ERC4337Account _account, bytes memory _encodedData) {
        // This allows us to get a replay-safe hash on any deployed or undeployed account
        // in a single eth_call. We do this by calling replaySafeHash on a deployed account,
        // or by simulating the deployment of an undeployed account and then calling replaySafeHash on it.
        bytes32 replaySafeHash = universal1271Input(_account, _encodedData);
        assembly {
            mstore(0x80, replaySafeHash)
            return(0x80, 0x20)
        }
    }

    /// @dev Returns a replay-safe hash for a given account and encoded data. For an already
    /// deployed account, encodedData should just be the hash we want a replay-safe version of.
    /// For an undeployed account, encodedData should be wrapped to include the factory address,
    /// the original hash, and the factory calldata.
    /// @param account the account to get a replay-safe hash for.
    /// @param encodedData the encoded data to use to get a replay-safe hash. For an already
    /// deployed account, this should just be the hash we want a replay-safe version of. For an
    /// undeployed account, this should be wrapped to include the factory address, the original
    /// hash, and the factory calldata, ie abi.encode(accountFactory, originalHash, factoryCalldata).
    function universal1271Input(
        ERC4337Account account,
        bytes memory encodedData
    ) public returns (bytes32) {
        bytes memory contractCode = address(account).code;

        // If the account is already deployed, call and return replaySafeHash.
        if (contractCode.length > 0) {
            return account.replaySafeHash(bytes32(encodedData));
        }

        // If the account is undeployed, deploy it and call replaySafeHash.
        address accountFactory;
        bytes32 originalHash;
        bytes memory factoryCalldata;
        // Similar to ERC-6492 signatures, wrap the factory address, the
        // original hash, and the factory calldata into encodedData
        // so we can simulate deploying the account and then calling replaySafeHash.
        (accountFactory, originalHash, factoryCalldata) = abi.decode(
            encodedData,
            (address, bytes32, bytes)
        );

        // Deploy the account.
        (bool success, ) = accountFactory.call(factoryCalldata);
        require(success, "Universal1271InputGenerator: deployment");

        // Call and return replaySafeHash on the now-deployed account.
        return account.replaySafeHash(originalHash);
    }
}
