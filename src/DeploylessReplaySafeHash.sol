// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

interface IERC1271Wallet {
    function replaySafeHash(bytes32 hash) external view returns (bytes32);
}

contract DeploylessReplaySafeHash {
    struct HashWrapper {
        address accountFactory;
        bytes32 hash;
        bytes factoryCalldata;
    }

    constructor(address _account, HashWrapper memory _wrappedHash) {
        bytes32 replaySafeHash = deploylessReplaySafeHash(_account, _wrappedHash);
        assembly {
            mstore(0x80, replaySafeHash)
            return(0x80, 0x20)
        }
    }

    function deploylessReplaySafeHash(
        address account,
        HashWrapper memory wrappedHash
    ) public returns (bytes32) {
        bytes memory contractCode = address(account).code;

        if (contractCode.length > 0) {
            return IERC1271Wallet(account).replaySafeHash(wrappedHash.hash);
        }

        (bool success, ) = wrappedHash.accountFactory.call(wrappedHash.factoryCalldata);
        require(success, "DeploylessReplaySafeHash: deployment");
        return IERC1271Wallet(account).replaySafeHash(wrappedHash.hash);
    }
}
