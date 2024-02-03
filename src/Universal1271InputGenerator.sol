// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

interface IERC1271Wallet {
    function replaySafeHash(bytes32 hash) external view returns (bytes32);
}

contract Universal1271InputGenerator {
    constructor(address _account, bytes memory _encodedData) {
        bytes32 replaySafeHash = universal1271Input(_account, _encodedData);
        assembly {
            mstore(0x80, replaySafeHash)
            return(0x80, 0x20)
        }
    }

    function universal1271Input(
        address account,
        bytes memory encodedData
    ) public returns (bytes32) {
        bytes memory contractCode = address(account).code;

        if (contractCode.length > 0) {
            return IERC1271Wallet(account).replaySafeHash(bytes32(encodedData));
        }

        address accountFactory;
        bytes32 originalHash;
        bytes memory factoryCalldata;
        (accountFactory, originalHash, factoryCalldata) = abi.decode(
            encodedData,
            (address, bytes32, bytes)
        );

        (bool success, ) = accountFactory.call(factoryCalldata);
        require(success, "Universal1271InputGenerator: deployment");
        return IERC1271Wallet(account).replaySafeHash(originalHash);
    }
}
