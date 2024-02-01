// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

interface IERC1271Wallet {
    function replaySafeHash(bytes32 hash) external view returns (bytes32);
}

contract DeploylessReplaySafeHash {
    constructor(address _account, bytes memory _hash) {
        bytes32 replaySafeHash = deploylessReplaySafeHash(_account, _hash);
        assembly {
            mstore(0x80, replaySafeHash)
            return(0x80, 0x20)
        }
    }

    function deploylessReplaySafeHash(
        address _account,
        bytes memory _hash
    ) public returns (bytes32) {
        bytes memory contractCode = address(_account).code;

        if (contractCode.length > 0) {
            return IERC1271Wallet(_account).replaySafeHash(bytes32(_hash));
        }

        address create2Factory;
        bytes32 originalHash;
        bytes memory factoryCalldata;
        (create2Factory, originalHash, factoryCalldata) = abi.decode(
            _hash,
            (address, bytes32, bytes)
        );

        (bool success, ) = create2Factory.call(factoryCalldata);
        require(success, "DeploylessReplaySafeHash: deployment");
        return IERC1271Wallet(_account).replaySafeHash(originalHash);
    }
}
