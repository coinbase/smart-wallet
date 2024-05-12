// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "forge-std/Test.sol";

import {CoinbaseSmartWallet} from "../../src/CoinbaseSmartWallet.sol";
import {ERC1271} from "../../src/ERC1271.sol";

contract ERC1271Test is Test {
    ERC1271 private sut;

    function setUp() public {
        sut = new CoinbaseSmartWallet({keyStore_: makeAddr("KeyStore"), stateVerifier_: makeAddr("StateVerifier")});
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                             TESTS                                              //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @custom:test-section isValidSignature

    function test_isValidSignature_returns() external {}

    /// @custom:test-section eip712Domain

    function test_eip712Domain_returnsTheEip712DomainInformation() external {
        (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        ) = sut.eip712Domain();

        assertEq(fields, hex"0f");
        assertEq(keccak256(bytes(name)), keccak256("Coinbase Smart Wallet"));
        assertEq(keccak256(bytes(version)), keccak256("1"));
        assertEq(chainId, block.chainid);
        assertEq(verifyingContract, address(sut));
        assertEq(salt, bytes32(0));
        assertEq(abi.encode(extensions), abi.encode(new uint256[](0)));
    }

    /// @custom:test-section domainSeparator

    function test_domainSeparator_returnsTheDomainSeparator() external {
        (, string memory name, string memory version, uint256 chainId, address verifyingContract,,) = sut.eip712Domain();

        bytes32 expected = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );
        assertEq(expected, sut.domainSeparator());
    }

    /// @custom:test-section replaySafeHash

    function test_replaySafeHash_returnsAnEip712HashOfTheGivenHash(uint256 privateKey, bytes32 h) external {
        // Setup test:
        // 1. Set the `.message.hash` key to `h` in "test/ERC1271/ERC712.json".
        // 2. Ensure `privateKey` is a valid private key.
        // 3. Create a wallet from the `privateKey`.
        Vm.Wallet memory wallet;
        {
            vm.writeJson({json: vm.toString(h), path: "test/ERC1271/ERC712.json", valueKey: ".message.hash"});

            privateKey = bound(privateKey, 1, type(uint248).max);
            wallet = vm.createWallet(privateKey, "Wallet");
        }

        bytes32 replaySafeHash = sut.replaySafeHash(h);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign({wallet: wallet, digest: replaySafeHash});

        string[] memory inputs = new string[](8);
        inputs[0] = "cast";
        inputs[1] = "wallet";
        inputs[2] = "sign";
        inputs[3] = "--data";
        inputs[4] = "--from-file";
        inputs[5] = "test/ERC1271/ERC712.json";
        inputs[6] = "--private-key";
        inputs[7] = vm.toString(bytes32(privateKey));

        bytes memory expectedSignature = vm.ffi(inputs);
        bytes memory signature = abi.encodePacked(r, s, v);

        assertEq(signature, expectedSignature);
    }
}
