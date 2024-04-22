// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console2} from "forge-std/Test.sol";

import "../src/CoinbaseSmartWalletFactory.sol";
import "../src/ERC1271.sol";

import {MockCoinbaseSmartWallet} from "./mocks/MockCoinbaseSmartWallet.sol";

contract ERC1271Test is Test {
    CoinbaseSmartWalletFactory factory;
    CoinbaseSmartWallet account;
    bytes[] owners;

    function setUp() public {
        factory = new CoinbaseSmartWalletFactory(address(new CoinbaseSmartWallet()));
        owners.push(abi.encode(address(1)));
        owners.push(abi.encode(address(2)));
        account = factory.createAccount(owners, 0);
    }

    function test_returnsExpectedDomainHashWhenProxy() public {
        (
            ,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        ) = account.eip712Domain();
        assertEq(verifyingContract, address(account));
        assertEq(abi.encode(extensions), abi.encode(new uint256[](0)));
        assertEq(salt, bytes32(0));
        bytes32 expected = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );
        assertEq(expected, account.domainSeparator());
    }

    /// @dev a test for a static output, for reference with a javascript test out of this repo
    function test_static() public {
        vm.chainId(84532);

        owners.push(
            hex"66efa90a7c6a9fe2f4472dc80307116577be940f06f4b81b3cce9207d0d35ebdd420af05337a40c253b6a37144c30ba22bbd54c71af9e4457774d790b34c8227"
        );
        CoinbaseSmartWallet a = new MockCoinbaseSmartWallet();
        vm.etch(0x2Af621c1B01466256393EBA6BF183Ac2962fd98C, address(a).code);
        a.initialize(owners);
        bytes32 expected = 0x1b03b7e3bddbb2f9b5080f154cf33fcbed9b9cd42c98409fb0730369426a0a69;
        bytes32 actual = CoinbaseSmartWallet(payable(0x2Af621c1B01466256393EBA6BF183Ac2962fd98C)).replaySafeHash(
            0x9ef3f7124243b092c883252302a74d4ed968efc9f612396f1a82bbeef8931328
        );
        assertEq(expected, actual);
    }
}
