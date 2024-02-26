// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console2} from "forge-std/Test.sol";

import "../src/ERC1271.sol";
import "../src/CoinbaseSmartWalletFactory.sol";

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
        (, string memory name, string memory version, uint256 chainId, address verifyingContract,,) =
            account.eip712Domain();
        assertEq(verifyingContract, address(account));
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
}
