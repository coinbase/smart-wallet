// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console2} from "forge-std/Test.sol";

import "../src/ERC1271.sol";
import "../src/ERC4337Factory.sol";

contract ERC1271Test is Test {
    ERC4337Factory factory;
    ERC4337Account account;
    bytes[] owners;

    function setUp() public {
        factory = new ERC4337Factory(address(new ERC4337Account()));
        owners.push(abi.encode(address(1)));
        owners.push(abi.encode(address(2)));
        account = ERC4337Account(payable(address(factory.createAccount(owners, 0))));
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
