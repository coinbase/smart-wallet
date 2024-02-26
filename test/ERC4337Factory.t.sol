// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test, console2} from "forge-std/Test.sol";
import {ERC4337Account} from "../src/ERC4337Account.sol";
import {ERC4337Factory} from "../src/ERC4337Factory.sol";

contract ERC4337FactoryTest is Test {
    ERC4337Factory factory;
    ERC4337Account erc4337;
    bytes[] owners;

    function setUp() public {
        erc4337 = new ERC4337Account();
        factory = new ERC4337Factory(address(erc4337));
        owners.push(abi.encode(address(1)));
        owners.push(abi.encode(address(2)));
    }

    function test_createAccountSetsOwnersCorrectly() public {
        address expectedAddress = factory.getAddress(owners, 0);
        vm.expectCall(expectedAddress, abi.encodeCall(ERC4337Account.initialize, (owners)));
        address a = factory.createAccount{value: 1e18}(owners, 0);
        assert(ERC4337Account(payable(a)).isOwnerAddress(address(1)));
        assert(ERC4337Account(payable(a)).isOwnerAddress(address(2)));
    }

    function test_revertsIfNoOwners() public {
        owners.pop();
        owners.pop();
        vm.expectRevert(ERC4337Factory.OwnerRequired.selector);
        factory.createAccount{value: 1e18}(owners, 0);
    }

    function test_createAccountDeploysToPredeterminedAddress() public {
        address p = factory.getAddress(owners, 0);
        address a = factory.createAccount{value: 1e18}(owners, 0);
        assertEq(a, p);
    }

    function test_CreateAccount_ReturnsPredeterminedAddress_WhenAccountAlreadyExists() public {
        address p = factory.getAddress(owners, 0);
        address a = factory.createAccount{value: 1e18}(owners, 0);
        address b = factory.createAccount{value: 1e18}(owners, 0);
        assertEq(a, p);
        assertEq(a, b);
    }

    function testDeployDeterministicPassValues() public {
        vm.deal(address(this), 1e18);
        address a = factory.createAccount{value: 1e18}(owners, 0);
        assertEq(a.balance, 1e18);
    }
}
