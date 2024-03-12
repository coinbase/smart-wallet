// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test, console2} from "forge-std/Test.sol";
import {CoinbaseSmartWallet} from "../src/CoinbaseSmartWallet.sol";
import {CoinbaseSmartWalletFactory} from "../src/CoinbaseSmartWalletFactory.sol";

contract CoinbaseSmartWalletFactoryTest is Test {
    CoinbaseSmartWalletFactory factory;
    CoinbaseSmartWallet account;
    bytes[] owners;

    function setUp() public {
        account = new CoinbaseSmartWallet();
        factory = new CoinbaseSmartWalletFactory(address(account));
        owners.push(abi.encode(address(1)));
        owners.push(abi.encode(address(2)));
    }

    function test_createAccountSetsOwnersCorrectly() public {
        address expectedAddress = factory.getAddress(owners, 0);
        vm.expectCall(expectedAddress, abi.encodeCall(CoinbaseSmartWallet.initialize, (owners)));
        CoinbaseSmartWallet a = factory.createAccount{value: 1e18}(owners, 0);
        assert(a.isOwnerAddress(address(1)));
        assert(a.isOwnerAddress(address(2)));
    }

    function test_revertsIfNoOwners() public {
        owners.pop();
        owners.pop();
        vm.expectRevert(CoinbaseSmartWalletFactory.OwnerRequired.selector);
        factory.createAccount{value: 1e18}(owners, 0);
    }

    function test_createAccountDeploysToPredeterminedAddress() public {
        address p = factory.getAddress(owners, 0);
        CoinbaseSmartWallet a = factory.createAccount{value: 1e18}(owners, 0);
        assertEq(address(a), p);
    }

    function test_CreateAccount_ReturnsPredeterminedAddress_WhenAccountAlreadyExists() public {
        address p = factory.getAddress(owners, 0);
        CoinbaseSmartWallet a = factory.createAccount{value: 1e18}(owners, 0);
        CoinbaseSmartWallet b = factory.createAccount{value: 1e18}(owners, 0);
        assertEq(address(a), p);
        assertEq(address(a), address(b));
    }

    function testDeployDeterministicPassValues() public {
        vm.deal(address(this), 1e18);
        CoinbaseSmartWallet a = factory.createAccount{value: 1e18}(owners, 0);
        assertEq(address(a).balance, 1e18);
    }

    function test_implementation_returnsExpectedAddress() public {
        assertEq(factory.implementation(), address(account));
    }
}
