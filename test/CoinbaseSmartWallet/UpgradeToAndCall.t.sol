// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {CoinbaseSmartWalletFactory} from "../../src/CoinbaseSmartWalletFactory.sol";
import {CoinbaseSmartWallet} from "../../src/CoinbaseSmartWallet.sol";

import "./SmartWalletTestBase.sol";

contract TestUpgradeToAndCall is SmartWalletTestBase {
    address newImplementation = address(new CoinbaseSmartWallet());

    function setUp() public override {
        super.setUp();
        CoinbaseSmartWalletFactory factory = new CoinbaseSmartWalletFactory(address(new CoinbaseSmartWallet()));
        account = factory.createAccount(owners, 1);
    }

    function testUpgradeToAndCall() public {
        vm.startPrank(signer);
        account.upgradeToAndCall(newImplementation, abi.encodeWithSignature("dummy()"));
        Dummy(address(account)).dummy();
    }
    
    function testUpgradeToAndCallWithNonOwner() public {
        vm.startPrank(address(1));
        vm.expectRevert(MultiOwnable.Unauthorized.selector);  
        account.upgradeToAndCall(newImplementation, abi.encodeWithSignature("dummy()"));
    }
}

contract Dummy is UUPSUpgradeable {
    event Done();

    function dummy() public {
        emit Done();
    }

    function _authorizeUpgrade(address newImplementation) internal override {}
}
