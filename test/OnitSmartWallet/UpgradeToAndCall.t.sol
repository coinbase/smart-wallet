// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {OnitSmartWalletFactory} from "../../src/OnitSmartWalletFactory.sol";

import "./SmartWalletTestBase.sol";

contract TestUpgradeToAndCall is SmartWalletTestBase {
    address newImplementation = address(new Dummy());

    function setUp() public override {
        super.setUp();
        OnitSmartWalletFactory factory = new OnitSmartWalletFactory(address(new OnitSmartWallet()));
        account = factory.createAccount(owners, 1);
        vm.startPrank(signer);
    }

    function testUpgradeToAndCall() public {
        account.upgradeToAndCall(newImplementation, abi.encodeWithSignature("dummy()"));
        Dummy(address(account)).dummy();
    }
}

contract Dummy is UUPSUpgradeable {
    event Done();

    function dummy() public {
        emit Done();
    }

    function _authorizeUpgrade(address newImplementation) internal override {}
}
