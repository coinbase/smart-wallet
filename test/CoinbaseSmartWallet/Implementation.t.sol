// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {OnitSmartWallet} from "../../src/CoinbaseSmartWallet.sol";
import {OnitSmartWalletFactory} from "../../src/CoinbaseSmartWalletFactory.sol";

import "./SmartWalletTestBase.sol";

contract TestImplementation is SmartWalletTestBase {
    address implementation = address(new OnitSmartWallet());

    function setUp() public override {
        super.setUp();
        OnitSmartWalletFactory factory = new OnitSmartWalletFactory(implementation);
        account = factory.createAccount(owners, 1);
    }

    function testImplementation() public {
        address addr = account.implementation();
        assertEq(addr, implementation);
    }
}
