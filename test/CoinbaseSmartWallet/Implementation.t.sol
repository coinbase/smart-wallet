// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {CoinbaseSmartWallet} from "../../src/CoinbaseSmartWallet.sol";
import {CoinbaseSmartWalletFactory} from "../../src/CoinbaseSmartWalletFactory.sol";

import "./SmartWalletTestBase.sol";

contract TestImplementation is SmartWalletTestBase {
    address implementation = address(new CoinbaseSmartWallet());

    function setUp() public override {
        super.setUp();
        CoinbaseSmartWalletFactory factory = new CoinbaseSmartWalletFactory(implementation);
        account = factory.createAccount(owners, 1);
    }

    function testImplementation() public {
        address addr = account.implementation();
        assertEq(addr, implementation);
    }
}
