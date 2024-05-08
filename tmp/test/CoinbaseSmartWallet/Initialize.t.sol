// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./SmartWalletTestBase.sol";

contract TestInitialize is SmartWalletTestBase {
    function testInitialize() public view {
        assert(account.isOwnerAddress(signer));
        assert(account.isOwnerBytes(passkeyOwner));
    }

    function test_cannotInitImplementation() public {
        account = new CoinbaseSmartWallet();
        vm.expectRevert(CoinbaseSmartWallet.Initialized.selector);
        account.initialize(owners);
    }
}
