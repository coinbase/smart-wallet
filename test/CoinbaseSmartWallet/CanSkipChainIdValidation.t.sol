// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./SmartWalletTestBase.sol";

contract TestCanSkipChainIdValidation is SmartWalletTestBase {
    bytes4[] approvedSelectors = [
        MultiOwnable.addOwnerAddress.selector,
        MultiOwnable.addOwnerPublicKey.selector,
        MultiOwnable.removeOwnerAtIndex.selector,
        MultiOwnable.removeLastOwner.selector,
        UUPSUpgradeable.upgradeToAndCall.selector
    ];
    bytes4[] otherSelectors = [CoinbaseSmartWallet.execute.selector, CoinbaseSmartWallet.executeBatch.selector];

    function test_approvedSelectorsReturnTrue() public {
        for (uint256 i; i < approvedSelectors.length; i++) {
            assertTrue(account.canSkipChainIdValidation(approvedSelectors[i]));
        }
    }

    function test_otherSelectorsReturnFalse() public {
        for (uint256 i; i < otherSelectors.length; i++) {
            assertFalse(account.canSkipChainIdValidation(otherSelectors[i]));
        }
    }
}
