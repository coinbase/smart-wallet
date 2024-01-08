// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import "./ERC4337AccountTestBase.t.sol";

contract TestCanSkipChainIdValidation is AccountTestBase {
    bytes4[] approvedSelectors = [
        MultiOwnable.addOwnerAddress.selector,
        MultiOwnable.addOwnerPublicKey.selector,
        MultiOwnable.addOwnerAddressAtIndex.selector,
        MultiOwnable.addOwnerPublicKeyAtIndex.selector,
        MultiOwnable.removeOwnerAtIndex.selector,
        UUPSUpgradeable.upgradeToAndCall.selector
    ];
    bytes4[] otherSelectors = [ERC4337Account.execute.selector, ERC4337Account.executeBatch.selector];

    function test_approvedSelectorsReturnTrue() public {
        for (uint256 i = 0; i < approvedSelectors.length; i++) {
            assertTrue(account.canSkipChainIdValidation(approvedSelectors[i]));
        }
    }

    function test_otherSelectorsReturnFalse() public {
        for (uint256 i = 0; i < otherSelectors.length; i++) {
            assertFalse(account.canSkipChainIdValidation(otherSelectors[i]));
        }
    }
}
