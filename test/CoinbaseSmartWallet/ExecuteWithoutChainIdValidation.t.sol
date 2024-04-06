// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./SmartWalletTestBase.sol";

contract TestExecuteWithoutChainIdValidation is SmartWalletTestBase {
    bytes[] calls;

    function setUp() public override {
        super.setUp();
        userOpNonce = account.REPLAYABLE_NONCE_KEY() << 64;
        userOpCalldata = abi.encodeWithSelector(CoinbaseSmartWallet.executeWithoutChainIdValidation.selector);
    }

    function test_reverts_whenCallerNotEntryPoint() public {
        vm.expectRevert(MultiOwnable.Unauthorized.selector);
        account.executeWithoutChainIdValidation(calls);
    }

    function test_succeeds_whenSelectorAllowed() public {
        bytes4 selector = MultiOwnable.addOwnerAddress.selector;
        assertTrue(account.canSkipChainIdValidation(selector));
        address newOwner = address(6);
        assertFalse(account.isOwnerAddress(newOwner));
        calls.push(abi.encodeWithSelector(selector, newOwner));
        userOpCalldata = abi.encodeWithSelector(CoinbaseSmartWallet.executeWithoutChainIdValidation.selector, calls);
        _sendUserOperation(_getUserOpWithSignature());
        assertTrue(account.isOwnerAddress(newOwner));
    }

    function test_reverts_whenSelectorNotApproved() public {
        bytes4 selector = CoinbaseSmartWallet.execute.selector;
        assertFalse(account.canSkipChainIdValidation(selector));
        bytes memory restrictedSelectorCalldata = abi.encodeWithSelector(selector, "");
        calls.push(restrictedSelectorCalldata);
        vm.prank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                CoinbaseSmartWallet.SelectorNotAllowed.selector, CoinbaseSmartWallet.execute.selector
            )
        );
        account.executeWithoutChainIdValidation(calls);
    }

    function test_reverts_whenOneSelectorNotApproved() public {
        bytes4 badSelector = CoinbaseSmartWallet.execute.selector;
        bytes4 goodSelector = MultiOwnable.addOwnerAddress.selector;
        assertFalse(account.canSkipChainIdValidation(badSelector));
        assertTrue(account.canSkipChainIdValidation(goodSelector));
        calls.push(abi.encodeWithSelector(badSelector, ""));
        address newOwner = address(6);
        assertFalse(account.isOwnerAddress(newOwner));
        calls.push(abi.encodeWithSelector(goodSelector, newOwner));
        vm.prank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                CoinbaseSmartWallet.SelectorNotAllowed.selector, CoinbaseSmartWallet.execute.selector
            )
        );
        account.executeWithoutChainIdValidation(calls);
    }

    function test_reverts_whenOneCallReverts() public {
        bytes4 selector = MultiOwnable.addOwnerAddress.selector;
        assertTrue(account.canSkipChainIdValidation(selector));
        address newOwner = address(6);
        assertFalse(account.isOwnerAddress(newOwner));
        calls.push(abi.encodeWithSelector(selector, newOwner));
        calls.push(abi.encodeWithSelector(selector, newOwner));
        userOpCalldata = abi.encodeWithSelector(CoinbaseSmartWallet.executeWithoutChainIdValidation.selector, calls);
        vm.prank(address(entryPoint));
        vm.expectRevert();
        account.executeWithoutChainIdValidation(calls);
    }

    function _sign(UserOperation memory userOp) internal view override returns (bytes memory signature) {
        bytes32 toSign = account.getUserOpHashWithoutChainId(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, toSign);
        signature = abi.encode(CoinbaseSmartWallet.SignatureWrapper(0, abi.encodePacked(r, s, v)));
    }
}
