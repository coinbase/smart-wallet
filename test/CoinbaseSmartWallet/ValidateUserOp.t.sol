// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "webauthn-sol/../test/Utils.sol";
import {FCL_ecdsa} from "FreshCryptoLib/FCL_ecdsa.sol";

import {MockEntryPoint} from "../mocks/MockEntryPoint.sol";
import "./SmartWalletTestBase.sol";

contract TestValidateUserOp is SmartWalletTestBase {
    struct _TestTemps {
        bytes32 userOpHash;
        address signer;
        uint256 privateKey;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 missingAccountFunds;
    }

    // test adapted from Solady
    function test_succeedsWithEOASigner() public {
        _TestTemps memory t;
        t.userOpHash = keccak256("123");
        t.signer = signer;
        t.privateKey = signerPrivateKey;
        (t.v, t.r, t.s) = vm.sign(t.privateKey, t.userOpHash);
        t.missingAccountFunds = 456;
        vm.deal(address(account), 1 ether);
        assertEq(address(account).balance, 1 ether);

        vm.etch(account.entryPoint(), address(new MockEntryPoint()).code);
        MockEntryPoint ep = MockEntryPoint(payable(account.entryPoint()));

        UserOperation memory userOp;
        // Success returns 0.
        userOp.signature = abi.encode(CoinbaseSmartWallet.SignatureWrapper(0, abi.encodePacked(t.r, t.s, t.v)));
        assertEq(ep.validateUserOp(address(account), userOp, t.userOpHash, t.missingAccountFunds), 0);
        assertEq(address(ep).balance, t.missingAccountFunds);
        // Failure returns 1.
        userOp.signature =
            abi.encode(CoinbaseSmartWallet.SignatureWrapper(0, abi.encodePacked(t.r, bytes32(uint256(t.s) ^ 1), t.v)));
        assertEq(ep.validateUserOp(address(account), userOp, t.userOpHash, t.missingAccountFunds), 1);
        assertEq(address(ep).balance, t.missingAccountFunds * 2);
        // Not entry point reverts.
        vm.expectRevert(MultiOwnable.Unauthorized.selector);
        account.validateUserOp(userOp, t.userOpHash, t.missingAccountFunds);
    }

    function test_succeedsWithPasskeySigner() public {
        _TestTemps memory t;
        t.userOpHash = keccak256("123");
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(t.userOpHash);

        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        s = bytes32(Utils.normalizeS(uint256(s)));
        bytes memory sig = abi.encode(
            CoinbaseSmartWallet.SignatureWrapper({
                ownerIndex: 1,
                signatureData: abi.encode(
                    WebAuthn.WebAuthnAuth({
                        authenticatorData: webAuthn.authenticatorData,
                        clientDataJSON: webAuthn.clientDataJSON,
                        typeIndex: 1,
                        challengeIndex: 23,
                        r: uint256(r),
                        s: uint256(s)
                    })
                )
            })
        );

        vm.etch(account.entryPoint(), address(new MockEntryPoint()).code);
        MockEntryPoint ep = MockEntryPoint(payable(account.entryPoint()));

        UserOperation memory userOp;
        // Success returns 0.
        userOp.signature = sig;
        assertEq(ep.validateUserOp(address(account), userOp, t.userOpHash, t.missingAccountFunds), 0);
    }

    function test_returnsOne_whenPasskeySignedDifferentHash() public {
        bytes32 userOpHash = keccak256("123");
        bytes memory sig = _passkeySignature(keccak256("456"));

        vm.etch(account.entryPoint(), address(new MockEntryPoint()).code);
        MockEntryPoint ep = MockEntryPoint(payable(account.entryPoint()));

        UserOperation memory userOp;
        userOp.signature = sig;
        assertEq(ep.validateUserOp(address(account), userOp, userOpHash, 0), 1);
    }

    function test_succeedsWithPasskeySigner_onReplayableUserOp() public {
        UserOperation memory userOp;
        userOp.sender = address(account);
        userOp.nonce = account.REPLAYABLE_NONCE_KEY() << 64;
        userOp.callData = abi.encodeWithSelector(CoinbaseSmartWallet.executeWithoutChainIdValidation.selector);
        // The passkey signs the chain-agnostic hash, not the hash the EntryPoint passes in.
        userOp.signature = _passkeySignature(account.getUserOpHashWithoutChainId(userOp));

        vm.etch(account.entryPoint(), address(new MockEntryPoint()).code);
        MockEntryPoint ep = MockEntryPoint(payable(account.entryPoint()));

        assertEq(ep.validateUserOp(address(account), userOp, keccak256("ignored for replayable ops"), 0), 0);

        // The same signature is still valid after switching chains.
        vm.chainId(block.chainid + 1);
        assertEq(ep.validateUserOp(address(account), userOp, keccak256("ignored for replayable ops"), 0), 0);
    }

    function test_reverts_whenPasskeyOwnerRemoved() public {
        bytes32 userOpHash = keccak256("123");
        bytes memory sig = _passkeySignature(userOpHash);

        vm.prank(signer);
        account.removeOwnerAtIndex(1, passkeyOwner);

        vm.etch(account.entryPoint(), address(new MockEntryPoint()).code);
        MockEntryPoint ep = MockEntryPoint(payable(account.entryPoint()));

        UserOperation memory userOp;
        userOp.signature = sig;
        vm.expectRevert(abi.encodeWithSelector(MultiOwnable.InvalidOwnerBytesLength.selector, ""));
        ep.validateUserOp(address(account), userOp, userOpHash, 0);
    }

    // Foundry won't etch over the P-256 precompile at 0x100, so check the Solidity fallback
    // that WebAuthn uses on chains without it directly.
    function test_fallbackVerifierAcceptsPasskeySignature() public view {
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(keccak256("123"));
        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        s = bytes32(Utils.normalizeS(uint256(s)));
        (uint256 x, uint256 y) = abi.decode(passkeyOwner, (uint256, uint256));

        assertTrue(FCL_ecdsa.ecdsa_verify(webAuthn.messageHash, uint256(r), uint256(s), x, y));
        assertFalse(FCL_ecdsa.ecdsa_verify(keccak256("456"), uint256(r), uint256(s), x, y));
    }

    function _passkeySignature(bytes32 hash) internal view returns (bytes memory) {
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(hash);
        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        s = bytes32(Utils.normalizeS(uint256(s)));
        return abi.encode(
            CoinbaseSmartWallet.SignatureWrapper({
                ownerIndex: 1,
                signatureData: abi.encode(
                    WebAuthn.WebAuthnAuth({
                        authenticatorData: webAuthn.authenticatorData,
                        clientDataJSON: webAuthn.clientDataJSON,
                        typeIndex: 1,
                        challengeIndex: 23,
                        r: uint256(r),
                        s: uint256(s)
                    })
                )
            })
        );
    }

    function test_reverts_whenSelectorInvalidForReplayableNonceKey() public {
        UserOperation memory userOp;
        userOp.nonce = 0;
        userOp.callData = abi.encodeWithSelector(CoinbaseSmartWallet.executeWithoutChainIdValidation.selector, "");
        vm.startPrank(account.entryPoint());
        vm.expectRevert(abi.encodeWithSelector(CoinbaseSmartWallet.InvalidNonceKey.selector, 0));
        account.validateUserOp(userOp, "", 0);
    }

    function test_reverts_whenReplayableNonceKeyInvalidForSelector() public {
        UserOperation memory userOp;
        userOp.nonce = account.REPLAYABLE_NONCE_KEY() << 64;
        userOp.callData = abi.encodeWithSelector(CoinbaseSmartWallet.execute.selector, "");
        vm.startPrank(account.entryPoint());
        vm.expectRevert(
            abi.encodeWithSelector(CoinbaseSmartWallet.InvalidNonceKey.selector, account.REPLAYABLE_NONCE_KEY())
        );
        account.validateUserOp(userOp, "", 0);
    }

    function test_reverts_whenUpgradeToImplementationWithNoCode(address emptyImplementation) public {
        vm.assume(emptyImplementation.code.length == 0);

        // Create a UserOperation that calls executeWithoutChainIdValidation with an upgrade call
        bytes[] memory calls = new bytes[](1);
        calls[0] = abi.encodeWithSelector(UUPSUpgradeable.upgradeToAndCall.selector, emptyImplementation, "");

        UserOperation memory userOp;
        userOp.nonce = account.REPLAYABLE_NONCE_KEY() << 64;
        userOp.callData = abi.encodeWithSelector(CoinbaseSmartWallet.executeWithoutChainIdValidation.selector, calls);
        userOp.signature =
            abi.encode(CoinbaseSmartWallet.SignatureWrapper(0, abi.encodePacked(bytes32(0), bytes32(0), uint8(27))));

        vm.startPrank(account.entryPoint());
        vm.expectRevert(abi.encodeWithSelector(CoinbaseSmartWallet.InvalidImplementation.selector, emptyImplementation));
        account.validateUserOp(userOp, "", 0);
    }

    function test_succeeds_whenUpgradeToImplementationWithCode() public {
        // Deploy a mock implementation that has code
        MockCoinbaseSmartWallet mockImpl = new MockCoinbaseSmartWallet();
        address validImplementation = address(mockImpl);

        // Create a UserOperation that calls executeWithoutChainIdValidation with an upgrade call
        bytes[] memory calls = new bytes[](1);
        calls[0] = abi.encodeWithSelector(UUPSUpgradeable.upgradeToAndCall.selector, validImplementation, "");

        UserOperation memory userOp;
        userOp.nonce = account.REPLAYABLE_NONCE_KEY() << 64;
        userOp.callData = abi.encodeWithSelector(CoinbaseSmartWallet.executeWithoutChainIdValidation.selector, calls);
        userOp.signature =
            abi.encode(CoinbaseSmartWallet.SignatureWrapper(0, abi.encodePacked(bytes32(0), bytes32(0), uint8(27))));

        vm.startPrank(account.entryPoint());
        // Should revert with signature error (1) rather than InvalidImplementation
        assertEq(account.validateUserOp(userOp, "", 0), 1);
    }
}
