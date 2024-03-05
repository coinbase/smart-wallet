// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./SmartWalletTestBase.sol";
import "webauthn-sol/../test/Utils.sol";

contract TestIsValidSignature is SmartWalletTestBase {
    function testValidateSignatureWithPasskeySigner() public {
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 challenge = account.replaySafeHash(hash);
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(challenge);

        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
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

        // check a valid signature
        bytes4 ret = account.isValidSignature(hash, sig);
        assertEq(ret, bytes4(0x1626ba7e));
    }

    function testValidateSignatureWithPasskeySignerFailsBadOwnerIndex() public {
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 challenge = account.replaySafeHash(hash);
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(challenge);

        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);

        uint8 badOwnerIndex = 2;
        bytes memory sig = abi.encode(
            CoinbaseSmartWallet.SignatureWrapper({
                ownerIndex: badOwnerIndex,
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

        vm.expectRevert(abi.encodeWithSelector(CoinbaseSmartWallet.InvalidOwnerForSignature.selector, uint8(2), ""));
        account.isValidSignature(hash, sig);
    }

    function testValidateSignatureWithPasskeySignerFailsWithWrongBadSignature() public {
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 challenge = account.replaySafeHash(hash);
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(challenge);

        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);

        bytes memory sig = abi.encode(
            CoinbaseSmartWallet.SignatureWrapper({
                ownerIndex: 1,
                signatureData: abi.encode(
                    WebAuthn.WebAuthnAuth({
                        authenticatorData: webAuthn.authenticatorData,
                        clientDataJSON: webAuthn.clientDataJSON,
                        typeIndex: 1,
                        challengeIndex: 23,
                        r: uint256(r) - 1,
                        s: uint256(s)
                    })
                    )
            })
        );

        // check a valid signature
        bytes4 ret = account.isValidSignature(hash, sig);
        assertEq(ret, bytes4(0xffffffff));
    }

    function testValidateSignatureWithEOASigner() public {
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 toSign = account.replaySafeHash(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, toSign);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes4 ret = account.isValidSignature(hash, abi.encode(CoinbaseSmartWallet.SignatureWrapper(0, signature)));
        assertEq(ret, bytes4(0x1626ba7e));
    }

    function testValidateSignatureWithEOASignerFailsWithWrongSigner() public {
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xa12ce, hash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes4 ret = account.isValidSignature(hash, abi.encode(CoinbaseSmartWallet.SignatureWrapper(0, signature)));
        assertEq(ret, bytes4(0xffffffff));
    }

    function testRevertsIfPasskeySigButWrongOwnerLength() public {
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 challenge = account.replaySafeHash(hash);
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(challenge);

        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);

        uint8 addressOwnerIndex = 0;
        bytes memory sig = abi.encode(
            CoinbaseSmartWallet.SignatureWrapper({
                ownerIndex: addressOwnerIndex,
                signatureData: abi.encode(
                    WebAuthn.WebAuthnAuth({
                        authenticatorData: webAuthn.authenticatorData,
                        clientDataJSON: webAuthn.clientDataJSON,
                        typeIndex: 1,
                        challengeIndex: 23,
                        r: uint256(r) - 1,
                        s: uint256(s)
                    })
                    )
            })
        );

        vm.expectRevert(
            abi.encodeWithSelector(CoinbaseSmartWallet.InvalidOwnerForSignature.selector, uint8(0), abi.encode(signer))
        );
        account.isValidSignature(hash, sig);
    }

    function testRevertsIfEthereumSignatureButWrongOwnerLength() public {
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 toSign = SignatureCheckerLib.toEthSignedMessageHash(account.replaySafeHash(hash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, toSign);
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.expectRevert(
            abi.encodeWithSelector(CoinbaseSmartWallet.InvalidOwnerForSignature.selector, uint8(1), passkeyOwner)
        );
        account.isValidSignature(hash, abi.encode(CoinbaseSmartWallet.SignatureWrapper(1, signature)));
    }
}
