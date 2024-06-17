// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {FCL_ecdsa_utils} from "FreshCryptoLib/FCL_ecdsa_utils.sol";
import {FCL_Elliptic_ZZ} from "FreshCryptoLib/FCL_elliptic.sol";
import {UserOperation, UserOperationLib} from "account-abstraction/interfaces/UserOperation.sol";
import {Vm} from "forge-std/Vm.sol";
import {Base64} from "openzeppelin-contracts/contracts/utils/Base64.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {WebAuthn} from "webauthn-sol/WebAuthn.sol";

import {CoinbaseSmartWallet} from "../../src/CoinbaseSmartWallet.sol";
import {ERC1271} from "../../src/ERC1271.sol";
import {IKeyStore} from "../../src/ext/IKeyStore.sol";
import {IVerifier} from "../../src/ext/IVerifier.sol";

enum ProofVerificationOutput {
    Reverts,
    Fails,
    Succeeds
}

library LibCoinbaseSmartWallet {
    bytes32 private constant COINBASE_SMART_WALLET_LOCATION =
        0x99a34bffa68409ea583717aeb46691b092950ed596c79c2fc789604435b66c00;

    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                         MOCK HELPERS                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    function uninitialize(address target) internal {
        vm.store(target, COINBASE_SMART_WALLET_LOCATION, bytes32(0));
        vm.store(target, bytes32(uint256(COINBASE_SMART_WALLET_LOCATION) + 1), bytes32(0));
    }

    function initialize(address target, uint256 ksKey, CoinbaseSmartWallet.KeyspaceKeyType ksKeyType) internal {
        vm.store(target, COINBASE_SMART_WALLET_LOCATION, bytes32(ksKey));
        vm.store(target, bytes32(uint256(COINBASE_SMART_WALLET_LOCATION) + 1), bytes32(uint256(ksKeyType)));
    }

    function readEip1967ImplementationSlot(address target) internal view returns (address) {
        return address(
            uint160(
                uint256(
                    vm.load({target: target, slot: 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc})
                )
            )
        );
    }

    function mockEip1271(address signer, bool isValid) internal {
        bytes memory res = abi.encode(isValid ? bytes4(0x1626ba7e) : bytes4(0xffffffff));
        vm.mockCall({callee: signer, data: abi.encodeWithSelector(ERC1271.isValidSignature.selector), returnData: res});
    }

    function mockKeyStore(address keyStore, uint256 root) internal {
        vm.mockCall({
            callee: keyStore,
            data: abi.encodeWithSelector(IKeyStore.root.selector),
            returnData: abi.encode(root)
        });
    }

    function mockRevertKeyStore(address keyStore, bytes memory revertData) internal {
        vm.mockCallRevert({
            callee: keyStore,
            data: abi.encodeWithSelector(IKeyStore.root.selector),
            revertData: revertData
        });
    }

    function mockStateVerifier(address stateVerifier, bool value) internal {
        vm.mockCall({
            callee: stateVerifier,
            data: abi.encodeWithSelector(IVerifier.Verify.selector),
            returnData: abi.encode(value)
        });
    }

    function mockRevertKeyStateVerifier(address stateVerifier, bytes memory revertData) internal {
        vm.mockCallRevert({
            callee: stateVerifier,
            data: abi.encodeWithSelector(IVerifier.Verify.selector),
            revertData: revertData
        });
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                         TEST HELPERS                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    function uintToKsKeyType(uint256 value) internal pure returns (CoinbaseSmartWallet.KeyspaceKeyType) {
        // Prevent generting 0 (None) value.
        value = value % 2;
        return CoinbaseSmartWallet.KeyspaceKeyType(value + 1);
    }

    function hashUserOp(CoinbaseSmartWallet sut, UserOperation memory userOp, bool forceChainId)
        internal
        view
        returns (bytes32)
    {
        bytes32 h = keccak256(
            abi.encode(
                userOp.sender,
                userOp.nonce,
                keccak256(userOp.initCode),
                keccak256(userOp.callData),
                userOp.callGasLimit,
                userOp.verificationGasLimit,
                userOp.preVerificationGas,
                userOp.maxFeePerGas,
                userOp.maxPriorityFeePerGas,
                keccak256(userOp.paymasterAndData)
            )
        );

        if (
            forceChainId == false
                && bytes4(userOp.callData) == CoinbaseSmartWallet.executeWithoutChainIdValidation.selector
        ) {
            return keccak256(abi.encode(h, sut.entryPoint()));
        } else {
            return keccak256(abi.encode(h, sut.entryPoint(), block.chainid));
        }
    }

    function wallet(uint256 privateKey) internal returns (Vm.Wallet memory wallet_) {
        if (privateKey == 0) {
            privateKey = 1;
        }

        wallet_ = vm.createWallet(privateKey, "Wallet");
    }

    function passKeyWallet(uint256 privateKey) internal view returns (Vm.Wallet memory passKeyWallet_) {
        if (privateKey == 0) {
            privateKey = 1;
        }

        passKeyWallet_.addr = address(0xdead);
        passKeyWallet_.privateKey = privateKey;
        (passKeyWallet_.publicKeyX, passKeyWallet_.publicKeyY) = FCL_ecdsa_utils.ecdsa_derivKpub(privateKey);
    }

    function validNonceKey(CoinbaseSmartWallet sut, UserOperation memory userOp)
        internal
        view
        returns (uint256 nonce)
    {
        // Force the key to be REPLAYABLE_NONCE_KEY when calling `executeWithoutChainIdValidation`
        if (bytes4(userOp.callData) == CoinbaseSmartWallet.executeWithoutChainIdValidation.selector) {
            nonce = sut.REPLAYABLE_NONCE_KEY() << 64 | uint256(uint64(userOp.nonce));
        }
        // Else ensure the key is NOT REPLAYABLE_NONCE_KEY.
        else {
            uint256 key = userOp.nonce >> 64;
            if (key == sut.REPLAYABLE_NONCE_KEY()) {
                key += 1;
            }

            nonce = key << 64 | uint256(uint64(userOp.nonce));
        }
    }

    function eoaSignature(Vm.Wallet memory w, bytes32 userOpHash, bool validSig, bytes memory stateProof)
        internal
        returns (bytes memory sigData)
    {
        uint8 v;
        bytes32 r;
        bytes32 s;
        bytes memory sig = bytes("invalid by default");
        if (validSig) {
            (v, r, s) = vm.sign(w, userOpHash);
        }

        sig = abi.encodePacked(r, s, v);
        sigData = abi.encode(sig, w.publicKeyX, w.publicKeyY, stateProof);
    }

    function eip1271Signature(Vm.Wallet memory w, bytes32 userOpHash, bool validSig, bytes memory stateProof)
        internal
        returns (bytes memory sigData)
    {
        bytes memory sig = bytes.concat("CUSTOM EIP1271 SIGNATURE: ", userOpHash);
        sigData = abi.encode(sig, w.publicKeyX, w.publicKeyY, stateProof);

        mockEip1271({signer: w.addr, isValid: validSig});
    }

    function webAuthnSignature(Vm.Wallet memory w, bytes32 userOpHash, bool validSig, bytes memory stateProof)
        internal
        pure
        returns (bytes memory sigData)
    {
        string memory challengeb64url = Base64.encodeURL(abi.encode(userOpHash));
        string memory clientDataJSON = string(
            abi.encodePacked(
                '{"type":"webauthn.get","challenge":"',
                challengeb64url,
                '","origin":"https://sign.coinbase.com","crossOrigin":false}'
            )
        );

        // Authenticator data for Chrome Profile touchID signature
        bytes memory authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000";

        bytes32 h = sha256(abi.encodePacked(authenticatorData, sha256(bytes(clientDataJSON))));

        WebAuthn.WebAuthnAuth memory webAuthn;
        webAuthn.authenticatorData = authenticatorData;
        webAuthn.clientDataJSON = clientDataJSON;
        webAuthn.typeIndex = 1;
        webAuthn.challengeIndex = 23;

        if (validSig) {
            (bytes32 r, bytes32 s) = vm.signP256(w.privateKey, h);
            if (uint256(s) > (FCL_Elliptic_ZZ.n / 2)) {
                s = bytes32(FCL_Elliptic_ZZ.n - uint256(s));
            }
            webAuthn.r = uint256(r);
            webAuthn.s = uint256(s);
        }

        bytes memory sig = abi.encode(webAuthn);
        sigData = abi.encode(sig, w.publicKeyX, w.publicKeyY, stateProof);
    }

    function publicInputs(Vm.Wallet memory w, uint256 ksKey, uint256 stateRoot)
        internal
        pure
        returns (uint256[] memory publicInputs_)
    {
        // Verify the state proof.
        uint256[] memory data = new uint256[](8);
        data[0] = w.publicKeyX;
        data[1] = w.publicKeyY;

        publicInputs_ = new uint256[](3);
        publicInputs_[0] = ksKey;
        publicInputs_[1] = stateRoot;
        publicInputs_[2] = uint256(keccak256(abi.encodePacked(data)) >> 8);
    }

    function isApprovedSelector(bytes4 selector) internal pure returns (bool) {
        return selector == UUPSUpgradeable.upgradeToAndCall.selector;
    }

    function approvedSelectors() internal pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](1);
        selectors[0] = UUPSUpgradeable.upgradeToAndCall.selector;
    }

    function notApprovedSelectors() internal pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](2);
        selectors[0] = CoinbaseSmartWallet.execute.selector;
        selectors[1] = CoinbaseSmartWallet.executeBatch.selector;
    }
}
