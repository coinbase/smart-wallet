// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "forge-std/Test.sol";

import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";

import {IKeyStore} from "../../src/ext/IKeyStore.sol";
import {IVerifier} from "../../src/ext/IVerifier.sol";

import {CoinbaseSmartWallet} from "../../src/CoinbaseSmartWallet.sol";
import {CoinbaseSmartWalletFactory} from "../../src/CoinbaseSmartWalletFactory.sol";
import {ERC1271} from "../../src/ERC1271.sol";

import {LibCoinbaseSmartWallet, ProofVerificationOutput} from "../utils/LibCoinbaseSmartWallet.sol";

contract CoinbaseSmartWalletTest is Test {
    address private keyStore = makeAddr("KeyStore");
    address private stateVerifier = makeAddr("StateVerifier");

    CoinbaseSmartWallet private impl;
    CoinbaseSmartWallet private sut;

    function setUp() public {
        impl = new CoinbaseSmartWallet({keyStore_: keyStore, stateVerifier_: stateVerifier});

        CoinbaseSmartWalletFactory factory = new CoinbaseSmartWalletFactory(address(impl));

        // `ksKey` and `ksKeyType` are overwritten by tests so their value here does not matter.
        sut = factory.createAccount({
            ksKey: uint256(keccak256("start-key")),
            ksKeyType: CoinbaseSmartWallet.KeyspaceKeyType.WebAuthn,
            nonce: 0
        });
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            MODIFIERS                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    modifier withSenderEntryPoint() {
        vm.startPrank(sut.entryPoint());
        _;
        vm.stopPrank();
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                             TESTS                                              //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @custom:test-section initialize

    function test_initialize_reverts_whenTheAccountIsAlreadyInitialized(uint256 ksKey, uint256 ksKeyType) external {
        vm.expectRevert(CoinbaseSmartWallet.Initialized.selector);
        sut.initialize({ksKey: ksKey, ksKeyType: LibCoinbaseSmartWallet.uintToKsKeyType(ksKeyType)});
    }

    function test_initialize_reverts_whenTheKsKeyTypeIsNone(uint256 ksKey) external {
        vm.expectRevert(CoinbaseSmartWallet.Initialized.selector);
        sut.initialize({ksKey: ksKey, ksKeyType: CoinbaseSmartWallet.KeyspaceKeyType.None});
    }

    function test_initialize_initializesTheAccount(uint256 ksKey, uint256 ksKeyType) external {
        // Setup test:
        // 1. "De-initialize" the implementation.
        {
            LibCoinbaseSmartWallet.uninitialize(address(sut));
        }

        sut.initialize({ksKey: ksKey, ksKeyType: LibCoinbaseSmartWallet.uintToKsKeyType(ksKeyType)});
    }

    /// @custom:test-section validateUserOp

    function test_validateUserOp_reverts_whenNotCalledByTheEntryPoint(UserOperation memory userOp) external {
        bytes32 userOpHash = LibCoinbaseSmartWallet.hashUserOp({sut: sut, userOp: userOp, forceChainId: true});

        vm.expectRevert(CoinbaseSmartWallet.Unauthorized.selector);
        sut.validateUserOp({userOp: userOp, userOpHash: userOpHash, missingAccountFunds: 0});
    }

    function test_validateUserOp_reverts_whenCallingExecuteWithoutChainIdValidationWithoutReplayableNonceKey(
        UserOperation memory userOp
    ) external withSenderEntryPoint {
        // Setup test:
        // 1. Set `userOp.callData` to `CoinbaseSmartWallet.executeWithoutChainIdValidation.selector`.
        // 2. Set `userOp.nonce` NOT to `REPLAYABLE_NONCE_KEY`.
        uint256 key;
        {
            userOp.callData = abi.encodeWithSelector(CoinbaseSmartWallet.executeWithoutChainIdValidation.selector);

            key = userOp.nonce >> 64;
            if (key == sut.REPLAYABLE_NONCE_KEY()) {
                key += 1;
            }
            userOp.nonce = key << 64 | uint256(uint64(userOp.nonce));
        }

        bytes32 userOpHash = LibCoinbaseSmartWallet.hashUserOp({sut: sut, userOp: userOp, forceChainId: true});

        vm.expectRevert(abi.encodeWithSelector(CoinbaseSmartWallet.InvalidNonceKey.selector, key));
        sut.validateUserOp({userOp: userOp, userOpHash: userOpHash, missingAccountFunds: 0});
    }

    function test_validateUserOp_reverts_whenUsingTheReplayableNonceKeyWhileNotCallingExecuteWithoutChainIdValidation(
        UserOperation memory userOp
    ) external withSenderEntryPoint {
        // Setup test:
        // 1. Set `userOp.callData` to `CoinbaseSmartWallet.execute.selector`.
        // 2. Set `userOp.nonce` to `REPLAYABLE_NONCE_KEY`.
        uint256 key;
        {
            userOp.callData = abi.encodeWithSelector(CoinbaseSmartWallet.execute.selector);

            key = sut.REPLAYABLE_NONCE_KEY();
            userOp.nonce = key << 64 | uint256(uint64(userOp.nonce));
        }

        bytes32 userOpHash = LibCoinbaseSmartWallet.hashUserOp({sut: sut, userOp: userOp, forceChainId: true});

        vm.expectRevert(abi.encodeWithSelector(CoinbaseSmartWallet.InvalidNonceKey.selector, key));
        sut.validateUserOp({userOp: userOp, userOpHash: userOpHash, missingAccountFunds: 0});
    }

    function test_validateUserOp_returnsOne_whenStateProofVerifReverts(
        uint256 ksKey,
        uint256 ksKeyType,
        uint248 privateKey,
        UserOperation memory userOp
    ) external withSenderEntryPoint {
        bytes32 userOpHash = _setUpTestWrapper_validateUserOp({
            ksKey: ksKey,
            ksKeyType: LibCoinbaseSmartWallet.uintToKsKeyType(ksKeyType),
            privateKey: privateKey,
            proofVerifOutput: ProofVerificationOutput.Reverts,
            isValidSig: true,
            userOp: userOp
        });

        uint256 validationData = sut.validateUserOp({userOp: userOp, userOpHash: userOpHash, missingAccountFunds: 0});
        assertEq(validationData, 1);
    }

    function test_validateUserOp_returnsOne_whenStateProofVerifFails(
        uint256 ksKey,
        uint256 ksKeyType,
        uint248 privateKey,
        UserOperation memory userOp
    ) external withSenderEntryPoint {
        bytes32 userOpHash = _setUpTestWrapper_validateUserOp({
            ksKey: ksKey,
            ksKeyType: LibCoinbaseSmartWallet.uintToKsKeyType(ksKeyType),
            privateKey: privateKey,
            proofVerifOutput: ProofVerificationOutput.Fails,
            isValidSig: true,
            userOp: userOp
        });

        uint256 validationData = sut.validateUserOp({userOp: userOp, userOpHash: userOpHash, missingAccountFunds: 0});
        assertEq(validationData, 1);
    }

    function test_validateUserOp_returnsOne_whenStateProofIsValidButSignatureIsInvalid(
        uint256 ksKey,
        uint256 ksKeyType,
        uint248 privateKey,
        UserOperation memory userOp
    ) external withSenderEntryPoint {
        bytes32 userOpHash = _setUpTestWrapper_validateUserOp({
            ksKey: ksKey,
            ksKeyType: LibCoinbaseSmartWallet.uintToKsKeyType(ksKeyType),
            privateKey: privateKey,
            proofVerifOutput: ProofVerificationOutput.Succeeds,
            isValidSig: false,
            userOp: userOp
        });

        uint256 validationData = sut.validateUserOp({userOp: userOp, userOpHash: userOpHash, missingAccountFunds: 0});
        assertEq(validationData, 1);
    }

    function test_validateUserOp_returnsZero_whenStateProofIsValidAndSignatureIsValid(
        uint256 ksKey,
        uint256 ksKeyType,
        uint248 privateKey,
        UserOperation memory userOp
    ) external withSenderEntryPoint {
        bytes32 userOpHash = _setUpTestWrapper_validateUserOp({
            ksKey: ksKey,
            ksKeyType: LibCoinbaseSmartWallet.uintToKsKeyType(ksKeyType),
            privateKey: privateKey,
            proofVerifOutput: ProofVerificationOutput.Succeeds,
            isValidSig: true,
            userOp: userOp
        });

        uint256 validationData = sut.validateUserOp({userOp: userOp, userOpHash: userOpHash, missingAccountFunds: 0});
        assertEq(validationData, 0);
    }

    function test_validateUserOp_transferMissingdFundsToEntryPoint_whenStateProofIsValidAndSignatureIsValid(
        uint256 ksKey,
        uint256 ksKeyType,
        uint248 privateKey,
        UserOperation memory userOp,
        uint256 missingAccountFunds
    ) external withSenderEntryPoint {
        bytes32 userOpHash = _setUpTestWrapper_validateUserOp({
            ksKey: ksKey,
            ksKeyType: LibCoinbaseSmartWallet.uintToKsKeyType(ksKeyType),
            privateKey: privateKey,
            proofVerifOutput: ProofVerificationOutput.Succeeds,
            isValidSig: true,
            userOp: userOp
        });

        vm.deal({account: address(sut), newBalance: missingAccountFunds});

        sut.validateUserOp({userOp: userOp, userOpHash: userOpHash, missingAccountFunds: missingAccountFunds});

        assertEq(address(sut).balance, 0);
        assertEq(sut.entryPoint().balance, missingAccountFunds);
    }

    /// @custom:test-section executeWithoutChainIdValidation

    function test_executeWithoutChainIdValidation_reverts_whenNotCalledByTheEntryPoint(bytes[] memory calls) external {
        vm.expectRevert(CoinbaseSmartWallet.Unauthorized.selector);
        sut.executeWithoutChainIdValidation(calls);
    }

    function test_executeWithoutChainIdValidation_reverts_whenSelectorIsNotApproved(bytes4 selector)
        external
        withSenderEntryPoint
    {
        // Setup test:
        // 1. Ensure `selector` is not approved.
        // 2. Build a call from `selector`.
        bytes[] memory calls;
        {
            calls = new bytes[](1);

            if (LibCoinbaseSmartWallet.isApprovedSelector(selector)) {
                selector = CoinbaseSmartWallet.execute.selector;
            }

            calls[0] = abi.encodeWithSelector(selector);
        }

        vm.expectRevert(abi.encodeWithSelector(CoinbaseSmartWallet.SelectorNotAllowed.selector, selector));
        sut.executeWithoutChainIdValidation(calls);
    }

    function test_executeWithoutChainIdValidation_reverts_whenOneSelectorIsNotApproved(uint256 notApprovedIndex)
        external
        withSenderEntryPoint
    {
        // Setup test:
        // 1. Randomly pick a not approved selector from the known list.
        // 2. Get the list of approved selectors.
        // 3. Build a list of calls from the approved selectors.
        // 4. Set the call[notApprovedIndex] to the not approved selector picked.
        bytes4 notApprovedSelector;
        bytes[] memory calls;
        {
            bytes4[] memory notApprovedSelectors = LibCoinbaseSmartWallet.notApprovedSelectors();
            notApprovedSelector = notApprovedSelectors[notApprovedIndex % (notApprovedSelectors.length)];

            bytes4[] memory approvedSelectors = LibCoinbaseSmartWallet.approvedSelectors();

            calls = new bytes[](approvedSelectors.length);
            for (uint256 i; i < approvedSelectors.length; i++) {
                calls[i] = abi.encodeWithSelector(approvedSelectors[i]);
                vm.mockCall(address(sut), abi.encodeWithSelector(approvedSelectors[i]), "");
            }

            notApprovedIndex = bound(notApprovedIndex, 0, approvedSelectors.length - 1);
            calls[notApprovedIndex] = abi.encodeWithSelector(notApprovedSelector);
        }

        vm.expectRevert(abi.encodeWithSelector(CoinbaseSmartWallet.SelectorNotAllowed.selector, notApprovedSelector));
        sut.executeWithoutChainIdValidation(calls);
    }

    function test_executeWithoutChainIdValidation_reverts_whenOneCallReverts(uint256 execRevertIndex)
        external
        withSenderEntryPoint
    {
        // Setup test:
        // 1. Get the list of approved selectors.
        // 2. Build a list of calls from the approved selectors.
        // 3. Do not mock the call at `execRevertIndex` to force it to revert.
        bytes[] memory calls;
        {
            bytes4[] memory approvedSelectors = LibCoinbaseSmartWallet.approvedSelectors();

            calls = new bytes[](approvedSelectors.length);
            execRevertIndex = bound(execRevertIndex, 0, approvedSelectors.length - 1);
            for (uint256 i; i < approvedSelectors.length; i++) {
                calls[i] = abi.encodeWithSelector(approvedSelectors[i]);

                if (execRevertIndex == i) {
                    continue;
                }

                vm.mockCall(address(sut), abi.encodeWithSelector(approvedSelectors[i]), "");
            }
        }

        vm.expectRevert();
        sut.executeWithoutChainIdValidation(calls);
    }

    function test_executeWithoutChainIdValidation_performsTheCalls_whenAllSelectorsAreApproved()
        external
        withSenderEntryPoint
    {
        // Setup test:
        // 1. Get the list of approved selectors.
        // 2. Build a list of calls from the approved selectors.
        bytes[] memory calls;
        {
            bytes4[] memory approvedSelectors = LibCoinbaseSmartWallet.approvedSelectors();

            calls = new bytes[](approvedSelectors.length);
            for (uint256 i; i < approvedSelectors.length; i++) {
                calls[i] = abi.encodeWithSelector(approvedSelectors[i]);
                vm.mockCall({callee: address(sut), data: abi.encodeWithSelector(approvedSelectors[i]), returnData: ""});
            }
        }

        for (uint256 i; i < calls.length; i++) {
            vm.expectCall({callee: address(sut), data: calls[i]});
        }
        sut.executeWithoutChainIdValidation(calls);
    }

    /// @custom:test-section execute

    function test_execute_reverts_whenNotCalledByTheEntryPoint(address target, uint256 value, bytes memory data)
        external
    {
        vm.expectRevert(CoinbaseSmartWallet.Unauthorized.selector);
        sut.execute({target: target, value: value, data: data});
    }

    function test_execute_performsTheCall_whenCalledByTheEntryPoint(address target, uint256 value, bytes memory data)
        external
        withSenderEntryPoint
    {
        // Setup test:
        // 1. Ensure `target` is a reasonable address.
        // 2. Mock the call to not revert.
        // 3. Deal `value` to `sut`.
        {
            target = _sanitizeAddress(target);
            vm.mockCall({callee: target, msgValue: value, data: data, returnData: ""});
            vm.deal({account: address(sut), newBalance: value});
        }

        vm.expectCall({callee: target, msgValue: value, data: data});
        sut.execute({target: target, value: value, data: data});
    }

    /// @custom:test-section executeBatch

    function test_executeBatch_reverts_whenNotCalledByTheEntryPoint(CoinbaseSmartWallet.Call[] memory calls) external {
        // Setup test:
        // 1. Set all `call.data` to a random value based on the already present data.
        {
            for (uint256 i; i < calls.length; i++) {
                CoinbaseSmartWallet.Call memory call = calls[i];

                bytes4 b = bytes4(keccak256(call.data));
                call.data = bytes.concat(b, call.data);
            }
        }

        vm.expectRevert(CoinbaseSmartWallet.Unauthorized.selector);
        sut.executeBatch(calls);
    }

    function test_executeBatch_performsTheCalls_whenCalledByTheEntryPoint(CoinbaseSmartWallet.Call[] memory calls)
        external
        withSenderEntryPoint
    {
        vm.assume(calls.length > 0);

        // Setup test:
        // 1. Set all `call.data` to a random value based on the already present data.
        // 2. Ensure `call.target` is a reasonable address.
        // 3. Ensure `call.value` is reasonable.
        // 4. Mock the call to not revert.
        // 5. Deal the sum of the `call.value` to `sut`.
        {
            uint256 totalValue;
            for (uint256 i; i < calls.length; i++) {
                CoinbaseSmartWallet.Call memory call = calls[i];

                // NOTE: Include `i` in the `call.data` because for some reason `expectCall` does not work when
                //       expecting two exact same calls with only `msg.value` different.
                bytes4 b = bytes4(keccak256(call.data));
                call.data = bytes.concat(b, bytes.concat(call.data, bytes32(i)));
                call.target = _sanitizeAddress(call.target);
                call.value = bound(call.value, 0, 10 * 1e18);

                totalValue += call.value;

                vm.mockCall({callee: call.target, msgValue: call.value, data: call.data, returnData: ""});
            }

            vm.deal({account: address(sut), newBalance: totalValue});
        }

        for (uint256 i; i < calls.length; i++) {
            CoinbaseSmartWallet.Call memory call = calls[i];
            vm.expectCall({callee: call.target, msgValue: call.value, data: call.data});
        }
        sut.executeBatch(calls);
    }

    /// @custom:test-section canSkipChainIdValidation

    function test_canSkipChainIdValidation_shouldReturnFalseForNonApprovedRandomSelectors(bytes4 selector)
        external
        withSenderEntryPoint
    {
        // Setup test:
        // 1. Ensure `selector` is not an approved selector.
        {
            if (LibCoinbaseSmartWallet.isApprovedSelector(selector)) {
                selector = CoinbaseSmartWallet.execute.selector;
            }
        }

        assertFalse(sut.canSkipChainIdValidation(selector));
    }

    function test_canSkipChainIdValidation_shouldReturnFalseForNonApprovedSpecificSelectors()
        external
        withSenderEntryPoint
    {
        assertFalse(sut.canSkipChainIdValidation(CoinbaseSmartWallet.execute.selector));
        assertFalse(sut.canSkipChainIdValidation(CoinbaseSmartWallet.executeBatch.selector));
    }

    function test_canSkipChainIdValidation_shouldReturnTrueForApprovedSelectors() external withSenderEntryPoint {
        assertTrue(sut.canSkipChainIdValidation(UUPSUpgradeable.upgradeToAndCall.selector));
    }

    /// @custom:test-section upgradeToAndCall

    function test_upgradeToAndCall_reverts_whenNotCalledByTheAccountItself(address newImpl, bytes memory data)
        external
    {
        vm.expectRevert(CoinbaseSmartWallet.Unauthorized.selector);
        sut.upgradeToAndCall({newImplementation: newImpl, data: data});
    }

    function test_upgradeToAndCall_setsTheNewImplementation(address newImpl, bytes memory data) external {
        vm.prank(address(sut));

        // Setup test:
        // 1. Ensure `newImpl` is a reasonable address.
        // 2. Mock `newImpl.proxiableUUID` to return the `_ERC1967_IMPLEMENTATION_SLOT`.
        // 3. Set `data` to a random value based on the already present data.
        {
            newImpl = _sanitizeAddress(newImpl);
            vm.mockCall({
                callee: newImpl,
                data: abi.encodeWithSelector(UUPSUpgradeable.proxiableUUID.selector),
                returnData: abi.encode(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)
            });

            bytes4 b = bytes4(keccak256(data));
            data = bytes.concat(b, data);
        }

        sut.upgradeToAndCall({newImplementation: newImpl, data: ""});
        assertEq(LibCoinbaseSmartWallet.readEip1967ImplementationSlot(address(sut)), newImpl);
    }

    /// @custom:test-section implementation

    function test_implementation_returnsTheImplementation() external {
        assertEq(sut.implementation(), address(impl));
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                         TEST HELPERS                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    function _sanitizeAddress(address addr) private view returns (address) {
        addr = address(uint160(bound(uint160(addr), 100, type(uint160).max)));
        if (addr == VM_ADDRESS || addr == CONSOLE || addr == msg.sender) {
            addr = address(0xdead);
        }

        return addr;
    }

    function _setUpTestWrapper_validateUserOp(
        uint256 ksKey,
        CoinbaseSmartWallet.KeyspaceKeyType ksKeyType,
        uint248 privateKey,
        ProofVerificationOutput proofVerifOutput,
        bool isValidSig,
        UserOperation memory userOp
    ) private returns (bytes32 userOpHash) {
        // Setup test:
        // 1. Pick the correct `sigBuilder` method depending on `ksKeyType`.
        // 2. Setup the test for `validateUserOp`.
        // 3. Expect calls to the KeyStore and StateVerifier contracts.
        // 4. If using ERC1271 signature expect calls to `ERC1271.isValidSignature`.

        function (Vm.Wallet memory , bytes32, bool , bytes memory )  returns(bytes memory) sigBuilder;
        if (ksKeyType == CoinbaseSmartWallet.KeyspaceKeyType.WebAuthn) {
            sigBuilder = LibCoinbaseSmartWallet.webAuthnSignature;
        } else if (ksKeyType == CoinbaseSmartWallet.KeyspaceKeyType.Secp256k1) {
            sigBuilder =
                uint256(ksKey) % 2 == 0 ? LibCoinbaseSmartWallet.eoaSignature : LibCoinbaseSmartWallet.eip1271Signature;
        }

        Vm.Wallet memory wallet;
        uint256 stateRoot;
        bytes memory proof;

        (wallet, userOpHash, stateRoot, proof) = _setUpTest_validateUserOp({
            ksKey: ksKey,
            ksKeyType: ksKeyType,
            privateKey: privateKey,
            proofVerifOutput: proofVerifOutput,
            isValidSig: isValidSig,
            sigBuilder: sigBuilder,
            userOp: userOp
        });

        uint256[] memory publicInputs =
            LibCoinbaseSmartWallet.publicInputs({w: wallet, ksKey: ksKey, stateRoot: stateRoot});

        vm.expectCall({callee: keyStore, data: abi.encodeWithSelector(IKeyStore.root.selector)});
        vm.expectCall({callee: stateVerifier, data: abi.encodeCall(IVerifier.Verify, (proof, publicInputs))});

        if (sigBuilder == LibCoinbaseSmartWallet.eip1271Signature) {
            vm.expectCall({callee: wallet.addr, data: abi.encodeWithSelector(ERC1271.isValidSignature.selector)});
        }
    }

    function _setUpTest_validateUserOp(
        uint256 ksKey,
        CoinbaseSmartWallet.KeyspaceKeyType ksKeyType,
        uint248 privateKey,
        ProofVerificationOutput proofVerifOutput,
        bool isValidSig,
        function (Vm.Wallet memory , bytes32, bool , bytes memory )  returns(bytes memory) sigBuilder,
        UserOperation memory userOp
    ) private returns (Vm.Wallet memory wallet, bytes32 userOpHash, uint256 stateRoot, bytes memory proof) {
        // Setup test:
        // 1. Mock `IKeyStore.root` to return 42.
        // 2. Mock `IVerifier.Verify` to return revert, fail or succeed depending on `proofVerifOutput`.
        // 3. Create a Secp256k1 or Secp256r1 wallet depending on `ksKeyType`.
        // 4. Add the `ksKey` as owner of type `ksKeyType`.
        // 5. Set `userOp.nonce` to a valid nonce (with valid key).
        // 6. Set `userOp.signature` to a valid or invalid `signature` of `userOpHash` depending on `isValidSig`.
        //    NOTE: Invalid signatures are still correctly encoded.

        proof = "STATE PROOF";
        stateRoot = 42;

        LibCoinbaseSmartWallet.mockKeyStore({keyStore: keyStore, root: stateRoot});
        if (proofVerifOutput == ProofVerificationOutput.Reverts) {
            LibCoinbaseSmartWallet.mockRevertKeyStateVerifier({
                stateVerifier: stateVerifier,
                revertData: "PROOF REVERTS"
            });
        } else {
            bool isValidProof = proofVerifOutput == ProofVerificationOutput.Succeeds;
            LibCoinbaseSmartWallet.mockStateVerifier({stateVerifier: stateVerifier, value: isValidProof});
        }

        wallet = ksKeyType == CoinbaseSmartWallet.KeyspaceKeyType.WebAuthn
            ? LibCoinbaseSmartWallet.passKeyWallet(privateKey)
            : LibCoinbaseSmartWallet.wallet(privateKey);

        LibCoinbaseSmartWallet.initialize({target: address(sut), ksKey: ksKey, ksKeyType: ksKeyType});

        userOp.nonce = LibCoinbaseSmartWallet.validNonceKey({sut: sut, userOp: userOp});
        userOpHash = LibCoinbaseSmartWallet.hashUserOp({sut: sut, userOp: userOp, forceChainId: false});
        userOp.signature = sigBuilder(wallet, userOpHash, isValidSig, proof);
    }
}
