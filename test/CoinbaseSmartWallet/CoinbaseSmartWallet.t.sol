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
import {MultiOwnable} from "../../src/MultiOwnable.sol";

import {LibCoinbaseSmartWallet} from "../utils/LibCoinbaseSmartWallet.sol";
import {LibMultiOwnable} from "../utils/LibMultiOwnable.sol";

contract CoinbaseSmartWalletTest is Test {
    address private keyStore = makeAddr("KeyStore");
    address private stateVerifier = makeAddr("StateVerifier");

    CoinbaseSmartWallet private impl;
    CoinbaseSmartWallet private sut;

    function setUp() public {
        impl = new CoinbaseSmartWallet({keyStore_: keyStore, stateVerifier_: stateVerifier});

        CoinbaseSmartWalletFactory factory = new CoinbaseSmartWalletFactory(address(impl));
        sut = factory.createAccount({ksKeyAndTypes: LibMultiOwnable.generateKeyAndTypes(1), nonce: 0});
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

    function test_initialize_reverts_whenTheAccountIsAlreadyInitialized(uint8 keyCount) external {
        MultiOwnable.KeyAndType[] memory ksKeyAndTypes = LibMultiOwnable.generateKeyAndTypes(keyCount);

        vm.expectRevert(CoinbaseSmartWallet.Initialized.selector);
        sut.initialize(ksKeyAndTypes);

        assertEq(sut.ownerCount(), 1);
    }

    function test_initialize_initializesTheOwners(uint8 keyCount) external {
        // Setup test:
        // 1. "De-initialize" the implementation.
        {
            LibCoinbaseSmartWallet.uninitialized(address(sut));
        }

        MultiOwnable.KeyAndType[] memory ksKeyAndTypes = LibMultiOwnable.generateKeyAndTypes(keyCount);
        for (uint256 i; i < keyCount; i++) {
            vm.expectEmit(address(sut));
            emit MultiOwnable.OwnerAdded(ksKeyAndTypes[i].ksKey);
        }

        sut.initialize(ksKeyAndTypes);

        assertEq(sut.ownerCount(), keyCount);
    }

    /// @custom:test-section validateUserOp

    function test_validateUserOp_reverts_whenNotCalledByTheEntryPoint(UserOperation memory userOp) external {
        bytes32 userOpHash = LibCoinbaseSmartWallet.hashUserOp({sut: sut, userOp: userOp, forceChainId: true});

        vm.expectRevert(MultiOwnable.Unauthorized.selector);
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

    function test_validateUserOp_reverts_whenTheKsKeyIsNotRegistered(
        UserOperation memory userOp,
        CoinbaseSmartWallet.SignatureWrapper memory sigWrapper
    ) external withSenderEntryPoint {
        // Setup test:
        // 1. Set `userOp.nonce` to a valid nonce (with valid key).
        // 2. Set `userOp.signature` to a correctly formatted but invalid signature.
        {
            userOp.nonce = LibCoinbaseSmartWallet.validNonceKey({sut: sut, userOp: userOp});
            userOp.signature = LibCoinbaseSmartWallet.userOpSignature(sigWrapper);
        }

        bytes32 userOpHash = LibCoinbaseSmartWallet.hashUserOp({sut: sut, userOp: userOp, forceChainId: true});

        vm.expectRevert(abi.encodeWithSelector(CoinbaseSmartWallet.InvalidKeySpaceKey.selector, sigWrapper.ksKey));
        sut.validateUserOp({userOp: userOp, userOpHash: userOpHash, missingAccountFunds: 0});
    }

    function test_validateUserOp_returnsOne_whenSignatureIsInvalid(
        uint256 ksKey,
        uint256 ksKeyType,
        uint248 privateKey,
        UserOperation memory userOp
    ) external withSenderEntryPoint {
        bytes32 userOpHash = _setUpTestWrapper_validateUserOp({
            ksKey: ksKey,
            ksKeyType: ksKeyType,
            privateKey: privateKey,
            isValidSig: false,
            isValidProof: true,
            userOp: userOp
        });

        uint256 validationData = sut.validateUserOp({userOp: userOp, userOpHash: userOpHash, missingAccountFunds: 0});
        assertEq(validationData, 1);
    }

    function test_validateUserOp_returnsOne_whenSignatureIsInvalidButStateProofIsInvalid(
        uint256 ksKey,
        uint256 ksKeyType,
        uint248 privateKey,
        UserOperation memory userOp
    ) external withSenderEntryPoint {
        bytes32 userOpHash = _setUpTestWrapper_validateUserOp({
            ksKey: ksKey,
            ksKeyType: ksKeyType,
            privateKey: privateKey,
            isValidSig: true,
            isValidProof: false,
            userOp: userOp
        });

        uint256 validationData = sut.validateUserOp({userOp: userOp, userOpHash: userOpHash, missingAccountFunds: 0});
        assertEq(validationData, 1);
    }

    function test_validateUserOp_returnsZero_whenSignatureIsValidAndStateProofIsValid(
        uint256 ksKey,
        uint256 ksKeyType,
        uint248 privateKey,
        UserOperation memory userOp
    ) external withSenderEntryPoint {
        bytes32 userOpHash = _setUpTestWrapper_validateUserOp({
            ksKey: ksKey,
            ksKeyType: ksKeyType,
            privateKey: privateKey,
            isValidSig: true,
            isValidProof: true,
            userOp: userOp
        });

        uint256 validationData = sut.validateUserOp({userOp: userOp, userOpHash: userOpHash, missingAccountFunds: 0});
        assertEq(validationData, 0);
    }

    function test_validateUserOp_transferMissingdFundsToEntryPoint_whenSignatureIsValidAndStateProofIsValid(
        uint256 ksKey,
        uint256 ksKeyType,
        uint248 privateKey,
        UserOperation memory userOp,
        uint256 missingAccountFunds
    ) external withSenderEntryPoint {
        bytes32 userOpHash = _setUpTestWrapper_validateUserOp({
            ksKey: ksKey,
            ksKeyType: ksKeyType,
            privateKey: privateKey,
            isValidSig: true,
            isValidProof: true,
            userOp: userOp
        });

        vm.deal({account: address(sut), newBalance: missingAccountFunds});

        sut.validateUserOp({userOp: userOp, userOpHash: userOpHash, missingAccountFunds: missingAccountFunds});

        assertEq(address(sut).balance, 0);
        assertEq(sut.entryPoint().balance, missingAccountFunds);
    }

    /// @custom:test-section executeWithoutChainIdValidation

    function test_executeWithoutChainIdValidation_reverts_whenNotCalledByTheEntryPoint(bytes[] memory calls) external {
        vm.expectRevert(MultiOwnable.Unauthorized.selector);
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
        vm.expectRevert(MultiOwnable.Unauthorized.selector);
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

        vm.expectRevert(MultiOwnable.Unauthorized.selector);
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
        assertTrue(sut.canSkipChainIdValidation(MultiOwnable.addOwner.selector));
        assertTrue(sut.canSkipChainIdValidation(MultiOwnable.removeOwner.selector));
        assertTrue(sut.canSkipChainIdValidation(MultiOwnable.removeLastOwner.selector));
        assertTrue(sut.canSkipChainIdValidation(UUPSUpgradeable.upgradeToAndCall.selector));
    }

    /// @custom:test-section upgradeToAndCall

    function test_upgradeToAndCall_reverts_whenNotCalledByTheAccountItself(address newImpl, bytes memory data)
        external
    {
        vm.expectRevert(MultiOwnable.Unauthorized.selector);
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
        uint256 ksKeyType,
        uint248 privateKey,
        bool isValidSig,
        bool isValidProof,
        UserOperation memory userOp
    ) private returns (bytes32 userOpHash) {
        // Setup test:
        // 1. Pick the correct `sigWrapperDataBuilder` method depending on `ksKeyType`.
        // 2. Setup the test for `validateUserOp`;
        // 3. Expect calls if `isValidSig` is true.

        MultiOwnable.KeyspaceKeyType ksKeyType_ = LibMultiOwnable.uintToKsKeyType({value: ksKeyType, withNone: false});

        function (Vm.Wallet memory , bytes32, bool , bytes memory )  returns(bytes memory) sigWrapperDataBuilder;
        if (ksKeyType_ == MultiOwnable.KeyspaceKeyType.WebAuthn) {
            sigWrapperDataBuilder = LibCoinbaseSmartWallet.webAuthnSignatureWrapperData;
        } else if (ksKeyType_ == MultiOwnable.KeyspaceKeyType.Secp256k1) {
            sigWrapperDataBuilder = uint256(ksKey) % 2 == 0
                ? LibCoinbaseSmartWallet.eoaSignatureWrapperData
                : LibCoinbaseSmartWallet.eip1271SignatureWrapperData;
        }

        Vm.Wallet memory wallet;
        uint256 stateRoot;
        bytes memory proof;

        (wallet, userOpHash, stateRoot, proof) = _setUpTest_validateUserOp({
            ksKey: ksKey,
            ksKeyType: ksKeyType_,
            privateKey: privateKey,
            isValidSig: isValidSig,
            isValidProof: isValidProof,
            sigWrapperDataBuilder: sigWrapperDataBuilder,
            userOp: userOp
        });

        if (sigWrapperDataBuilder == LibCoinbaseSmartWallet.eip1271SignatureWrapperData) {
            vm.expectCall({callee: wallet.addr, data: abi.encodeWithSelector(ERC1271.isValidSignature.selector)});
        }

        if (isValidSig == true) {
            uint256[] memory publicInputs =
                LibCoinbaseSmartWallet.publicInputs({w: wallet, ksKey: ksKey, stateRoot: stateRoot});

            vm.expectCall({callee: keyStore, data: abi.encodeWithSelector(IKeyStore.root.selector)});
            vm.expectCall({callee: stateVerifier, data: abi.encodeCall(IVerifier.Verify, (proof, publicInputs))});
        }
    }

    function _setUpTest_validateUserOp(
        uint256 ksKey,
        MultiOwnable.KeyspaceKeyType ksKeyType,
        uint248 privateKey,
        bool isValidSig,
        bool isValidProof,
        function (Vm.Wallet memory , bytes32, bool , bytes memory )  returns(bytes memory) sigWrapperDataBuilder,
        UserOperation memory userOp
    ) private returns (Vm.Wallet memory wallet, bytes32 userOpHash, uint256 stateRoot, bytes memory proof) {
        // Setup test:
        // 1. Create an Secp256k1/Secp256r1 wallet.
        // 2. Add the owner as `ksKeyType`.
        // 3. Set `userOp.nonce` to a valid nonce (with valid key).
        // 4. Set `userOp.signature` to a valid or invalid `signature` of `userOpHash` depending on `isValidSig`.
        //    NOTE: Invalid signatures are still correctly encoded.
        // 5. Mock `IKeyStore.root` to revert or return 42 depending on `isValidSig`.
        //    NOTE: Reverting ensure `validateUserOp` returns before calling `IKeyStore.root`.
        // 6. If `isValidSig` is true, mock `IVerifier.Verify` to return `isValidProof`.

        wallet = ksKeyType == MultiOwnable.KeyspaceKeyType.WebAuthn
            ? LibCoinbaseSmartWallet.passKeyWallet(privateKey)
            : LibCoinbaseSmartWallet.wallet(privateKey);

        LibMultiOwnable.cheat_AddOwner({target: address(sut), ksKey: ksKey, ksKeyType: ksKeyType});

        userOp.nonce = LibCoinbaseSmartWallet.validNonceKey({sut: sut, userOp: userOp});
        userOpHash = LibCoinbaseSmartWallet.hashUserOp({sut: sut, userOp: userOp, forceChainId: false});

        proof = "STATE PROOF";
        CoinbaseSmartWallet.SignatureWrapper memory sigWrapper = CoinbaseSmartWallet.SignatureWrapper({
            ksKey: ksKey,
            data: sigWrapperDataBuilder(wallet, userOpHash, isValidSig, proof)
        });

        userOp.signature = LibCoinbaseSmartWallet.userOpSignature(sigWrapper);

        if (isValidSig == false) {
            LibCoinbaseSmartWallet.mockRevertKeyStore({keyStore: keyStore, revertData: "SHOULD RETURN FALSE BEFORE"});
        } else {
            stateRoot = 42;
            LibCoinbaseSmartWallet.mockKeyStore({keyStore: keyStore, root: stateRoot});
            LibCoinbaseSmartWallet.mockStateVerifier({stateVerifier: stateVerifier, value: isValidProof});
        }
    }
}
