// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "forge-std/Test.sol";

import {FCL_ecdsa_utils} from "FreshCryptoLib/FCL_ecdsa_utils.sol";
import {FCL_Elliptic_ZZ} from "FreshCryptoLib/FCL_elliptic.sol";
import {UserOperation, UserOperationLib} from "account-abstraction/interfaces/UserOperation.sol";
import {Base64} from "openzeppelin-contracts/contracts/utils/Base64.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {WebAuthn} from "webauthn-sol/WebAuthn.sol";

import {IKeyStore} from "../../src/ext/IKeyStore.sol";
import {IVerifier} from "../../src/ext/IVerifier.sol";

import {CoinbaseSmartWallet} from "../../src/CoinbaseSmartWallet.sol";
import {CoinbaseSmartWalletFactory} from "../../src/CoinbaseSmartWalletFactory.sol";
import {ERC1271} from "../../src/ERC1271.sol";
import {MultiOwnable} from "../../src/MultiOwnable.sol";

contract CoinbaseSmartWalletTest is Test {
    address private keyStore = makeAddr("KeyStore");
    address private stateVerifier = makeAddr("StateVerifier");

    CoinbaseSmartWallet private impl;
    CoinbaseSmartWallet private sut;

    function setUp() public {
        impl = new CoinbaseSmartWallet({keyStore_: keyStore, stateVerifier_: stateVerifier});

        CoinbaseSmartWalletFactory factory = new CoinbaseSmartWalletFactory(address(impl));
        sut = factory.createAccount({ksKeyAndTypes: _generateKeyAndTypes(1), nonce: 0});
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
        MultiOwnable.KeyAndType[] memory ksKeyAndTypes = _generateKeyAndTypes(keyCount);

        vm.expectRevert(CoinbaseSmartWallet.Initialized.selector);
        sut.initialize(ksKeyAndTypes);

        assertEq(sut.ownerCount(), 1);
    }

    function test_initialize_initializesTheOwners(uint8 keyCount) external {
        // Setup test:
        // 1. "De-initialize" the implementation.
        {
            _uninitialized();
        }

        MultiOwnable.KeyAndType[] memory ksKeyAndTypes = _generateKeyAndTypes(keyCount);
        for (uint256 i; i < keyCount; i++) {
            vm.expectEmit(address(sut));
            emit MultiOwnable.OwnerAdded(ksKeyAndTypes[i].ksKey);
        }

        sut.initialize(ksKeyAndTypes);

        assertEq(sut.ownerCount(), keyCount);
    }

    /// @custom:test-section validateUserOp

    function test_validateUserOp_reverts_whenNotCalledByTheEntryPoint(UserOperation memory userOp) external {
        bytes32 userOpHash = _hashUserOp({userOp: userOp, forceChainId: true});

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

        bytes32 userOpHash = _hashUserOp({userOp: userOp, forceChainId: true});

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

        bytes32 userOpHash = _hashUserOp({userOp: userOp, forceChainId: true});

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
            userOp.nonce = _validNonceKey(userOp);
            userOp.signature = _userOpSignature(sigWrapper);
        }

        bytes32 userOpHash = _hashUserOp({userOp: userOp, forceChainId: true});

        vm.expectRevert(abi.encodeWithSelector(CoinbaseSmartWallet.InvalidKeySpaceKey.selector, sigWrapper.ksKey));
        sut.validateUserOp({userOp: userOp, userOpHash: userOpHash, missingAccountFunds: 0});
    }

    function test_validateUserOp_returnsOne_whenEOASignatureIsInvalid(
        uint248 privateKey,
        UserOperation memory userOp,
        CoinbaseSmartWallet.SignatureWrapper memory sigWrapper
    ) external withSenderEntryPoint {
        // Setup test:
        // 1. Create an EOA owner.
        // 2. Add the owner as `MultiOwnable.KeyspaceKeyType.Secp256k1`.
        // 3. Set `userOp.nonce` to a valid nonce (with valid key).
        // 4. Set `userOp.signature` to a correctly formatted but invalid signature.
        // 5. Mock `IKeyStore.root` to revert if called (as the function should return before).
        bytes32 userOphash;
        {
            Vm.Wallet memory wallet = _wallet(privateKey);
            _addOwner(sigWrapper.ksKey, MultiOwnable.KeyspaceKeyType.Secp256k1);

            userOp.nonce = _validNonceKey(userOp);
            userOphash = _hashUserOp({userOp: userOp, forceChainId: false});
            sigWrapper.data = _eoaSignatureWrapperData({
                wallet: wallet,
                userOpHash: userOphash,
                validSig: false,
                stateProof: "DON'T CARE"
            });
            userOp.signature = _userOpSignature(sigWrapper);

            _mockRevertKeyStore("SHOULD RETURN FALSE BEFORE");
        }

        uint256 validationData = sut.validateUserOp({userOp: userOp, userOpHash: userOphash, missingAccountFunds: 0});
        assertEq(validationData, 1);
    }

    function test_validateUserOp_returnsOne_whenEip1271SignatureIsInvalid(
        uint248 privateKey,
        UserOperation memory userOp,
        CoinbaseSmartWallet.SignatureWrapper memory sigWrapper
    ) external withSenderEntryPoint {
        // Setup test:
        // 1. Create an EIP1271 contract owner.
        // 2. Add the owner as `MultiOwnable.KeyspaceKeyType.Secp256k1`.
        // 3. Set `userOp.nonce` to a valid nonce (with valid key).
        // 4. Set `userOp.signature` to a correctly formatted but invalid signature.
        // 5. Mock `IKeyStore.root` to revert if called (as the function should return before).
        Vm.Wallet memory eip1271Contract;
        bytes32 userOphash;
        {
            eip1271Contract = _wallet(privateKey);
            _addOwner(sigWrapper.ksKey, MultiOwnable.KeyspaceKeyType.Secp256k1);

            userOp.nonce = _validNonceKey(userOp);
            userOphash = _hashUserOp({userOp: userOp, forceChainId: false});
            sigWrapper.data = _eip1271SignatureWrapperData({
                wallet: eip1271Contract,
                userOpHash: userOphash,
                validSig: false,
                stateProof: "DON'T CARE"
            });
            userOp.signature = _userOpSignature(sigWrapper);

            _mockRevertKeyStore("SHOULD RETURN FALSE BEFORE");
        }

        vm.expectCall({callee: eip1271Contract.addr, data: abi.encodeWithSelector(ERC1271.isValidSignature.selector)});
        uint256 validationData = sut.validateUserOp({userOp: userOp, userOpHash: userOphash, missingAccountFunds: 0});
        assertEq(validationData, 1);
    }

    function test_validateUserOp_returnsOne_whenWebAuthnSignatureIsInvalid(
        uint248 privateKey,
        UserOperation memory userOp,
        CoinbaseSmartWallet.SignatureWrapper memory sigWrapper
    ) external withSenderEntryPoint {
        // Setup test:
        // 1. Create a PassKey owner.
        // 2. Add the owner as `MultiOwnable.KeyspaceKeyType.WebAuthn`.
        // 3. Set `userOp.nonce` to a valid nonce (with valid key).
        // 4. Set `userOp.signature` to a correctly formatted but invalid signature.
        // 5. Mock `IKeyStore.root` to revert if called (as the function should return before).
        bytes32 userOphash;
        {
            Vm.Wallet memory passKeyWallet = _passKeyWallet(privateKey);
            _addOwner(sigWrapper.ksKey, MultiOwnable.KeyspaceKeyType.WebAuthn);

            userOp.nonce = _validNonceKey(userOp);
            userOphash = _hashUserOp({userOp: userOp, forceChainId: false});
            sigWrapper.data = _webAuthnSignatureWrapperData({
                passKeyWallet: passKeyWallet,
                userOpHash: userOphash,
                validSig: false,
                stateProof: "DON'T CARE"
            });
            userOp.signature = _userOpSignature(sigWrapper);

            _mockRevertKeyStore("SHOULD RETURN FALSE BEFORE");
        }

        uint256 validationData = sut.validateUserOp({userOp: userOp, userOpHash: userOphash, missingAccountFunds: 0});
        assertEq(validationData, 1);
    }

    function test_validateUserOp_queriesTheStateRoot_whenEOASignatureIsValid(
        uint248 privateKey,
        UserOperation memory userOp,
        CoinbaseSmartWallet.SignatureWrapper memory sigWrapper
    ) external withSenderEntryPoint {
        // Setup test:
        // 1. Create an EOA owner.
        // 2. Add the owner as `MultiOwnable.KeyspaceKeyType.Secp256k1`.
        // 3. Set `userOp.nonce` to a valid nonce (with valid key).
        // 4. Set `userOp.signature` to a valid signature.
        // 5. Mock `IKeyStore.root` to return 42.
        // 6. Mock `IVerifier.Verify` to return false.
        bytes32 userOpHash;
        {
            Vm.Wallet memory wallet = _wallet(privateKey);
            _addOwner(sigWrapper.ksKey, MultiOwnable.KeyspaceKeyType.Secp256k1);

            userOp.nonce = _validNonceKey(userOp);
            userOpHash = _hashUserOp({userOp: userOp, forceChainId: false});
            sigWrapper.data = _eoaSignatureWrapperData({
                wallet: wallet,
                userOpHash: userOpHash,
                validSig: true,
                stateProof: "DON'T CARE"
            });
            userOp.signature = _userOpSignature(sigWrapper);

            _mockKeyStore(42);
            _mockStateVerifier(false);
        }

        vm.expectCall({callee: keyStore, data: abi.encodeWithSelector(IKeyStore.root.selector)});
        sut.validateUserOp({userOp: userOp, userOpHash: userOpHash, missingAccountFunds: 0});
    }

    function test_validateUserOp_queriesTheStateRoot_whenEip1271SignatureIsValid(
        uint248 privateKey,
        UserOperation memory userOp,
        CoinbaseSmartWallet.SignatureWrapper memory sigWrapper
    ) external withSenderEntryPoint {
        // Setup test:
        // 1. Create an EIP1271 contract owner.
        // 2. Add the owner as `MultiOwnable.KeyspaceKeyType.Secp256k1`.
        // 3. Set `userOp.nonce` to a valid nonce (with valid key).
        // 4. Set `userOp.signature` to a valid signature.
        // 5. Mock `IKeyStore.root` to return 42.
        // 6. Mock `IVerifier.Verify` to return false.
        Vm.Wallet memory eip1271Contract;
        bytes32 userOpHash;
        {
            eip1271Contract = _wallet(privateKey);
            _addOwner(sigWrapper.ksKey, MultiOwnable.KeyspaceKeyType.Secp256k1);

            userOp.nonce = _validNonceKey(userOp);
            userOpHash = _hashUserOp({userOp: userOp, forceChainId: false});
            sigWrapper.data = _eip1271SignatureWrapperData({
                wallet: eip1271Contract,
                userOpHash: userOpHash,
                validSig: true,
                stateProof: "DON'T CARE"
            });
            userOp.signature = _userOpSignature(sigWrapper);

            _mockKeyStore(42);
            _mockStateVerifier(false);
        }

        vm.expectCall({callee: eip1271Contract.addr, data: abi.encodeWithSelector(ERC1271.isValidSignature.selector)});
        vm.expectCall({callee: keyStore, data: abi.encodeWithSelector(IKeyStore.root.selector)});
        sut.validateUserOp({userOp: userOp, userOpHash: userOpHash, missingAccountFunds: 0});
    }

    function test_validateUserOp_queriesTheStateRoot_whenWebAuthnSignatureIsValid(
        uint248 privateKey,
        UserOperation memory userOp,
        CoinbaseSmartWallet.SignatureWrapper memory sigWrapper
    ) external withSenderEntryPoint {
        // Setup test:
        // 1. Create PassKey owner.
        // 2. Add the owner as `MultiOwnable.KeyspaceKeyType.WebAuthn`.
        // 3. Set `userOp.nonce` to a valid nonce (with valid key).
        // 4. Set `userOp.signature` to a valid signature.
        // 5. Mock `IKeyStore.root` to return 42.
        // 6. Mock `IVerifier.Verify` to return false.
        bytes32 userOpHash;
        {
            Vm.Wallet memory passKeyWallet = _passKeyWallet(privateKey);
            _addOwner(sigWrapper.ksKey, MultiOwnable.KeyspaceKeyType.WebAuthn);

            userOp.nonce = _validNonceKey(userOp);
            userOpHash = _hashUserOp({userOp: userOp, forceChainId: false});
            sigWrapper.data = _webAuthnSignatureWrapperData({
                passKeyWallet: passKeyWallet,
                userOpHash: userOpHash,
                validSig: true,
                stateProof: "DON'T CARE"
            });
            userOp.signature = _userOpSignature(sigWrapper);

            _mockKeyStore(42);
            _mockStateVerifier(false);
        }

        vm.expectCall({callee: keyStore, data: abi.encodeWithSelector(IKeyStore.root.selector)});
        sut.validateUserOp({userOp: userOp, userOpHash: userOpHash, missingAccountFunds: 0});
    }

    function test_validateUserOp_returnsTheStateVerifierResult_whenEOASignatureIsValid(
        uint248 privateKey,
        UserOperation memory userOp,
        CoinbaseSmartWallet.SignatureWrapper memory sigWrapper
    ) external withSenderEntryPoint {
        // Setup test:
        // 1. Create an EOA owner.
        // 2. Add the owner as `MultiOwnable.KeyspaceKeyType.Secp256k1`.
        // 3. Set `userOp.nonce` to a valid nonce (with valid key).
        // 4. Set `userOp.signature` to a valid signature.
        // 5. Mock `IKeyStore.root` to return 42.
        Vm.Wallet memory wallet;
        uint256 stateRoot = 42;
        bytes memory stateProof = "STATE PROOF";
        bytes32 userOpHash;
        {
            wallet = _wallet(privateKey);
            _addOwner(sigWrapper.ksKey, MultiOwnable.KeyspaceKeyType.Secp256k1);

            userOp.nonce = _validNonceKey(userOp);
            userOpHash = _hashUserOp({userOp: userOp, forceChainId: false});
            sigWrapper.data = _eoaSignatureWrapperData({
                wallet: wallet,
                userOpHash: userOpHash,
                validSig: true,
                stateProof: stateProof
            });
            userOp.signature = _userOpSignature(sigWrapper);

            _mockKeyStore(stateRoot);
        }

        uint256[] memory publicInputs = _publicInputs({wallet: wallet, sigWrapper: sigWrapper, stateRoot: stateRoot});

        // Test case where the Verifier reject the proof.
        _mockStateVerifier(false);
        vm.expectCall({callee: stateVerifier, data: abi.encodeCall(IVerifier.Verify, (stateProof, publicInputs))});
        uint256 validationData = sut.validateUserOp({userOp: userOp, userOpHash: userOpHash, missingAccountFunds: 0});
        assertEq(validationData, 1);

        // Test case where the Verifier accept the proof.
        _mockStateVerifier(true);
        vm.expectCall({callee: stateVerifier, data: abi.encodeCall(IVerifier.Verify, (stateProof, publicInputs))});
        validationData = sut.validateUserOp({userOp: userOp, userOpHash: userOpHash, missingAccountFunds: 0});
        assertEq(validationData, 0);
    }

    function test_validateUserOp_returnsTheStateVerifierResult_whenEip1271SignatureIsValid(
        uint248 privateKey,
        UserOperation memory userOp,
        CoinbaseSmartWallet.SignatureWrapper memory sigWrapper
    ) external withSenderEntryPoint {
        // Setup test:
        // 1. Create an EIP1271 contract owner.
        // 2. Add the owner as `MultiOwnable.KeyspaceKeyType.Secp256k1`.
        // 3. Set `userOp.nonce` to a valid nonce (with valid key).
        // 4. Set `userOp.signature` to a valid signature.
        // 5. Mock `IKeyStore.root` to return 42.
        Vm.Wallet memory eip1271Contract;
        uint256 stateRoot = 42;
        bytes memory stateProof = "STATE PROOF";
        bytes32 userOpHash;
        {
            eip1271Contract = _wallet(privateKey);
            _addOwner(sigWrapper.ksKey, MultiOwnable.KeyspaceKeyType.Secp256k1);

            userOp.nonce = _validNonceKey(userOp);
            userOpHash = _hashUserOp({userOp: userOp, forceChainId: false});
            sigWrapper.data = _eip1271SignatureWrapperData({
                wallet: eip1271Contract,
                userOpHash: userOpHash,
                validSig: true,
                stateProof: stateProof
            });
            userOp.signature = _userOpSignature(sigWrapper);

            _mockKeyStore(stateRoot);
        }

        uint256[] memory publicInputs =
            _publicInputs({wallet: eip1271Contract, sigWrapper: sigWrapper, stateRoot: stateRoot});

        // Test case where the Verifier reject the proof.
        _mockStateVerifier(false);
        vm.expectCall({callee: stateVerifier, data: abi.encodeCall(IVerifier.Verify, (stateProof, publicInputs))});
        uint256 validationData = sut.validateUserOp({userOp: userOp, userOpHash: userOpHash, missingAccountFunds: 0});
        assertEq(validationData, 1);

        // Test case where the Verifier accept the proof.
        _mockStateVerifier(true);
        vm.expectCall({callee: stateVerifier, data: abi.encodeCall(IVerifier.Verify, (stateProof, publicInputs))});
        validationData = sut.validateUserOp({userOp: userOp, userOpHash: userOpHash, missingAccountFunds: 0});
        assertEq(validationData, 0);
    }

    function test_validateUserOp_returnsTheStateVerifierResult_whenWebAuthnSignatureIsValid(
        uint248 privateKey,
        UserOperation memory userOp,
        CoinbaseSmartWallet.SignatureWrapper memory sigWrapper
    ) external withSenderEntryPoint {
        // Setup test:
        // 1. Create PassKey owner.
        // 2. Add the owner as `MultiOwnable.KeyspaceKeyType.WebAuthn`.
        // 3. Set `userOp.nonce` to a valid nonce (with valid key).
        // 4. Set `userOp.signature` to a valid signature.
        // 5. Mock `IKeyStore.root` to return 42.
        Vm.Wallet memory passKeyWallet;
        uint256 stateRoot = 42;
        bytes memory stateProof = "STATE PROOF";
        bytes32 userOpHash;
        {
            passKeyWallet = _passKeyWallet(privateKey);
            _addOwner(sigWrapper.ksKey, MultiOwnable.KeyspaceKeyType.WebAuthn);

            userOp.nonce = _validNonceKey(userOp);
            userOpHash = _hashUserOp({userOp: userOp, forceChainId: false});
            sigWrapper.data = _webAuthnSignatureWrapperData({
                passKeyWallet: passKeyWallet,
                userOpHash: userOpHash,
                validSig: true,
                stateProof: stateProof
            });
            userOp.signature = _userOpSignature(sigWrapper);

            _mockKeyStore(stateRoot);
        }

        uint256[] memory publicInputs =
            _publicInputs({wallet: passKeyWallet, sigWrapper: sigWrapper, stateRoot: stateRoot});

        // Test case where the Verifier reject the proof.
        _mockStateVerifier(false);
        vm.expectCall({callee: stateVerifier, data: abi.encodeCall(IVerifier.Verify, (stateProof, publicInputs))});
        uint256 validationData = sut.validateUserOp({userOp: userOp, userOpHash: userOpHash, missingAccountFunds: 0});
        assertEq(validationData, 1);

        // Test case where the Verifier accept the proof.
        _mockStateVerifier(true);
        vm.expectCall({callee: stateVerifier, data: abi.encodeCall(IVerifier.Verify, (stateProof, publicInputs))});
        validationData = sut.validateUserOp({userOp: userOp, userOpHash: userOpHash, missingAccountFunds: 0});
        assertEq(validationData, 0);
    }

    function test_validateUserOp_transferMissingdFundsToEntryPoint_whenSignatureIsValid(
        uint248 privateKey,
        UserOperation memory userOp,
        CoinbaseSmartWallet.SignatureWrapper memory sigWrapper,
        uint256 missingAccountFunds
    ) external withSenderEntryPoint {
        // Setup test:
        // 1. Create PassKey owner.
        // 2. Add the owner as `MultiOwnable.KeyspaceKeyType.WebAuthn`.
        // 3. Set `userOp.nonce` to a valid nonce (with valid key).
        // 4. Set `userOp.signature` to a valid signature.
        // 5. Mock `IKeyStore.root` to return 42.
        // 6. Mock `IVerifier.Verify` to return true.
        bytes32 userOpHash;
        {
            Vm.Wallet memory wallet = _wallet(privateKey);
            _addOwner(sigWrapper.ksKey, MultiOwnable.KeyspaceKeyType.Secp256k1);

            userOp.nonce = _validNonceKey(userOp);
            userOpHash = _hashUserOp({userOp: userOp, forceChainId: false});
            sigWrapper.data = _eoaSignatureWrapperData({
                wallet: wallet,
                userOpHash: userOpHash,
                validSig: true,
                stateProof: "STATE PROOF"
            });
            userOp.signature = _userOpSignature(sigWrapper);

            _mockKeyStore(42);
            _mockStateVerifier(true);

            vm.deal({account: address(sut), newBalance: missingAccountFunds});
        }

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

            if (_isApprovedSelector(selector)) {
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
            bytes4[] memory notApprovedSelectors = _notApprovedSelectors();
            notApprovedSelector = notApprovedSelectors[notApprovedIndex % (notApprovedSelectors.length)];

            bytes4[] memory approvedSelectors = _approvedSelectors();

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
            bytes4[] memory approvedSelectors = _approvedSelectors();

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
            bytes4[] memory approvedSelectors = _approvedSelectors();

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
            if (_isApprovedSelector(selector)) {
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

        sut.upgradeToAndCall({newImplementation: newImpl, data: data});
        assertEq(_readEip1967ImplementationSlot(), newImpl);
    }

    /// @custom:test-section implementation

    function test_implementation_returnsTheImplementation() external {
        assertEq(sut.implementation(), address(impl));
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                         MOCK HELPERS                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    function _uninitialized() private {
        vm.store(address(sut), _MUTLI_OWNABLE_STORAGE_LOCATION(), bytes32(0));
    }

    function _readEip1967ImplementationSlot() private view returns (address) {
        return address(
            uint160(
                uint256(
                    vm.load({
                        target: address(sut),
                        slot: 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
                    })
                )
            )
        );
    }

    function _addOwner(uint256 ksKey, MultiOwnable.KeyspaceKeyType ksKeyType) private {
        bytes32 slot = _MUTLI_OWNABLE_STORAGE_LOCATION();

        // Set `ownerCount += 1`;
        uint256 ownerCount = sut.ownerCount();
        vm.store(address(sut), slot, bytes32(ownerCount + 1));

        // Set `ksKeyTypes[ksKey] = ksKeyType`;
        slot = bytes32(uint256(slot) + 1);
        slot = keccak256(abi.encode(ksKey, slot));
        vm.store(address(sut), slot, bytes32(uint256(ksKeyType)));
    }

    function _mockEip1271(address signer, bool isValid) private {
        bytes memory res = abi.encode(isValid ? bytes4(0x1626ba7e) : bytes4(0xffffffff));
        vm.mockCall({callee: signer, data: abi.encodeWithSelector(ERC1271.isValidSignature.selector), returnData: res});
    }

    function _mockKeyStore(uint256 root) private {
        vm.mockCall({
            callee: keyStore,
            data: abi.encodeWithSelector(IKeyStore.root.selector),
            returnData: abi.encode(root)
        });
    }

    function _mockRevertKeyStore(bytes memory revertData) private {
        vm.mockCallRevert({
            callee: keyStore,
            data: abi.encodeWithSelector(IKeyStore.root.selector),
            revertData: revertData
        });
    }

    function _mockStateVerifier(bool value) private {
        vm.mockCall({
            callee: stateVerifier,
            data: abi.encodeWithSelector(IVerifier.Verify.selector),
            returnData: abi.encode(value)
        });
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                         TEST HELPERS                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    function _MUTLI_OWNABLE_STORAGE_LOCATION() private pure returns (bytes32) {
        return 0x97e2c6aad4ce5d562ebfaa00db6b9e0fb66ea5d8162ed5b243f51a2e03086f00;
    }

    function _sanitizeAddress(address addr) private pure returns (address) {
        addr = address(uint160(bound(uint160(addr), 100, type(uint160).max)));
        if (addr == VM_ADDRESS || addr == CONSOLE) {
            addr = address(0xdead);
        }

        return addr;
    }

    function _generateKeyAndTypes(uint256 count)
        private
        pure
        returns (MultiOwnable.KeyAndType[] memory ksKeyAndTypes)
    {
        uint256 startKey = uint256(keccak256("start-key")) - 1;
        uint256 startKeyType = uint256(keccak256("start-key-type")) - 1;

        ksKeyAndTypes = new MultiOwnable.KeyAndType[](count);

        for (uint256 i; i < count; i++) {
            uint256 ksKey = startKey + i;
            uint256 ksKeyType = startKeyType + i;

            ksKeyAndTypes[i] = MultiOwnable.KeyAndType({ksKey: ksKey, ksKeyType: _uintToKsKeyType(ksKeyType)});
        }
    }

    function _uintToKsKeyType(uint256 value) private pure returns (MultiOwnable.KeyspaceKeyType) {
        value = value % 2;
        return MultiOwnable.KeyspaceKeyType(value + 1);
    }

    function _hashUserOp(UserOperation memory userOp, bool forceChainId) private view returns (bytes32) {
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

    function _wallet(uint256 privateKey) private returns (Vm.Wallet memory wallet) {
        if (privateKey == 0) {
            privateKey = 1;
        }

        wallet = vm.createWallet(privateKey, "Wallet");
    }

    function _passKeyWallet(uint256 privateKey) private view returns (Vm.Wallet memory passKeyWallet) {
        if (privateKey == 0) {
            privateKey = 1;
        }

        passKeyWallet.addr = address(0xdead);
        passKeyWallet.privateKey = privateKey;
        (passKeyWallet.publicKeyX, passKeyWallet.publicKeyY) = FCL_ecdsa_utils.ecdsa_derivKpub(privateKey);
    }

    function _validNonceKey(UserOperation memory userOp) private view returns (uint256 nonce) {
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

    function _userOpSignature(CoinbaseSmartWallet.SignatureWrapper memory sigWrapper)
        private
        pure
        returns (bytes memory)
    {
        return abi.encode(sigWrapper);
    }

    function _eoaSignatureWrapperData(
        Vm.Wallet memory wallet,
        bytes32 userOpHash,
        bool validSig,
        bytes memory stateProof
    ) private returns (bytes memory sigData) {
        uint8 v;
        bytes32 r;
        bytes32 s;
        bytes memory sig = bytes("invalid by default");
        if (validSig) {
            (v, r, s) = vm.sign(wallet, userOpHash);
        }

        sig = abi.encodePacked(r, s, v);
        sigData = abi.encode(sig, wallet.publicKeyX, wallet.publicKeyY, stateProof);
    }

    function _eip1271SignatureWrapperData(
        Vm.Wallet memory wallet,
        bytes32 userOpHash,
        bool validSig,
        bytes memory stateProof
    ) private returns (bytes memory sigData) {
        bytes memory sig = bytes.concat("CUSTOM EIP1271 SIGNATURE: ", userOpHash);
        sigData = abi.encode(sig, wallet.publicKeyX, wallet.publicKeyY, stateProof);

        _mockEip1271({signer: wallet.addr, isValid: validSig});
    }

    function _webAuthnSignatureWrapperData(
        Vm.Wallet memory passKeyWallet,
        bytes32 userOpHash,
        bool validSig,
        bytes memory stateProof
    ) private pure returns (bytes memory sigData) {
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
            (bytes32 r, bytes32 s) = vm.signP256(passKeyWallet.privateKey, h);
            if (uint256(s) > (FCL_Elliptic_ZZ.n / 2)) {
                s = bytes32(FCL_Elliptic_ZZ.n - uint256(s));
            }
            webAuthn.r = uint256(r);
            webAuthn.s = uint256(s);
        }

        bytes memory sig = abi.encode(webAuthn);
        sigData = abi.encode(sig, passKeyWallet.publicKeyX, passKeyWallet.publicKeyY, stateProof);
    }

    function _publicInputs(
        Vm.Wallet memory wallet,
        CoinbaseSmartWallet.SignatureWrapper memory sigWrapper,
        uint256 stateRoot
    ) private pure returns (uint256[] memory publicInputs) {
        // Verify the state proof.
        uint256[] memory data = new uint256[](8);
        data[0] = wallet.publicKeyX;
        data[1] = wallet.publicKeyY;

        publicInputs = new uint256[](3);
        publicInputs[0] = sigWrapper.ksKey;
        publicInputs[1] = stateRoot;
        publicInputs[2] = uint256(keccak256(abi.encodePacked(data)) >> 8);
    }

    function _isApprovedSelector(bytes4 selector) private pure returns (bool) {
        return selector == MultiOwnable.addOwner.selector || selector == MultiOwnable.removeOwner.selector
            || selector == MultiOwnable.removeLastOwner.selector || selector == UUPSUpgradeable.upgradeToAndCall.selector;
    }

    function _approvedSelectors() private pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](4);
        selectors[0] = MultiOwnable.addOwner.selector;
        selectors[1] = MultiOwnable.removeOwner.selector;
        selectors[2] = MultiOwnable.removeLastOwner.selector;
        selectors[3] = UUPSUpgradeable.upgradeToAndCall.selector;
    }

    function _notApprovedSelectors() private pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](2);
        selectors[0] = CoinbaseSmartWallet.execute.selector;
        selectors[1] = CoinbaseSmartWallet.executeBatch.selector;
    }
}
