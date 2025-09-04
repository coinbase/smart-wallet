// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {console2} from "forge-std/Test.sol";
import {SmartWalletTestBase} from "../CoinbaseSmartWallet/SmartWalletTestBase.sol";
import {CoinbaseSmartWallet} from "../../src/CoinbaseSmartWallet.sol";
import {CoinbaseSmartWalletFactory} from "../../src/CoinbaseSmartWalletFactory.sol";
import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";
import {WebAuthn} from "webauthn-sol/WebAuthn.sol";

/// forge-config: default.isolate = true
contract ValidateUserOpTest is SmartWalletTestBase {
    bytes32 constant TEST_HASH = keccak256("test operation");
    CoinbaseSmartWalletFactory factory;
    
    function setUp() public override {
        super.setUp();
        vm.etch(account.entryPoint(), address(new MockEntryPoint()).code);
        
        // Deploy factory
        CoinbaseSmartWallet implementation = new CoinbaseSmartWallet();
        factory = new CoinbaseSmartWalletFactory(address(implementation));
    }
    
    function test_k1() public {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, TEST_HASH);
        UserOperation memory op;
        op.signature = abi.encode(CoinbaseSmartWallet.SignatureWrapper(0, abi.encodePacked(r, s, v)));
        
        vm.startSnapshotGas("validation_k1");
        MockEntryPoint(account.entryPoint()).validateUserOp(address(account), op, TEST_HASH, 0);
        uint256 gasUsed = vm.stopSnapshotGas();
        console2.log("test_k1 gas:", gasUsed);
    }
    
    function test_r1_7212() public {
        // Simulate EIP-7212 precompile support
        bytes[] memory owners = new bytes[](1);
        owners[0] = passkeyOwner;
        CoinbaseSmartWallet passkeyAccount = factory.createAccount(owners, 1);
        
        WebAuthn.WebAuthnAuth memory auth = createWebAuthnAuth();
        UserOperation memory op;
        op.signature = abi.encode(CoinbaseSmartWallet.SignatureWrapper(0, abi.encode(auth)));
        
        // Mock 7212 precompile exists
        vm.etch(address(0x0100), hex"60FF"); // Simple return true
        
        vm.startSnapshotGas("validation_r1_7212");
        MockEntryPoint(account.entryPoint()).validateUserOp(address(passkeyAccount), op, TEST_HASH, 0);
        uint256 gasUsed = vm.stopSnapshotGas();
        console2.log("test_r1_7212 gas:", gasUsed);
    }
    
    function test_r1_FCL() public {
        // Without 7212 precompile - uses FCL library
        bytes[] memory owners = new bytes[](1);
        owners[0] = passkeyOwner;
        CoinbaseSmartWallet passkeyAccount = factory.createAccount(owners, 1);
        
        WebAuthn.WebAuthnAuth memory auth = createWebAuthnAuth();
        UserOperation memory op;
        op.signature = abi.encode(CoinbaseSmartWallet.SignatureWrapper(0, abi.encode(auth)));
        
        vm.startSnapshotGas("validation_r1_FCL");
        MockEntryPoint(account.entryPoint()).validateUserOp(address(passkeyAccount), op, TEST_HASH, 0);
        uint256 gasUsed = vm.stopSnapshotGas();
        console2.log("test_r1_FCL gas:", gasUsed);
    }
    
    function test_k1_replayable() public {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, TEST_HASH);
        UserOperation memory op;
        op.nonce = account.REPLAYABLE_NONCE_KEY() << 64;
        op.callData = abi.encodeCall(CoinbaseSmartWallet.executeWithoutChainIdValidation, (new bytes[](1)));
        op.signature = abi.encode(CoinbaseSmartWallet.SignatureWrapper(0, abi.encodePacked(r, s, v)));
        
        vm.startSnapshotGas("validation_k1_replayable");
        MockEntryPoint(account.entryPoint()).validateUserOp(address(account), op, TEST_HASH, 0);
        uint256 gasUsed = vm.stopSnapshotGas();
        console2.log("test_k1_replayable gas:", gasUsed);
    }
    
    function test_r1_7212_replayable() public {
        bytes[] memory owners = new bytes[](1);
        owners[0] = passkeyOwner;
        CoinbaseSmartWallet passkeyAccount = factory.createAccount(owners, 1);
        
        WebAuthn.WebAuthnAuth memory auth = createWebAuthnAuth();
        UserOperation memory op;
        op.nonce = passkeyAccount.REPLAYABLE_NONCE_KEY() << 64;
        op.callData = abi.encodeCall(CoinbaseSmartWallet.executeWithoutChainIdValidation, (new bytes[](1)));
        op.signature = abi.encode(CoinbaseSmartWallet.SignatureWrapper(0, abi.encode(auth)));
        
        vm.etch(address(0x0100), hex"60FF"); // Mock 7212
        
        vm.startSnapshotGas("validation_r1_7212_replayable");
        MockEntryPoint(account.entryPoint()).validateUserOp(address(passkeyAccount), op, TEST_HASH, 0);
        uint256 gasUsed = vm.stopSnapshotGas();
        console2.log("test_r1_7212_replayable gas:", gasUsed);
    }
    
    function test_r1_FCL_replayable() public {
        bytes[] memory owners = new bytes[](1);
        owners[0] = passkeyOwner;
        CoinbaseSmartWallet passkeyAccount = factory.createAccount(owners, 1);
        
        WebAuthn.WebAuthnAuth memory auth = createWebAuthnAuth();
        UserOperation memory op;
        op.nonce = passkeyAccount.REPLAYABLE_NONCE_KEY() << 64;
        op.callData = abi.encodeCall(CoinbaseSmartWallet.executeWithoutChainIdValidation, (new bytes[](1)));
        op.signature = abi.encode(CoinbaseSmartWallet.SignatureWrapper(0, abi.encode(auth)));
        
        vm.startSnapshotGas("validation_r1_FCL_replayable");
        MockEntryPoint(account.entryPoint()).validateUserOp(address(passkeyAccount), op, TEST_HASH, 0);
        uint256 gasUsed = vm.stopSnapshotGas();
        console2.log("test_r1_FCL_replayable gas:", gasUsed);
    }
    
    function createWebAuthnAuth() internal pure returns (WebAuthn.WebAuthnAuth memory) {
        return WebAuthn.WebAuthnAuth({
            authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000",
            clientDataJSON: '{"type":"webauthn.get","challenge":"',
            challengeIndex: 23,
            typeIndex: 1,
            r: 0x7e7de1a8b53f9fea2e6b2b8f0e564c126a5b3a8f0e1234567890abcdef123456,
            s: 0x3b2a5c8f5e4d6c7b8a9b0c1d2e3f4051627384950617283940516273849506ff
        });
    }
}

contract MockEntryPoint {
    function validateUserOp(address account, UserOperation memory op, bytes32 hash, uint256 funds) 
        external returns (uint256) {
        return CoinbaseSmartWallet(payable(account)).validateUserOp(op, hash, funds);
    }
} 