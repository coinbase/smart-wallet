// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {console2} from "forge-std/Test.sol";
import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";

import {CoinbaseSmartWallet} from "../../src/CoinbaseSmartWallet.sol";
import {CoinbaseSmartWalletFactory} from "../../src/CoinbaseSmartWalletFactory.sol";
import {MockERC20} from "../../lib/solady/test/utils/mocks/MockERC20.sol";

import {MockTarget} from "../mocks/MockTarget.sol";
import {SmartWalletTestBase} from "../CoinbaseSmartWallet/SmartWalletTestBase.sol";
import {Static} from "../CoinbaseSmartWallet/Static.sol";

/// @title EndToEndTest
/// @notice Gas comparison tests between ERC-4337 Base Account and EOA transactions
/// @dev Isolated test contract to measure gas consumption for common operations
/// Tests ran using `FOUNDRY_PROFILE=deploy` to simulate real-world gas costs
/// forge-config: default.isolate = true
contract EndToEndTest is SmartWalletTestBase {
    address eoaUser = address(0xe0a);
    MockERC20 usdc;
    MockTarget target;
    CoinbaseSmartWalletFactory factory;

    function setUp() public override {
        // Deploy EntryPoint at canonical address
        vm.etch(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789, Static.ENTRY_POINT_BYTES);

        // Deploy smart wallet infrastructure
        CoinbaseSmartWallet implementation = new CoinbaseSmartWallet();
        factory = new CoinbaseSmartWalletFactory(address(implementation));

        // Configure wallet owner
        signerPrivateKey = 0xa11ce;
        signer = vm.addr(signerPrivateKey);
        owners.push(abi.encode(signer));
        account = factory.createAccount(owners, 0);

        // Fund wallets with ETH
        vm.deal(address(account), 100 ether);
        vm.deal(eoaUser, 100 ether);

        // Deploy and mint USDC tokens
        usdc = new MockERC20("USD Coin", "USDC", 6);
        usdc.mint(address(account), 10000e6);
        usdc.mint(eoaUser, 10000e6);

        target = new MockTarget();
    }
    
    // Native ETH Transfer - Base Account
    function test_transfer_native_baseAccount() public {
        // Dust recipient to avoid gas changes for first non-zero balance
        vm.deal(address(0x1234), 1 wei);
        
        // Prepare UserOperation for native ETH transfer
        userOpCalldata = abi.encodeCall(CoinbaseSmartWallet.execute, (address(0x1234), 1 ether, ""));
        UserOperation memory op = _getUserOpWithSignature();

        // Measure calldata size
        bytes memory handleOpsCalldata = abi.encodeCall(entryPoint.handleOps, (_makeOpsArray(op), payable(bundler)));
        console2.log("test_transfer_native Base Account calldata size:", handleOpsCalldata.length);

        // Execute and measure gas
        vm.startSnapshotGas("e2e_transfer_native_baseAccount");
        _sendUserOperation(op);
        uint256 gasUsed = vm.stopSnapshotGas();
        console2.log("test_transfer_native Base Account gas:", gasUsed);
    }

    // Native ETH Transfer - EOA
    function test_transfer_native_eoa() public {
        // Dust recipient to avoid gas changes for first non-zero balance
        vm.deal(address(0x1234), 1 wei);
        
        console2.log("test_transfer_native EOA calldata size:", uint256(0));

        // Execute and measure gas
        vm.prank(eoaUser);
        vm.startSnapshotGas("e2e_transfer_native_eoa");
        payable(address(0x1234)).transfer(1 ether);
        uint256 gasUsed = vm.stopSnapshotGas();
        console2.log("test_transfer_native EOA gas:", gasUsed);
    }
    
    // ERC20 Transfer - Base Account
    function test_transfer_erc20_baseAccount() public {
        // Dust recipient to avoid gas changes for first non-zero balance
        vm.deal(address(0x5678), 1 wei);
        usdc.mint(address(0x5678), 1 wei);

        // Prepare UserOperation for ERC20 transfer
        userOpCalldata = abi.encodeCall(
            CoinbaseSmartWallet.execute, (address(usdc), 0, abi.encodeCall(usdc.transfer, (address(0x5678), 100e6)))
        );
        UserOperation memory op = _getUserOpWithSignature();

        // Measure calldata size
        bytes memory handleOpsCalldata = abi.encodeCall(entryPoint.handleOps, (_makeOpsArray(op), payable(bundler)));
        console2.log("test_transfer_erc20 Base Account calldata size:", handleOpsCalldata.length);

        // Execute and measure gas
        vm.startSnapshotGas("e2e_transfer_erc20_baseAccount");
        _sendUserOperation(op);
        uint256 gasUsed = vm.stopSnapshotGas();
        console2.log("test_transfer_erc20 Base Account gas:", gasUsed);
    }

    // ERC20 Transfer - EOA
    function test_transfer_erc20_eoa() public {
        // Dust recipient to avoid gas changes for first non-zero balance
        vm.deal(address(0x5678), 1 wei);
        usdc.mint(address(0x5678), 1 wei);
        
        // Measure calldata size
        bytes memory eoaCalldata = abi.encodeCall(usdc.transfer, (address(0x5678), 100e6));
        console2.log("test_transfer_erc20 EOA calldata size:", eoaCalldata.length);

        // Execute and measure gas
        vm.prank(eoaUser);
        vm.startSnapshotGas("e2e_transfer_erc20_eoa");
        usdc.transfer(address(0x5678), 100e6);
        uint256 gasUsed = vm.stopSnapshotGas();
        console2.log("test_transfer_erc20 EOA gas:", gasUsed);
    }

    // Helper Functions
    // Creates an array containing a single UserOperation
    function _makeOpsArray(UserOperation memory op) internal pure returns (UserOperation[] memory) {
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        return ops;
    }

    // Signs a UserOperation with the configured signer
    // Overrides the parent implementation to use the configured signer
    function _sign(UserOperation memory userOp) internal view override returns (bytes memory signature) {
        bytes32 toSign = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, toSign);
        signature = abi.encode(CoinbaseSmartWallet.SignatureWrapper(0, abi.encodePacked(r, s, v)));
    }
}