// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {console2} from "forge-std/Test.sol";
import {SmartWalletTestBase} from "../CoinbaseSmartWallet/SmartWalletTestBase.sol";
import {CoinbaseSmartWallet} from "../../src/CoinbaseSmartWallet.sol";
import {CoinbaseSmartWalletFactory} from "../../src/CoinbaseSmartWalletFactory.sol";
import {MockTarget} from "../mocks/MockTarget.sol";
import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";
import {MockERC20} from "../../lib/solady/test/utils/mocks/MockERC20.sol";
import {Static} from "../CoinbaseSmartWallet/Static.sol";

/// forge-config: default.isolate = true
contract EndToEndTest is SmartWalletTestBase {
    address eoaUser = address(0xe0a);
    
    MockERC20 usdc;
    MockTarget target;
    CoinbaseSmartWalletFactory factory;
    
    function setUp() public override {
        vm.etch(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789, Static.ENTRY_POINT_BYTES);
        
        CoinbaseSmartWallet implementation = new CoinbaseSmartWallet();
        factory = new CoinbaseSmartWalletFactory(address(implementation));
        
        signerPrivateKey = 0xa11ce;
        signer = vm.addr(signerPrivateKey);
        owners.push(abi.encode(signer));
        account = factory.createAccount(owners, 0);
        
        vm.deal(address(account), 100 ether);
        vm.deal(eoaUser, 100 ether);
        
        usdc = new MockERC20("USD Coin", "USDC", 6);
        usdc.mint(address(account), 10000e6);
        usdc.mint(eoaUser, 10000e6);
        
        target = new MockTarget();
    }
    
    // Native ETH transfer comparison between ERC-4337 and EOA
    function test_transfer_native() public {
        userOpCalldata = abi.encodeCall(CoinbaseSmartWallet.execute, (address(0x1234), 1 ether, ""));
        UserOperation memory op = _getUserOpWithSignature();
        
        bytes memory handleOpsCalldata = abi.encodeCall(entryPoint.handleOps, (_makeOpsArray(op), payable(bundler)));
        console2.log("test_transfer_native ERC-4337 calldata size:", handleOpsCalldata.length);
        
        vm.startSnapshotGas("e2e_transfer_native_4337");
        _sendUserOperation(op);
        uint256 gas4337 = vm.stopSnapshotGas();
        console2.log("test_transfer_native ERC-4337 gas:", gas4337);
        
        console2.log("test_transfer_native EOA calldata size:", uint256(0));
        
        vm.prank(eoaUser);
        vm.startSnapshotGas("e2e_transfer_native_eoa");
        payable(address(0x1234)).transfer(1 ether);
        uint256 gasEOA = vm.stopSnapshotGas();
        console2.log("test_transfer_native EOA gas:", gasEOA);
        console2.log("Gas overhead (4337/EOA):", (gas4337 * 100) / gasEOA, "%");
    }
    
    // ERC20 transfer comparison showing overhead for token operations
    function test_transfer_erc20() public {
        userOpCalldata = abi.encodeCall(
            CoinbaseSmartWallet.execute,
            (address(usdc), 0, abi.encodeCall(usdc.transfer, (address(0x5678), 100e6)))
        );
        UserOperation memory op = _getUserOpWithSignature();
        
        bytes memory handleOpsCalldata = abi.encodeCall(entryPoint.handleOps, (_makeOpsArray(op), payable(bundler)));
        console2.log("test_transfer_erc20 ERC-4337 calldata size:", handleOpsCalldata.length);
        
        vm.startSnapshotGas("e2e_transfer_erc20_4337");
        _sendUserOperation(op);
        uint256 gas4337 = vm.stopSnapshotGas();
        console2.log("test_transfer_erc20 ERC-4337 gas:", gas4337);
        
        bytes memory eoaCalldata = abi.encodeCall(usdc.transfer, (address(0x5678), 100e6));
        console2.log("test_transfer_erc20 EOA calldata size:", eoaCalldata.length);
        
        vm.prank(eoaUser);
        vm.startSnapshotGas("e2e_transfer_erc20_eoa");
        usdc.transfer(address(0x5678), 100e6);
        uint256 gasEOA = vm.stopSnapshotGas();
        console2.log("test_transfer_erc20 EOA gas:", gasEOA);
        console2.log("Gas overhead (4337/EOA):", (gas4337 * 100) / gasEOA, "%");
    }
    
    // Simple swap simulation - single contract interaction with ETH value
    function test_swap_eth_usdc_uniV4() public {
        userOpCalldata = abi.encodeCall(
            CoinbaseSmartWallet.execute,
            (address(target), 0.1 ether, abi.encodeCall(target.setData, ("swap_eth_usdc")))
        );
        UserOperation memory op = _getUserOpWithSignature();
        
        bytes memory handleOpsCalldata = abi.encodeCall(entryPoint.handleOps, (_makeOpsArray(op), payable(bundler)));
        console2.log("test_swap_eth_usdc_uniV4 ERC-4337 calldata size:", handleOpsCalldata.length);
        
        vm.startSnapshotGas("e2e_swap_eth_usdc_4337");
        _sendUserOperation(op);
        uint256 gas4337 = vm.stopSnapshotGas();
        console2.log("test_swap_eth_usdc_uniV4 ERC-4337 gas:", gas4337);
        
        bytes memory eoaCalldata = abi.encodeCall(target.setData, ("swap_eth_usdc"));
        console2.log("test_swap_eth_usdc_uniV4 EOA calldata size:", eoaCalldata.length);
        
        vm.prank(eoaUser);
        vm.startSnapshotGas("e2e_swap_eth_usdc_eoa");
        target.setData{value: 0.1 ether}("swap_eth_usdc");
        uint256 gasEOA = vm.stopSnapshotGas();
        console2.log("test_swap_eth_usdc_uniV4 EOA gas:", gasEOA);
        console2.log("Gas overhead (4337/EOA):", (gas4337 * 100) / gasEOA, "%");
    }
    
    // Multi-hop swap demonstrating batch execution advantages
    function test_swap_eth_contentcoin_uniV4() public {
        CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](4);
        
        calls[0] = CoinbaseSmartWallet.Call({
            target: address(target),
            value: 0.1 ether,
            data: abi.encodeCall(target.setData, ("swap_eth_usdc"))
        });
        
        calls[1] = CoinbaseSmartWallet.Call({
            target: address(usdc),
            value: 0,
            data: abi.encodeCall(usdc.approve, (address(target), 100e6))
        });
        
        calls[2] = CoinbaseSmartWallet.Call({
            target: address(target),
            value: 0,
            data: abi.encodeCall(target.setData, ("swap_usdc_zora"))
        });
        
        calls[3] = CoinbaseSmartWallet.Call({
            target: address(target),
            value: 0,
            data: abi.encodeCall(target.setData, ("swap_zora_contentcoin"))
        });
        
        userOpCalldata = abi.encodeCall(CoinbaseSmartWallet.executeBatch, (calls));
        UserOperation memory op = _getUserOpWithSignature();
        
        bytes memory handleOpsCalldata = abi.encodeCall(entryPoint.handleOps, (_makeOpsArray(op), payable(bundler)));
        console2.log("test_swap_eth_contentcoin_uniV4 ERC-4337 calldata size:", handleOpsCalldata.length);
        
        vm.startSnapshotGas("e2e_swap_eth_contentcoin_4337");
        _sendUserOperation(op);
        uint256 gas4337 = vm.stopSnapshotGas();
        console2.log("test_swap_eth_contentcoin_uniV4 ERC-4337 gas:", gas4337);
        
        // EOA would require 4 separate transactions
        console2.log("test_swap_eth_contentcoin_uniV4 EOA calldata size: N/A (4 separate txs)");
        console2.log("test_swap_eth_contentcoin_uniV4 EOA gas: N/A (4 separate txs required)");
    }
    
    // Contract creation simulation to measure deployment overhead
    function test_create_contentcoin() public {
        userOpCalldata = abi.encodeCall(
            CoinbaseSmartWallet.execute,
            (address(target), 0, abi.encodeCall(target.setData, ("create_contentcoin_MyCoin")))
        );
        UserOperation memory op = _getUserOpWithSignature();
        
        bytes memory handleOpsCalldata = abi.encodeCall(entryPoint.handleOps, (_makeOpsArray(op), payable(bundler)));
        console2.log("test_create_contentcoin ERC-4337 calldata size:", handleOpsCalldata.length);
        
        vm.startSnapshotGas("e2e_create_contentcoin_4337");
        _sendUserOperation(op);
        uint256 gas4337 = vm.stopSnapshotGas();
        console2.log("test_create_contentcoin ERC-4337 gas:", gas4337);
        
        bytes memory eoaCalldata = abi.encodeCall(target.setData, ("create_contentcoin_MyCoin"));
        console2.log("test_create_contentcoin EOA calldata size:", eoaCalldata.length);
        
        vm.prank(eoaUser);
        vm.startSnapshotGas("e2e_create_contentcoin_eoa");
        target.setData("create_contentcoin_MyCoin");
        uint256 gasEOA = vm.stopSnapshotGas();
        console2.log("test_create_contentcoin EOA gas:", gasEOA);
        console2.log("Gas overhead (4337/EOA):", (gas4337 * 100) / gasEOA, "%");
    }
    
    function _makeOpsArray(UserOperation memory op) internal pure returns (UserOperation[] memory) {
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        return ops;
    }
    
    function _sign(UserOperation memory userOp) internal view override returns (bytes memory signature) {
        bytes32 toSign = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, toSign);
        signature = abi.encode(CoinbaseSmartWallet.SignatureWrapper(0, abi.encodePacked(r, s, v)));
    }
} 