// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {console2} from "forge-std/Test.sol";
import {CoinbaseSmartWallet} from "../../src/CoinbaseSmartWallet.sol";
import {SmartWalletTestBase} from "../CoinbaseSmartWallet/SmartWalletTestBase.sol";

/// forge-config: default.isolate = true
contract ExecuteGasBenchmarkBase is SmartWalletTestBase {
    // Standard test values
    uint256 internal constant BENCHMARK_ETH_AMOUNT = 1 ether;
    address internal constant BENCHMARK_RECIPIENT = address(0x1234);
    
    function setUp() public virtual override {
        super.setUp();
        
        // Do a dummy transfer to initialize any storage slots
        vm.deal(address(account), 10 ether);
        vm.prank(signer);
        account.execute(address(0x9999), 1 wei, "");
    }
}

contract Execute_ETHTransfer_GasBenchmark is ExecuteGasBenchmarkBase {
    // This will show up in --gas-report
    function test_execute_ethTransfer_benchmark() public {
        vm.prank(signer);
        account.execute(BENCHMARK_RECIPIENT, BENCHMARK_ETH_AMOUNT, "");
    }
    
    // This will also show up in --gas-report 
    // and writes to snapshots/Execute_ETHTransfer_GasBenchmark.json
    function test_execute_ethTransfer_snapshot() public {
        // The snapshot captures ONLY this execute call
        vm.prank(signer);
        vm.startSnapshotGas("Execute_ETHTransfer");
        account.execute(BENCHMARK_RECIPIENT, BENCHMARK_ETH_AMOUNT, "");
        uint256 gasUsed = vm.stopSnapshotGas();
        
        // Optional: log for immediate visibility
        console2.log("ETH Transfer gas (snapshot):", gasUsed);
        
        // Gas report will show the ENTIRE function (including vm.prank, console.log, etc.)
        // Snapshot will show ONLY the execute call
    }
}

contract Execute_SelfCall_GasBenchmark is ExecuteGasBenchmarkBase {
    function test_execute_selfCall_benchmark() public {
        // Measure only overhead without external call
        vm.prank(signer);
        account.execute(address(account), 0, "");
    }
}

// Simple target contract for testing
contract Target {
    uint256 public value;
    function setValue(uint256 v) external { value = v; }
}

contract Execute_ContractCall_GasBenchmark is ExecuteGasBenchmarkBase {
    Target target;
    
    function setUp() public override {
        super.setUp();
        target = new Target();
    }
    
    function test_execute_contractCall_benchmark() public {
        bytes memory data = abi.encodeCall(Target.setValue, (42));
        vm.prank(signer);
        account.execute(address(target), 0, data);
    }
}

contract ExecuteBatch_GasBenchmark is ExecuteGasBenchmarkBase {
    function test_executeBatch_3transfers_benchmark() public {
        CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](3);
        
        calls[0] = CoinbaseSmartWallet.Call({
            target: address(0x1111),
            value: 0.1 ether,
            data: ""
        });
        
        calls[1] = CoinbaseSmartWallet.Call({
            target: address(0x2222),
            value: 0.1 ether,
            data: ""
        });
        
        calls[2] = CoinbaseSmartWallet.Call({
            target: address(0x3333),
            value: 0.1 ether,
            data: ""
        });
        
        vm.prank(signer);
        account.executeBatch(calls);
    }
    
    function test_executeBatch_detailed_analysis() public {
        // Measure batch sizes 1-5 to see scaling
        for (uint256 size = 1; size <= 5; size++) {
            CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](size);
            
            for (uint256 i = 0; i < size; i++) {
                calls[i] = CoinbaseSmartWallet.Call({
                    target: address(uint160(0x1000 + i)),
                    value: 0.01 ether,
                    data: ""
                });
            }
            
            vm.prank(signer);
            string memory label = string(abi.encodePacked("batch_", vm.toString(size)));
            vm.startSnapshotGas("ExecuteBatch", label);
            account.executeBatch(calls);
            uint256 gasUsed = vm.stopSnapshotGas();
            
            console2.log("Batch size", size, "gas:", gasUsed);
            if (size > 1) {
                console2.log("  Per call:", gasUsed / size);
            }
        }
    }
}

contract Execute_ViaEntryPoint_GasBenchmark is ExecuteGasBenchmarkBase {
    function test_execute_viaEntryPoint_benchmark() public {
        // Test execution when called via EntryPoint (not owner)
        vm.prank(account.entryPoint());
        account.execute(BENCHMARK_RECIPIENT, BENCHMARK_ETH_AMOUNT, "");
    }
}

contract ExecuteWithoutChainIdValidation_GasBenchmark is ExecuteGasBenchmarkBase {
    function test_executeWithoutChainIdValidation_benchmark() public {
        // Setup call to add owner (allowed cross-chain operation)
        bytes memory addOwnerCall = abi.encodeWithSignature(
            "addOwnerAddress(address)",
            address(0x5555)
        );
        
        bytes[] memory calls = new bytes[](1);
        calls[0] = addOwnerCall;
        
        vm.prank(account.entryPoint());
        account.executeWithoutChainIdValidation(calls);
    }
} 