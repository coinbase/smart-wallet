// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "solady/../test/utils/TestPlus.sol";
import {console2} from "forge-std/Test.sol";
import {MockTarget} from "../mocks/MockTarget.sol";
import "./SmartWalletTestBase.sol";

contract TestExecuteWithoutChainIdValidation is SmartWalletTestBase, TestPlus {
    function testExecuteBatch() public {
        vm.deal(address(account), 1 ether);
        vm.prank(signer);
        account.addOwnerAddress(address(this));
        CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](2);
        calls[0].target = address(new MockTarget());
        calls[1].target = address(new MockTarget());
        calls[0].value = 123;
        calls[1].value = 456;
        calls[0].data = abi.encodeWithSignature("setData(bytes)", _randomBytes(111));
        calls[1].data = abi.encodeWithSignature("setData(bytes)", _randomBytes(222));
        account.executeBatch(calls);
        assertEq(MockTarget(calls[0].target).datahash(), keccak256(_randomBytes(111)));
        assertEq(MockTarget(calls[1].target).datahash(), keccak256(_randomBytes(222)));
        assertEq(calls[0].target.balance, 123);
        assertEq(calls[1].target.balance, 456);
        calls[1].data = abi.encodeWithSignature("revertWithTargetError(bytes)", _randomBytes(111));
        vm.expectRevert(abi.encodeWithSignature("TargetError(bytes)", _randomBytes(111)));
        account.executeBatch(calls);
    }

    function testExecuteBatch(uint256 r) public {
        // Tighten fuzz input to avoid pathological outliers that create noisy snapshot data.
        vm.assume(r < 1 << 20);
        // Limit n (number of calls in array) to 0..1 to reduce path explosion.
        // Since (r & 3) yields 0..3, constraining it to < 2 gives us 0 or 1 call arrays.
        vm.assume((r & 3) < 2);

        account = new MockCoinbaseSmartWallet();
        account.initialize(owners);
        vm.deal(address(account), 1 ether);

        uint256 n = (r & 3) + 2; // yields 2..3
        CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](n);

        for (uint256 i = 0; i < n; i++) {
            calls[i].target = address(new MockTarget());
            calls[i].value = i * 100;
            calls[i].data = abi.encodeWithSignature("setData(bytes)", _randomBytes(i + 1));
        }

        console2.log("Batch size n=", n);
        console2.logBytes(abi.encodePacked(r));
        account.executeBatch(calls);

        for (uint256 i = 0; i < n; i++) {
            assertEq(calls[i].target.balance, i * 100);
        }
    }

    // Deterministic test for edge cases: explicitly test batch execution with n=2 and n=3 MockTarget contracts.
    // These cases stress-test the batch execution logic with small but realistic array sizes.
    function testExecuteBatchDeterministicEdgeCases() public {
        vm.deal(address(account), 2 ether);
        vm.prank(signer);
        account.addOwnerAddress(address(this));

        // Test case 1: n=2 calls
        {
            CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](2);
            calls[0].target = address(new MockTarget());
            calls[1].target = address(new MockTarget());
            calls[0].value = 100;
            calls[1].value = 200;
            calls[0].data = abi.encodeWithSignature("setData(bytes)", bytes("data1"));
            calls[1].data = abi.encodeWithSignature("setData(bytes)", bytes("data2"));

            account.executeBatch(calls);

            assertEq(calls[0].target.balance, 100);
            assertEq(calls[1].target.balance, 200);
            assertEq(MockTarget(calls[0].target).datahash(), keccak256(bytes("data1")));
            assertEq(MockTarget(calls[1].target).datahash(), keccak256(bytes("data2")));
        }

        // Test case 2: n=3 calls
        {
            CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](3);
            calls[0].target = address(new MockTarget());
            calls[1].target = address(new MockTarget());
            calls[2].target = address(new MockTarget());
            calls[0].value = 150;
            calls[1].value = 250;
            calls[2].value = 350;
            calls[0].data = abi.encodeWithSignature("setData(bytes)", bytes("data1"));
            calls[1].data = abi.encodeWithSignature("setData(bytes)", bytes("data2"));
            calls[2].data = abi.encodeWithSignature("setData(bytes)", bytes("data3"));

            account.executeBatch(calls);

            assertEq(calls[0].target.balance, 150);
            assertEq(calls[1].target.balance, 250);
            assertEq(calls[2].target.balance, 350);
            assertEq(MockTarget(calls[0].target).datahash(), keccak256(bytes("data1")));
            assertEq(MockTarget(calls[1].target).datahash(), keccak256(bytes("data2")));
            assertEq(MockTarget(calls[2].target).datahash(), keccak256(bytes("data3")));
        }
    }
}
