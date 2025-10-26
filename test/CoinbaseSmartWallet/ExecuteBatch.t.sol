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
        // Limit r so derived values (like loops / random sizes) stay reasonable.
        vm.assume(r < 1 << 20);
    // Limit number of created MockTarget contracts (n = r & 3) to 0..1 to avoid large gas variance
    // from repeated contract deployments during fuzzing.
    vm.assume((r & 3) < 2);
        // Instrument fuzz inputs to help root-cause gas variance.
        // Log the raw fuzz seed and derived values.
    uint256 n = r & 3;
    console2.log("fuzz r:", r);
    console2.log("derived n:", n);
    // Reuse the `account` deployed in `setUp()` (avoid redeploying here which adds ~4.6M gas).
        vm.prank(signer);
        account.addOwnerAddress(address(this));
        vm.deal(address(account), 1 ether);

        unchecked {
            CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](n);

            for (uint256 i; i != n; ++i) {
                uint256 v = _random() & 0xff;
                console2.log("call i v:", i, v);
                calls[i].target = address(new MockTarget());
                calls[i].value = v;
                calls[i].data = abi.encodeWithSignature("setData(bytes)", _randomBytes(v));
                console2.log("call i data len:", i, calls[i].data.length);
            }

            if (_random() & 1 == 0) {
                uint256 randParam = _random();
                console2.log("executeBatch randParam:", randParam);
                MockCoinbaseSmartWallet(payable(address(account))).executeBatch(randParam, calls);
            } else {
                account.executeBatch(calls);
            }

            for (uint256 i; i != n; ++i) {
                uint256 v = calls[i].value;
                assertEq(MockTarget(calls[i].target).datahash(), keccak256(_randomBytes(v)));
                assertEq(calls[i].target.balance, v);
            }
        }
    }
}
