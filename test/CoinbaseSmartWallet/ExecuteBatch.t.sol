// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "solady/../test/utils/TestPlus.sol";

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
        account = new MockCoinbaseSmartWallet();
        account.initialize(owners);
        vm.prank(signer);
        account.addOwnerAddress(address(this));
        vm.deal(address(account), 1 ether);

        unchecked {
            uint256 n = r & 3;
            CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](n);

            for (uint256 i; i != n; ++i) {
                uint256 v = _random() & 0xff;
                calls[i].target = address(new MockTarget());
                calls[i].value = v;
                calls[i].data = abi.encodeWithSignature("setData(bytes)", _randomBytes(v));
            }

            if (_random() & 1 == 0) {
                MockCoinbaseSmartWallet(payable(address(account))).executeBatch(_random(), calls);
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
