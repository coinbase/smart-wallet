// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {MockTarget} from "../mocks/MockTarget.sol";
import "./SmartWalletTestBase.sol";

contract TestExecuteWithoutChainIdValidation is SmartWalletTestBase {
    function setUp() public override {
        userOpCalldata = abi.encodeWithSelector(CoinbaseSmartWallet.execute.selector);
        super.setUp();
    }

    function test_revertsWithReservedNonce() public {
        userOpNonce = account.REPLAYABLE_NONCE_KEY() << 64;
        UserOperation memory userOp = _getUserOpWithSignature();
        vm.expectRevert();
        _sendUserOperation(userOp);
    }

    // from Solady tests
    // https://github.com/Vectorized/solady/blob/21009ce09f02c0e20ce4750b63577e8c0cc7ced8/test/ERC4337.t.sol#L122
    function testExecute() public {
        vm.deal(address(account), 1 ether);
        vm.prank(signer);
        account.addOwnerAddress(address(this));

        address target = address(new MockTarget());
        bytes memory data = _randomBytes(111);
        account.execute(target, 123, abi.encodeWithSignature("setData(bytes)", data));
        assertEq(MockTarget(target).datahash(), keccak256(data));
        assertEq(target.balance, 123);

        vm.prank(makeAddr("random"));
        vm.expectRevert(MultiOwnable.Unauthorized.selector);
        account.execute(target, 123, abi.encodeWithSignature("setData(bytes)", data));

        vm.expectRevert(abi.encodeWithSignature("TargetError(bytes)", data));
        account.execute(target, 123, abi.encodeWithSignature("revertWithTargetError(bytes)", data));
    }
}
