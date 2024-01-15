// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import "./ERC4337AccountTestBase.t.sol";

contract TestExecuteWithoutChainIdValidation is AccountTestBase {
    function setUp() public override {
        userOpCalldata = abi.encodeWithSelector(ERC4337Account.execute.selector);
        super.setUp();
    }

    function test_revertsWithReservedNonce() public {
        userOpNonce = account.REPLAYABLE_NONCE_KEY() << 64;
        UserOperation memory userOp = _getUserOpWithSignature();
        vm.expectRevert();
        _sendUserOperation(userOp);
    }
}
