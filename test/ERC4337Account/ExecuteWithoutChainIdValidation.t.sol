// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import "./ERC4337AccountTestBase.t.sol";

contract TestExecuteWithoutChainIdValidation is AccountTestBase {
    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost,
        uint256 actualGasUsed
    );

    function setUp() public override {
        super.setUp();
        userOpNonce = account.REPLAYABLE_NONCE_KEY() << 64;
        userOpCalldata = abi.encodeWithSelector(ERC4337Account.executeWithoutChainIdValidation.selector);
    }

    function test_revertsIfCallerNotEntryPoint() public {
        vm.expectRevert(MultiOwnable.Unauthorized.selector);
        account.executeWithoutChainIdValidation("");
    }

    function test_revertsIfWrongNonceKey() public {
        userOpNonce = 0;
        UserOperation memory userOp = _getUserOpWithSignature();
        vm.expectRevert();
        _sendUserOperation(userOp);
    }

    function test_canChangeOwnerWithoutChainId() public {
        address newOwner = address(6);
        assertFalse(account.isOwner(newOwner));

        userOpCalldata = abi.encodeWithSelector(
            ERC4337Account.executeWithoutChainIdValidation.selector,
            abi.encodeWithSelector(MultiOwnable.addOwnerAddress.selector, newOwner)
        );
        _sendUserOperation(_getUserOpWithSignature());
        assertTrue(account.isOwner(newOwner));
    }

    function test_cannotCallExec() public {
        userOpCalldata = abi.encodeWithSelector(
            ERC4337Account.executeWithoutChainIdValidation.selector,
            abi.encodeWithSelector(ERC4337Account.execute.selector, "")
        );
        UserOperation memory userOp = _getUserOpWithSignature();
        vm.expectEmit(true, true, true, true);
        emit UserOperationEvent(
            entryPoint.getUserOpHash(userOp), userOp.sender, address(0), userOp.nonce, false, 0, 47747
        );
        _sendUserOperation(userOp);
    }

    function _sign(UserOperation memory userOp) internal view override returns (bytes memory signature) {
        bytes32 toSign = account.getUserOpHashWithoutChainId(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, toSign);
        signature = abi.encodePacked(uint8(0), r, s, v);
    }
}
