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

    function test_revertsIfCallerNotEntryPoint() public {
        vm.expectRevert(MultiOwnable.Unauthorized.selector);
        account.executeWithoutChainIdValidation("");
    }

    function test_canChangeOwnerWithoutChainId() public {
        address newOwner = address(6);
        UserOperation memory userOp = _getUserOp();
        userOp.callData = abi.encodeWithSelector(
            ERC4337Account.executeWithoutChainIdValidation.selector,
            abi.encodeWithSelector(MultiOwnable.addOwnerAddress.selector, newOwner)
        );
        bytes32 toSign = account.getUserOpHashWithoutChainId(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, toSign);
        userOp.signature = abi.encodePacked(uint8(0), r, s, v);

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;
        entryPoint.handleOps(ops, payable(address(1)));
        assertTrue(account.isOwner(newOwner));
    }

    function test_cannotCallExecWithoutChainId() public {
        UserOperation memory userOp = _getUserOp();
        userOp.callData = abi.encodeWithSelector(
            ERC4337Account.executeWithoutChainIdValidation.selector,
            abi.encodeWithSelector(ERC4337Account.execute.selector, "")
        );
        bytes32 toSign = account.getUserOpHashWithoutChainId(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, toSign);
        userOp.signature = abi.encodePacked(uint8(0), r, s, v);

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;
        vm.expectEmit(true, true, true, true);
        emit UserOperationEvent(entryPoint.getUserOpHash(userOp), address(account), address(0), 0, false, 0, 47320);
        entryPoint.handleOps(ops, payable(address(1)));
    }

    function _getUserOp() public view returns (UserOperation memory userOp) {
        userOp = UserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: "",
            callGasLimit: uint256(1_000_000),
            verificationGasLimit: uint256(1_000_000),
            preVerificationGas: uint256(0),
            maxFeePerGas: uint256(0),
            maxPriorityFeePerGas: uint256(0),
            paymasterAndData: "",
            signature: ""
        });
    }
}
