// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {Test, console2, stdError} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/contracts/interfaces/IEntryPoint.sol";

import "../../src/ERC4337Account.sol";
import {MockERC4337Account} from "../mocks/MockERC4337Account.sol";
import {Static} from "./Static.sol";

contract AccountTestBase is Test {
    ERC4337Account public account;
    uint256 signerPrivateKey = 0xa11ce;
    address signer = vm.addr(signerPrivateKey);
    bytes[] owners;
    bytes passkeyOwner =
        hex"d0266650cb64be790f59ad65381659583bfbf6d8338783af12f4c9f6cd70333f8224d6f6a871980a9f08df9ff70ba3531299e8da7e42a9e8e89b84fb1f53febe";
    IEntryPoint entryPoint = IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789);
    address bundler = address(uint160(uint256(keccak256(abi.encodePacked("bundler")))));

    // userOp values
    uint256 userOpNonce;
    bytes userOpCalldata;

    function setUp() public virtual {
        vm.etch(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789, Static.ENTRY_POINT_BYTES);
        account = new MockERC4337Account();
        owners.push(abi.encode(signer));
        owners.push(passkeyOwner);
        account.initialize(owners);
    }

    function _sendUserOperation(UserOperation memory userOp) internal {
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;
        entryPoint.handleOps(ops, payable(bundler));
    }

    function _getUserOp() internal view returns (UserOperation memory userOp) {
        userOp = UserOperation({
            sender: address(account),
            nonce: userOpNonce,
            initCode: "",
            callData: userOpCalldata,
            callGasLimit: uint256(1_000_000),
            verificationGasLimit: uint256(1_000_000),
            preVerificationGas: uint256(0),
            maxFeePerGas: uint256(0),
            maxPriorityFeePerGas: uint256(0),
            paymasterAndData: "",
            signature: ""
        });
    }

    function _getUserOpWithSignature() internal view returns (UserOperation memory userOp) {
        userOp = _getUserOp();
        userOp.signature = _sign(userOp);
    }

    function _sign(UserOperation memory userOp) internal view virtual returns (bytes memory signature) {
        bytes32 toSign = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, toSign);
        signature = abi.encodePacked(uint8(0), r, s, v);
    }
}
