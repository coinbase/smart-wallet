// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Test, console2, stdError} from "forge-std/Test.sol";

import "../../src/CoinbaseSmartWallet.sol";
import {MockCoinbaseSmartWallet} from "../mocks/MockCoinbaseSmartWallet.sol";
import {Static} from "./Static.sol";

contract SmartWalletTestBase is Test {
    CoinbaseSmartWallet public account;
    uint256 signerPrivateKey = 0xa11ce;
    address signer = vm.addr(signerPrivateKey);
    bytes[] owners;
    uint256 passkeyPrivateKey = uint256(0x03d99692017473e2d631945a812607b23269d85721e0f370b8d3e7d29a874fd2);
    bytes passkeyOwner =
        hex"1c05286fe694493eae33312f2d2e0d0abeda8db76238b7a204be1fb87f54ce4228fef61ef4ac300f631657635c28e59bfb2fe71bce1634c81c65642042f6dc4d";
    IEntryPoint entryPoint = IEntryPoint(0x0000000071727De22E5E9d8BAf0edAc6f37da032);
    address bundler = address(uint160(uint256(keccak256(abi.encodePacked("bundler")))));

    // userOp values
    uint256 userOpNonce;
    bytes userOpCalldata;

    function setUp() public virtual {
        vm.etch(0x0000000071727De22E5E9d8BAf0edAc6f37da032, Static.ENTRY_POINT_BYTES);
        account = new MockCoinbaseSmartWallet();
        owners.push(abi.encode(signer));
        owners.push(passkeyOwner);
        account.initialize(owners);
    }

    function _sendUserOperation(PackedUserOperation memory userOp) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        entryPoint.handleOps(ops, payable(bundler));
    }

    function _getUserOp() internal view returns (PackedUserOperation memory userOp) {
        userOp = PackedUserOperation({
            sender: address(account),
            nonce: userOpNonce,
            initCode: "",
            callData: userOpCalldata,
            accountGasLimits: bytes32(abi.encodePacked(uint128(1_000_000), uint128(1_000_000))),
            gasFees: bytes32(0),
            preVerificationGas: uint256(0),
            paymasterAndData: "",
            signature: ""
        });
    }

    function _getUserOpWithSignature() internal view returns (PackedUserOperation memory userOp) {
        userOp = _getUserOp();
        userOp.signature = _sign(userOp);
    }

    function _sign(PackedUserOperation memory userOp) internal view virtual returns (bytes memory signature) {
        bytes32 toSign = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, toSign);
        signature = abi.encodePacked(uint8(0), r, s, v);
    }

    function _randomBytes(uint256 seed) internal pure returns (bytes memory result) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, seed)
            let r := keccak256(0x00, 0x20)
            if lt(byte(2, r), 0x20) {
                result := mload(0x40)
                let n := and(r, 0x7f)
                mstore(result, n)
                codecopy(add(result, 0x20), byte(1, r), add(n, 0x40))
                mstore(0x40, add(add(result, 0x40), n))
            }
        }
    }
}
