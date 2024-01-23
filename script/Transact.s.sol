// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";

import {ERC4337Factory, ERC4337Account} from "../src/ERC4337Factory.sol";
import {WebAuthn} from "../src/WebAuthn.sol";
import {IEntryPoint, UserOperation} from "account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "../test/Utils.sol";
import "p256-verifier/src/P256.sol";

contract TransactScript is Script {
    ERC4337Factory f = ERC4337Factory(0x748e5dD94d5F619371d763adfcBB0eDB863905fD);
    uint256 passkeyPrivateKey = vm.envUint("P256_PRIVATE_KEY");
    bytes passkeyOwner =
        hex"1c05286fe694493eae33312f2d2e0d0abeda8db76238b7a204be1fb87f54ce4228fef61ef4ac300f631657635c28e59bfb2fe71bce1634c81c65642042f6dc4d";
    bytes[] owners;
    uint256 deployerPrivateKey;
    IEntryPoint entryPoint = IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789);
    ERC4337Account account = ERC4337Account(payable(0xDCeE0dF9513eb53a55E9dE7bBc93A04F8DABd3F4));

    function run() public {
        deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        console2.logBytes(account.ownerAtIndex(1));
        // owners.push(abi.encode(vm.addr(deployerPrivateKey)));
        // owners.push(passkeyOwner);
        // account = ERC4337Account(payable(f.createAccount(owners, 1)));
        UserOperation memory userOp = UserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: "",
            callGasLimit: uint256(9100),
            verificationGasLimit: uint256(1016000),
            preVerificationGas: uint256(1002600),
            maxFeePerGas: uint256(0),
            maxPriorityFeePerGas: uint256(0),
            paymasterAndData: "",
            signature: ""
        });
        console2.log(userOp.sender);
        bytes32 challenge = entryPoint.getUserOpHash(userOp);
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(challenge);
        bytes32 check = webAuthn.messageHash;
        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, check);
        bytes memory sig = abi.encode(
            ERC4337Account.SignatureWrapper({
                ownerIndex: 1,
                signatureData: abi.encode(
                    WebAuthn.WebAuthnAuth({
                        authenticatorData: webAuthn.authenticatorData,
                        origin: "",
                        crossOrigin: false,
                        remainder: "",
                        r: uint256(r),
                        s: uint256(s)
                    })
                    )
            })
        );

        bytes memory sigWithOwnerIndex = sig;
        userOp.signature = sigWithOwnerIndex;
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;

        entryPoint.handleOps{gas: 2_200_000}(ops, payable(vm.addr(deployerPrivateKey)));
    }
}
