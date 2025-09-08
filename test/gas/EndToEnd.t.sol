// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {MockERC20} from "../../lib/solady/test/utils/mocks/MockERC20.sol";
import {CoinbaseSmartWallet} from "../../src/CoinbaseSmartWallet.sol";
import {CoinbaseSmartWalletFactory} from "../../src/CoinbaseSmartWalletFactory.sol";
import {SmartWalletTestBase} from "../CoinbaseSmartWallet/SmartWalletTestBase.sol";

import {Static} from "../CoinbaseSmartWallet/Static.sol";
import {MockTarget} from "../mocks/MockTarget.sol";
import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";
import {console2} from "forge-std/Test.sol";

/// forge-config: default.isolate = true
contract EndToEndTest is SmartWalletTestBase {
    address eoaUser = address(0xe0a);

    MockERC20 usdc;
    MockTarget target;
    CoinbaseSmartWalletFactory factory;

    function setUp() public override {
        vm.etch(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789, Static.ENTRY_POINT_BYTES);

        CoinbaseSmartWallet implementation = new CoinbaseSmartWallet();
        factory = new CoinbaseSmartWalletFactory(address(implementation));

        signerPrivateKey = 0xa11ce;
        signer = vm.addr(signerPrivateKey);
        owners.push(abi.encode(signer));
        account = factory.createAccount(owners, 0);

        vm.deal(address(account), 100 ether);
        vm.deal(eoaUser, 100 ether);

        usdc = new MockERC20("USD Coin", "USDC", 6);
        usdc.mint(address(account), 10000e6);
        usdc.mint(eoaUser, 10000e6);

        target = new MockTarget();
    }

    // Native ETH transfer comparison between ERC-4337 and EOA
    function test_transfer_native() public {
        // Dust recipient to control for gas increase for first non-zero balance
        vm.deal(address(0x1234), 1 wei);
        usdc.mint(eoaUser, 1 wei);

        userOpCalldata = abi.encodeCall(CoinbaseSmartWallet.execute, (address(0x1234), 1 ether, ""));
        UserOperation memory op = _getUserOpWithSignature();

        bytes memory handleOpsCalldata = abi.encodeCall(entryPoint.handleOps, (_makeOpsArray(op), payable(bundler)));
        console2.log("test_transfer_native Base Account calldata size:", handleOpsCalldata.length);

        vm.startSnapshotGas("e2e_transfer_native_baseAccount");
        _sendUserOperation(op);
        uint256 gas4337 = vm.stopSnapshotGas();
        console2.log("test_transfer_native Base Account gas:", gas4337);

        console2.log("test_transfer_native EOA calldata size:", uint256(0));

        vm.prank(eoaUser);
        vm.startSnapshotGas("e2e_transfer_native_eoa");
        payable(address(0x1234)).transfer(1 ether);
        uint256 gasEOA = vm.stopSnapshotGas();
        console2.log("test_transfer_native EOA gas:", gasEOA);
        console2.log("Gas overhead (4337 Base Account / EOA):", (gas4337 * 100) / gasEOA, "%");
    }

    // ERC20 transfer comparison between ERC-4337 and EOA
    function test_transfer_erc20() public {
        // Dust recipient to control for gas increase for first non-zero balance
        vm.deal(address(0x5678), 1 wei);
        usdc.mint(eoaUser, 1 wei);

        userOpCalldata = abi.encodeCall(
            CoinbaseSmartWallet.execute, (address(usdc), 0, abi.encodeCall(usdc.transfer, (address(0x5678), 100e6)))
        );
        UserOperation memory op = _getUserOpWithSignature();

        bytes memory handleOpsCalldata = abi.encodeCall(entryPoint.handleOps, (_makeOpsArray(op), payable(bundler)));
        console2.log("test_transfer_erc20 Base Account calldata size:", handleOpsCalldata.length);

        vm.startSnapshotGas("e2e_transfer_erc20_baseAccount");
        _sendUserOperation(op);
        uint256 gas4337 = vm.stopSnapshotGas();
        console2.log("test_transfer_erc20 Base Account gas:", gas4337);

        bytes memory eoaCalldata = abi.encodeCall(usdc.transfer, (address(0x5678), 100e6));
        console2.log("test_transfer_erc20 EOA calldata size:", eoaCalldata.length);

        vm.prank(eoaUser);
        vm.startSnapshotGas("e2e_transfer_erc20_eoa");
        usdc.transfer(address(0x5678), 100e6);
        uint256 gasEOA = vm.stopSnapshotGas();
        console2.log("test_transfer_erc20 EOA gas:", gasEOA);
        console2.log("Gas overhead (4337 Base Account / EOA):", (gas4337 * 100) / gasEOA, "%");
    }

    function _makeOpsArray(UserOperation memory op) internal pure returns (UserOperation[] memory) {
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        return ops;
    }

    function _sign(UserOperation memory userOp) internal view override returns (bytes memory signature) {
        bytes32 toSign = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, toSign);
        signature = abi.encode(CoinbaseSmartWallet.SignatureWrapper(0, abi.encodePacked(r, s, v)));
    }
}
