// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {MagicSpend} from "../src/MagicSpend.sol";

contract MagicSpendTest is Test {
    MagicSpend magicSpend;
    uint256 ownerKey = 0xA11CE;
    address owner;
    address user = address(0x1234);

    function setUp() public {
        owner = vm.addr(ownerKey);
        vm.prank(owner);
        magicSpend = new MagicSpend();
        vm.deal(address(magicSpend), 10 ether);
    }

    function _makeRequest(uint256 amount, uint256 nonce, uint48 expiry, address asset)
        internal view returns (MagicSpend.WithdrawRequest memory req)
    {
        req = MagicSpend.WithdrawRequest({
            signature: "",
            asset: asset,
            amount: amount,
            nonce: nonce,
            expiry: expiry
        });
        bytes32 hash = magicSpend.getHash(user, req);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        req.signature = abi.encodePacked(r, s, v);
    }

    function test_withdraw_ETH_success() public {
        MagicSpend.WithdrawRequest memory req = _makeRequest(1 ether, 0, uint48(block.timestamp + 1 hours), address(0));
        uint256 balBefore = user.balance;
        vm.prank(user);
        magicSpend.withdraw(req);
        assertEq(user.balance - balBefore, 1 ether);
    }

    function test_expiredRequest_doesNotBurnNonce() public {
        MagicSpend.WithdrawRequest memory req = _makeRequest(1 ether, 7, uint48(block.timestamp - 1), address(0));
        vm.prank(user);
        vm.expectRevert(MagicSpend.Expired.selector);
        magicSpend.withdraw(req);
        assertFalse(magicSpend.nonceUsed(user, 7), "nonce burned by expired request");
    }

    function test_invalidSig_doesNotBurnNonce() public {
        MagicSpend.WithdrawRequest memory req = _makeRequest(1 ether, 9, uint48(block.timestamp + 1 hours), address(0));
        req.signature[0] = ~req.signature[0];
        vm.prank(user);
        vm.expectRevert(MagicSpend.InvalidSignature.selector);
        magicSpend.withdraw(req);
        assertFalse(magicSpend.nonceUsed(user, 9), "nonce burned by invalid sig");
    }

    function test_withdraw_revertsOnNonceReplay() public {
        MagicSpend.WithdrawRequest memory req = _makeRequest(1 ether, 0, uint48(block.timestamp + 1 hours), address(0));
        vm.prank(user);
        magicSpend.withdraw(req);
        MagicSpend.WithdrawRequest memory req2 = _makeRequest(1 ether, 0, uint48(block.timestamp + 1 hours), address(0));
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(MagicSpend.InvalidNonce.selector, 0));
        magicSpend.withdraw(req2);
    }

    function test_ownerWithdraw_revertsZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(MagicSpend.InvalidAddress.selector);
        magicSpend.ownerWithdraw(address(0), address(0), 1 ether);
    }

    function test_entryPointDeposit_sendsMsgValue() public {
        address ep = magicSpend.entryPoint();
        vm.etch(ep, hex"00");
        uint256 balBefore = ep.balance;
        vm.deal(owner, 2 ether);
        vm.prank(owner);
        magicSpend.entryPointDeposit{value: 1 ether}();
        assertEq(ep.balance - balBefore, 1 ether);
    }
}
