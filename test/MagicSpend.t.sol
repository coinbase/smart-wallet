// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

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
        internal
        view
        returns (MagicSpend.WithdrawRequest memory req)
    {
        req = MagicSpend.WithdrawRequest({signature: "", asset: asset, amount: amount, nonce: nonce, expiry: expiry});
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

    function test_receive_acceptsETH() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        (bool ok,) = address(magicSpend).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(address(magicSpend).balance, 11 ether);
    }

    function test_entryPointAddStake_stakesMsgValue() public {
        address ep = magicSpend.entryPoint();
        vm.etch(ep, hex"00");
        vm.deal(owner, 2 ether);
        vm.expectCall(ep, 1 ether, abi.encodeWithSignature("addStake(uint32)", uint32(1 days)));
        vm.prank(owner);
        magicSpend.entryPointAddStake{value: 1 ether}(1 days);
    }

    function test_ownerWithdraw_emitsOwnerEvent() public {
        vm.expectEmit(true, true, false, true, address(magicSpend));
        emit MagicSpend.MagicSpendOwnerWithdrawal(user, address(0), 1 ether);
        vm.prank(owner);
        magicSpend.ownerWithdraw(address(0), user, 1 ether);
        assertEq(user.balance, 1 ether);
    }

    function test_onlyOwnerFunctions_revertForNonOwner() public {
        vm.startPrank(user);
        vm.expectRevert(Ownable.Unauthorized.selector);
        magicSpend.ownerWithdraw(address(0), user, 1);
        vm.expectRevert(Ownable.Unauthorized.selector);
        magicSpend.entryPointDeposit();
        vm.expectRevert(Ownable.Unauthorized.selector);
        magicSpend.entryPointAddStake(1 days);
        vm.expectRevert(Ownable.Unauthorized.selector);
        magicSpend.entryPointUnlockStake();
        vm.expectRevert(Ownable.Unauthorized.selector);
        magicSpend.entryPointWithdrawStake(payable(user));
        vm.stopPrank();
    }

    function test_withdraw_revertsWhenSignedByNonOwner() public {
        MagicSpend.WithdrawRequest memory req = MagicSpend.WithdrawRequest({
            signature: "", asset: address(0), amount: 1 ether, nonce: 3, expiry: uint48(block.timestamp + 1 hours)
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBAD, magicSpend.getHash(user, req));
        req.signature = abi.encodePacked(r, s, v);
        vm.prank(user);
        vm.expectRevert(MagicSpend.InvalidSignature.selector);
        magicSpend.withdraw(req);
    }

    function test_withdraw_succeedsAtExactExpiry() public {
        MagicSpend.WithdrawRequest memory req = _makeRequest(1 ether, 4, uint48(block.timestamp), address(0));
        vm.prank(user);
        magicSpend.withdraw(req);
        assertEq(user.balance, 1 ether);
    }

    function test_withdraw_ERC20_success() public {
        MockERC20 token = new MockERC20();
        token.mint(address(magicSpend), 100);
        MagicSpend.WithdrawRequest memory req = _makeRequest(40, 5, uint48(block.timestamp + 1 hours), address(token));
        vm.prank(user);
        magicSpend.withdraw(req);
        assertEq(token.balanceOf(user), 40);
        assertEq(token.balanceOf(address(magicSpend)), 60);
    }
}

contract MagicSpendExtraTest is Test {
    MagicSpend magicSpend;
    uint256 ownerKey = 0xA11CE;
    address owner;
    address user = address(0x1234);
    address ep;

    function setUp() public {
        owner = vm.addr(ownerKey);
        vm.prank(owner);
        magicSpend = new MagicSpend();
        vm.deal(address(magicSpend), 10 ether);
        ep = magicSpend.entryPoint();
    }

    function _signedRequest(address account, uint256 amount, uint256 nonce, address asset)
        internal
        view
        returns (MagicSpend.WithdrawRequest memory req)
    {
        req = MagicSpend.WithdrawRequest({
            signature: "", asset: asset, amount: amount, nonce: nonce, expiry: uint48(block.timestamp + 1 hours)
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, magicSpend.getHash(account, req));
        req.signature = abi.encodePacked(r, s, v);
    }

    function test_withdraw_emitsWithdrawalEvent() public {
        MagicSpend.WithdrawRequest memory req = _signedRequest(user, 1 ether, 11, address(0));
        vm.expectEmit(true, true, false, true, address(magicSpend));
        emit MagicSpend.MagicSpendWithdrawal(user, address(0), 1 ether, 11);
        vm.prank(user);
        magicSpend.withdraw(req);
    }

    function test_withdraw_revertsWhenRedeemedByDifferentAccount() public {
        MagicSpend.WithdrawRequest memory req = _signedRequest(user, 1 ether, 1, address(0));
        vm.prank(address(0xBEEF));
        vm.expectRevert(MagicSpend.InvalidSignature.selector);
        magicSpend.withdraw(req);
    }

    function test_withdraw_revertsOnDifferentChainId() public {
        MagicSpend.WithdrawRequest memory req = _signedRequest(user, 1 ether, 1, address(0));
        vm.chainId(block.chainid + 1);
        vm.prank(user);
        vm.expectRevert(MagicSpend.InvalidSignature.selector);
        magicSpend.withdraw(req);
    }

    function test_withdraw_revertsWhenContractUnderfunded() public {
        MagicSpend.WithdrawRequest memory req = _signedRequest(user, 11 ether, 12, address(0));
        vm.prank(user);
        vm.expectRevert(SafeTransferLib.ETHTransferFailed.selector);
        magicSpend.withdraw(req);
        assertFalse(magicSpend.nonceUsed(user, 12), "nonce burned by failed transfer");
    }

    function test_ownerWithdraw_ERC20() public {
        MockERC20 token = new MockERC20();
        token.mint(address(magicSpend), 100);
        vm.prank(owner);
        magicSpend.ownerWithdraw(address(token), user, 30);
        assertEq(token.balanceOf(user), 30);
        assertEq(token.balanceOf(address(magicSpend)), 70);
    }

    function test_entryPointWithdraw_revertsZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(MagicSpend.InvalidAddress.selector);
        magicSpend.entryPointWithdraw(payable(address(0)), 1 ether);
    }

    function test_entryPointWithdrawStake_revertsZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(MagicSpend.InvalidAddress.selector);
        magicSpend.entryPointWithdrawStake(payable(address(0)));
    }

    // The tests below etch a recording fake over the EntryPoint address, so they check that
    // MagicSpend forwards the right calls, not the real EntryPoint's behavior.
    function test_entryPointWithdraw_forwardsToEntryPoint() public {
        vm.etch(ep, address(new FakeEntryPoint()).code);
        vm.prank(owner);
        magicSpend.entryPointWithdraw(payable(user), 3 ether);
        assertEq(FakeEntryPoint(payable(ep)).lastWithdrawTo(), user);
        assertEq(FakeEntryPoint(payable(ep)).lastWithdrawAmount(), 3 ether);
    }

    function test_entryPointUnlockStake_forwardsToEntryPoint() public {
        vm.etch(ep, address(new FakeEntryPoint()).code);
        vm.prank(owner);
        magicSpend.entryPointUnlockStake();
        assertTrue(FakeEntryPoint(payable(ep)).unlocked());
    }

    function test_entryPointWithdrawStake_forwardsToEntryPoint() public {
        vm.etch(ep, address(new FakeEntryPoint()).code);
        vm.startPrank(owner);
        magicSpend.entryPointUnlockStake();
        magicSpend.entryPointWithdrawStake(payable(user));
        vm.stopPrank();
        assertEq(FakeEntryPoint(payable(ep)).lastStakeWithdrawTo(), user);
    }
}

contract FakeEntryPoint {
    bool public unlocked;
    address public lastWithdrawTo;
    uint256 public lastWithdrawAmount;
    address public lastStakeWithdrawTo;

    receive() external payable {}

    function withdrawTo(address payable to, uint256 amount) external {
        lastWithdrawTo = to;
        lastWithdrawAmount = amount;
    }

    function unlockStake() external {
        unlocked = true;
    }

    function withdrawStake(address payable to) external {
        require(unlocked, "stake not unlocked");
        lastStakeWithdrawTo = to;
    }
}

contract MockERC20 {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
