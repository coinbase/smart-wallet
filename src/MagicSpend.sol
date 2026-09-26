// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {Ownable} from "solady/auth/Ownable.sol";

contract MagicSpend is Ownable {
    constructor() {
        _initializeOwner(msg.sender);
    }

    struct WithdrawRequest {
        bytes signature;
        address asset;
        uint256 amount;
        uint256 nonce;
        uint48 expiry;
    }

    error InvalidSignature();
    error Expired();
    error InvalidNonce(uint256 nonce);
    error InvalidAddress();

    event MagicSpendWithdrawal(address indexed account, address indexed asset, uint256 amount, uint256 nonce);

    mapping(uint256 => mapping(address => bool)) private _nonceUsed;

    function withdraw(WithdrawRequest memory withdrawRequest) external {
        if (block.timestamp > withdrawRequest.expiry) revert Expired();
        if (!isValidWithdrawSignature(msg.sender, withdrawRequest)) revert InvalidSignature();
        _validateRequest(msg.sender, withdrawRequest);
        _withdraw(withdrawRequest.asset, msg.sender, withdrawRequest.amount);
        emit MagicSpendWithdrawal(msg.sender, withdrawRequest.asset, withdrawRequest.amount, withdrawRequest.nonce);
    }

    function ownerWithdraw(address asset, address to, uint256 amount) external onlyOwner {
        if (to == address(0)) revert InvalidAddress();
        _withdraw(asset, to, amount);
        emit MagicSpendWithdrawal(to, asset, amount, 0);
    }

    function entryPointDeposit() external payable onlyOwner {
        SafeTransferLib.safeTransferETH(entryPoint(), msg.value);
    }

    function entryPointWithdraw(address payable to, uint256 amount) external onlyOwner {
        if (to == address(0)) revert InvalidAddress();
        IEntryPoint(entryPoint()).withdrawTo(to, amount);
    }

    function entryPointAddStake(uint256 amount, uint32 unstakeDelaySeconds) external payable onlyOwner {
        IEntryPoint(entryPoint()).addStake{value: amount}(unstakeDelaySeconds);
    }

    function entryPointUnlockStake() external onlyOwner {
        IEntryPoint(entryPoint()).unlockStake();
    }

    function entryPointWithdrawStake(address payable to) external onlyOwner {
        if (to == address(0)) revert InvalidAddress();
        IEntryPoint(entryPoint()).withdrawStake(to);
    }

    function isValidWithdrawSignature(address account, WithdrawRequest memory withdrawRequest)
        public view returns (bool)
    {
        return SignatureCheckerLib.isValidSignatureNow(
            owner(), getHash(account, withdrawRequest), withdrawRequest.signature
        );
    }

    function getHash(address account, WithdrawRequest memory withdrawRequest) public view returns (bytes32) {
        return SignatureCheckerLib.toEthSignedMessageHash(
            abi.encode(
                address(this), account, block.chainid,
                withdrawRequest.asset, withdrawRequest.amount,
                withdrawRequest.nonce, withdrawRequest.expiry
            )
        );
    }

    function nonceUsed(address account, uint256 nonce) external view returns (bool) {
        return _nonceUsed[nonce][account];
    }

    function entryPoint() public pure returns (address) {
        return 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    }

    function _validateRequest(address account, WithdrawRequest memory withdrawRequest) internal {
        if (_nonceUsed[withdrawRequest.nonce][account]) revert InvalidNonce(withdrawRequest.nonce);
        _nonceUsed[withdrawRequest.nonce][account] = true;
    }

    function _withdraw(address asset, address to, uint256 amount) internal {
        if (asset == address(0)) {
            SafeTransferLib.safeTransferETH(to, amount);
        } else {
            SafeTransferLib.safeTransfer(asset, to, amount);
        }
    }
}
