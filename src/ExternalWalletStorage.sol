// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @title External Wallet Storage
/// @notice Singleton contract for storing wallet state, protected by caller address and code hash
contract ExternalWalletStorage {
    /// @notice Storage layout used by each wallet instance
    struct WalletStorage {
        uint256 nextOwnerIndex;
        uint256 removedOwnersCount;
        mapping(uint256 index => bytes owner) ownerAtIndex;
        mapping(bytes bytes_ => bool isOwner_) isOwner;
    }

    /// @notice Maps (wallet address, wallet code hash) to wallet storage
    mapping(address => mapping(bytes32 => WalletStorage)) private walletStorage;

    /// @notice Access denied - caller must have expected code hash
    error UnauthorizedAccess();

    /// @dev Validates caller has expected code hash
    function _validateCaller(bytes32 expectedCodeHash) internal view {
        bytes32 callerCodeHash;
        assembly {
            callerCodeHash := extcodehash(caller())
        }

        if (callerCodeHash != expectedCodeHash) {
            revert UnauthorizedAccess();
        }
    }

    /// @notice Gets the next owner index
    function getNextOwnerIndex(bytes32 expectedCodeHash) external view returns (uint256) {
        _validateCaller(expectedCodeHash);
        return walletStorage[msg.sender][expectedCodeHash].nextOwnerIndex;
    }

    /// @notice Gets the removed owners count
    function getRemovedOwnersCount(bytes32 expectedCodeHash) external view returns (uint256) {
        _validateCaller(expectedCodeHash);
        return walletStorage[msg.sender][expectedCodeHash].removedOwnersCount;
    }

    /// @notice Gets owner at index
    function getOwnerAtIndex(bytes32 expectedCodeHash, uint256 index) external view returns (bytes memory) {
        _validateCaller(expectedCodeHash);
        return walletStorage[msg.sender][expectedCodeHash].ownerAtIndex[index];
    }

    /// @notice Checks if bytes is an owner
    function isOwner(bytes32 expectedCodeHash, bytes calldata ownerBytes) external view returns (bool) {
        _validateCaller(expectedCodeHash);
        return walletStorage[msg.sender][expectedCodeHash].isOwner[ownerBytes];
    }

    /// @notice Sets the next owner index
    function setNextOwnerIndex(bytes32 expectedCodeHash, uint256 value) external {
        _validateCaller(expectedCodeHash);
        walletStorage[msg.sender][expectedCodeHash].nextOwnerIndex = value;
    }

    /// @notice Sets the removed owners count
    function setRemovedOwnersCount(bytes32 expectedCodeHash, uint256 value) external {
        _validateCaller(expectedCodeHash);
        walletStorage[msg.sender][expectedCodeHash].removedOwnersCount = value;
    }

    /// @notice Sets owner at index
    function setOwnerAtIndex(bytes32 expectedCodeHash, uint256 index, bytes calldata owner) external {
        _validateCaller(expectedCodeHash);
        walletStorage[msg.sender][expectedCodeHash].ownerAtIndex[index] = owner;
    }

    /// @notice Sets isOwner flag
    function setIsOwner(bytes32 expectedCodeHash, bytes calldata ownerBytes, bool value) external {
        _validateCaller(expectedCodeHash);
        walletStorage[msg.sender][expectedCodeHash].isOwner[ownerBytes] = value;
    }
}
