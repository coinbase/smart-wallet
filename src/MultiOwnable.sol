// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

/// @notice Storage layout used by this contract.
///
/// @custom:storage-location erc7201:coinbase.storage.MultiOwnable
struct MultiOwnableStorage {
    /// @dev Tracks the owner count.
    uint256 ownerCount;
    /// @dev Mapping of Keyspace keys to `KeyspaceKeyType`.
    mapping(uint256 ksKey => MultiOwnable.KeyspaceKeyType ksKeyType) ksKeyTypes;
}

/// @title Multi Ownable
///
/// @notice Auth contract allowing multiple Keyspace key owners.
///
/// @author Coinbase (https://github.com/coinbase/smart-wallet)
contract MultiOwnable {
    /// @notice The supported Keyspace key types.
    ///
    /// @dev `None` is intentionnaly placed first so that it equals the default unset value.
    ///      It is never allowed to register a new Keyspace key as an owner with type `None`.
    enum KeyspaceKeyType {
        None,
        EOA,
        WebAuthn
    }

    /// @notice Wrapper struct of a Keyspace key and its type.
    ///
    /// @dev This struct is never stored in storage and only used to group function parameters.
    struct KeyAndType {
        /// @dev The Keyspace key.
        uint256 ksKey;
        /// @dev The Keyspace key type.
        KeyspaceKeyType ksKeyType;
    }

    /// @dev Slot for the `MultiOwnableStorage` struct in storage.
    ///      Computed from
    ///      keccak256(abi.encode(uint256(keccak256("coinbase.storage.MultiOwnable")) - 1)) & ~bytes32(uint256(0xff))
    ///      Follows ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201).
    bytes32 private constant MUTLI_OWNABLE_STORAGE_LOCATION =
        0x97e2c6aad4ce5d562ebfaa00db6b9e0fb66ea5d8162ed5b243f51a2e03086f00;

    /// @notice Thrown when the `msg.sender` is not authorized to call a privileged function.
    error Unauthorized();

    /// @notice Thrown when trying to add a Keyspace key as an owner and providing a `KeyspaceKeyType.None` type.
    error KeyspaceKeyTypeCantBeNone();

    /// @notice Thrown when trying to add an already registered owner.
    ///
    /// @param ksKey The Keyspace key.
    error AlreadyOwner(uint256 ksKey);

    /// @notice Thrown when trying to remove an unregistered owner.
    ///
    /// @param ksKey The Keyspace key.
    error NotAnOwner(uint256 ksKey);

    /// @notice Thrown when `removeOwner` is called and there is only one current owner.
    error LastOwner();

    /// @notice Thrown when `removeLastOwner` is called and there is more than one current owner.
    ///
    /// @param ownersRemaining The number of current owners.
    error NotLastOwner(uint256 ownersRemaining);

    /// @notice Emitted when a new owner is registered.
    ///
    /// @param ksKey The Keyspace key added.
    event OwnerAdded(uint256 indexed ksKey);

    /// @notice Emitted when an owner is removed.
    ///
    /// @param ksKey The Keyspace key removed.
    event OwnerRemoved(uint256 indexed ksKey);

    /// @notice Access control modifier ensuring the call is originating from the contract itself.
    modifier onlySelf() virtual {
        _ensureIsSelf();
        _;
    }

    /// @notice Adds a new Keyspace key owner.
    ///
    /// @dev Reverts if the `ksKey` is already an owner.
    ///
    /// @param ksKey The Keyspace key.
    function addOwner(uint256 ksKey, KeyspaceKeyType ksKeyType) external virtual onlySelf {
        // Ensure the user is not adding a `None` type.
        if (ksKeyType == KeyspaceKeyType.None) {
            revert KeyspaceKeyTypeCantBeNone();
        }

        // Ensure the Keyspace key is not already registered.
        if (keyspaceKeyType(ksKey) != KeyspaceKeyType.None) revert AlreadyOwner(ksKey);

        _getMultiOwnableStorage().ownerCount += 1;
        _addOwner(ksKey, ksKeyType);
    }

    /// @notice Removes a Keyspace key owner.
    ///
    /// @dev Reverts if there is currently only one owner.
    /// @dev Reverts if `ksKey` is not an owner.
    ///
    /// @param ksKey The Keyspace key to be removed.
    function removeOwner(uint256 ksKey) external virtual onlySelf {
        if (ownerCount() == 1) {
            revert LastOwner();
        }

        _removeOwner(ksKey);
    }

    /// @notice Removes the last Keyspace key owner.
    ///
    /// @dev Reverts if there are more than one owners registered.
    /// @dev Reverts if `ksKey` is not an owner.
    ///
    /// @param ksKey The Keyspace key to be removed.
    function removeLastOwner(uint256 ksKey) external virtual onlySelf {
        uint256 ownersRemaining = ownerCount();
        if (ownersRemaining > 1) {
            revert NotLastOwner(ownersRemaining);
        }

        _removeOwner(ksKey);
    }

    /// @notice Returns the given Keyspace key type.
    ///
    /// @param ksKey The Keyspace key.
    ///
    /// @return The Keyspace key type. `KeyspaceKeyType.None` is returned when `ksKey` is not registered as an owner of
    ///         this account.
    function keyspaceKeyType(uint256 ksKey) public view virtual returns (KeyspaceKeyType) {
        return _getMultiOwnableStorage().ksKeyTypes[ksKey];
    }

    /// @notice Returns the current number of owners.
    ///
    /// @return The current owner count.
    function ownerCount() public view virtual returns (uint256) {
        return _getMultiOwnableStorage().ownerCount;
    }

    /// @notice Initializes the owners of this contract.
    ///
    /// @dev Intended to be called contract is first deployed and never again.
    /// @dev Reverts if a provided owner is neither 64 bytes long (for public key) nor a valid address.
    ///
    /// @param ksKeys The initial Keyspace keys to register as owners.
    function _initializeOwners(KeyAndType[] memory ksKeys) internal virtual {
        MultiOwnableStorage storage $ = _getMultiOwnableStorage();
        $.ownerCount += ksKeys.length;

        for (uint256 i; i < ksKeys.length; i++) {
            _addOwner(ksKeys[i].ksKey, ksKeys[i].ksKeyType);
        }
    }

    /// @notice Adds a new owner.
    ///
    /// @dev Reverts if `ksKey` is already an owner.
    ///
    /// @param ksKey The Keyspace key.
    function _addOwner(uint256 ksKey, KeyspaceKeyType ksKeyType) internal virtual {
        _getMultiOwnableStorage().ksKeyTypes[ksKey] = ksKeyType;
        emit OwnerAdded(ksKey);
    }

    /// @notice Removes an owner.
    ///
    /// @dev Reverts if `ksKey` is not an owner.
    ///
    /// @param ksKey The Keyspace key to be removed.
    function _removeOwner(uint256 ksKey) internal virtual {
        if (keyspaceKeyType(ksKey) == KeyspaceKeyType.None) {
            revert NotAnOwner(ksKey);
        }

        MultiOwnableStorage storage $ = _getMultiOwnableStorage();
        delete $.ksKeyTypes[ksKey];
        $.ownerCount -= 1;

        emit OwnerRemoved(ksKey);
    }

    /// @notice Checks if the sender is the account itself.
    ///
    /// @dev Reverts if the sender is not the contract itself.
    function _ensureIsSelf() internal view virtual {
        if (msg.sender != address(this)) {
            revert Unauthorized();
        }
    }

    /// @notice Helper function to get a storage reference to the `MultiOwnableStorage` struct.
    ///
    /// @return $ A storage reference to the `MultiOwnableStorage` struct.
    function _getMultiOwnableStorage() internal pure returns (MultiOwnableStorage storage $) {
        assembly ("memory-safe") {
            $.slot := MUTLI_OWNABLE_STORAGE_LOCATION
        }
    }
}
