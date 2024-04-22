// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

/// @notice Storage layout used by this contract.
///
/// @custom:storage-location erc7201:coinbase.storage.MultiOwnable
struct MultiOwnableStorage {
    /// @dev Tracks the index of the next owner to add.
    uint256 nextOwnerIndex;
    /// @dev Tracks number of owners that have been removed.
    uint256 removedOwnersCount;
    /// @dev Maps index to owner bytes, used to idenfitied owners via a uint256 index.
    ///
    ///      Some uses—-such as signature validation for secp256r1 public key owners—-
    ///      requires the caller to assert the public key of the caller. To economize calldata,
    ///      we allow an index to identify an owner, so that the full owner bytes do
    ///      not need to be passed.
    ///
    ///      The `owner` bytes should either be
    ///         - An ABI encoded Ethereum address
    ///         - An ABI encoded public key
    mapping(uint256 index => bytes owner) ownerAtIndex;
    /// @dev Mapping of bytes to booleans indicating whether or not
    ///      bytes_ is an owner of this contract.
    mapping(bytes bytes_ => bool isOwner_) isOwner;
}

/// @title Multi Ownable
///
/// @notice Auth contract allowing multiple owners, each identified as bytes.
///
/// @author Coinbase (https://github.com/coinbase/smart-wallet)
contract MultiOwnable {
    /// @dev Slot for the `MultiOwnableStorage` struct in storage.
    ///      Computed from
    ///      keccak256(abi.encode(uint256(keccak256("coinbase.storage.MultiOwnable")) - 1)) & ~bytes32(uint256(0xff))
    ///      Follows ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201).
    bytes32 private constant MUTLI_OWNABLE_STORAGE_LOCATION =
        0x97e2c6aad4ce5d562ebfaa00db6b9e0fb66ea5d8162ed5b243f51a2e03086f00;

    /// @notice Thrown when the `msg.sender` is not an owner and is trying to call a privileged function.
    error Unauthorized();

    /// @notice Thrown when trying to add an already registered owner.
    ///
    /// @param owner The owner bytes.
    error AlreadyOwner(bytes owner);

    /// @notice Thrown when trying to remove an owner from an index that is empty.
    ///
    /// @param index The targeted index for removal.
    error NoOwnerAtIndex(uint256 index);

    /// @notice Thrown when `owner` argument does not match owner found at index.
    ///
    /// @param index         The index of the owner to be removed.
    /// @param expectedOwner The owner passed in the remove call.
    /// @param actualOwner   The actual owner at `index`.
    error WrongOwnerAtIndex(uint256 index, bytes expectedOwner, bytes actualOwner);

    /// @notice Thrown when a provided owner is neither 64 bytes long (for public key)
    ///         nor a ABI encoded address.
    ///
    /// @param owner The invalid owner.
    error InvalidOwnerBytesLength(bytes owner);

    /// @notice Thrown if a provided owner is 32 bytes long but does not fit in an `address` type.
    ///
    /// @param owner The invalid owner.
    error InvalidEthereumAddressOwner(bytes owner);

    /// @notice Thrown when removeOwnerAtIndex is called and there is only one current owner.
    error LastOwner();

    /// @notice Thrown when removeLastOwner is called and there is more than one current owner.
    ///
    /// @param ownersRemaining The number of current owners.
    error NotLastOwner(uint256 ownersRemaining);

    /// @notice Emitted when a new owner is registered.
    ///
    /// @param index The owner index of the owner added.
    /// @param owner The owner added.
    event AddOwner(uint256 indexed index, bytes owner);

    /// @notice Emitted when an owner is removed.
    ///
    /// @param index The owner index of the owner removed.
    /// @param owner The owner removed.
    event RemoveOwner(uint256 indexed index, bytes owner);

    /// @notice Access control modifier ensuring the caller is an authorized owner
    modifier onlyOwner() virtual {
        _checkOwner();
        _;
    }

    /// @notice Adds a new Ethereum-address owner.
    ///
    /// @param owner The owner address.
    function addOwnerAddress(address owner) external virtual onlyOwner {
        _addOwnerAtIndex(abi.encode(owner), _getMultiOwnableStorage().nextOwnerIndex++);
    }

    /// @notice Adds a new public-key owner.
    ///
    /// @param x The owner public key x coordinate.
    /// @param y The owner public key y coordinate.
    function addOwnerPublicKey(bytes32 x, bytes32 y) external virtual onlyOwner {
        _addOwnerAtIndex(abi.encode(x, y), _getMultiOwnableStorage().nextOwnerIndex++);
    }

    /// @notice Removes owner at the given `index`.
    ///
    /// @dev Reverts if the owner is not registered at `index`.
    /// @dev Reverts if there is currently only one owner.
    /// @dev Reverts if `owner` does not match bytes found at `index`.
    ///
    /// @param index The index of the owner to be removed.
    /// @param owner The ABI encoded bytes of the owner to be removed.
    function removeOwnerAtIndex(uint256 index, bytes calldata owner) external virtual onlyOwner {
        if (ownerCount() == 1) {
            revert LastOwner();
        }

        _removeOwnerAtIndex(index, owner);
    }

    /// @notice Removes owner at the given `index`, which should be the only current owner.
    ///
    /// @dev Reverts if the owner is not registered at `index`.
    /// @dev Reverts if there is currently more than one owner.
    /// @dev Reverts if `owner` does not match bytes found at `index`.
    ///
    /// @param index The index of the owner to be removed.
    /// @param owner The ABI encoded bytes of the owner to be removed.
    function removeLastOwner(uint256 index, bytes calldata owner) external virtual onlyOwner {
        uint256 ownersRemaining = ownerCount();
        if (ownersRemaining > 1) {
            revert NotLastOwner(ownersRemaining);
        }

        _removeOwnerAtIndex(index, owner);
    }

    /// @notice Checks if the given `account` address is registered as owner.
    ///
    /// @param account The account address to check.
    ///
    /// @return `true` if the account is an owner else `false`.
    function isOwnerAddress(address account) public view virtual returns (bool) {
        return _getMultiOwnableStorage().isOwner[abi.encode(account)];
    }

    /// @notice Checks if the given `x`, `y` public key is registered as owner.
    ///
    /// @param x The public key x coordinate.
    /// @param y The public key y coordinate.
    ///
    /// @return `true` if the account is an owner else `false`.
    function isOwnerPublicKey(bytes32 x, bytes32 y) public view virtual returns (bool) {
        return _getMultiOwnableStorage().isOwner[abi.encode(x, y)];
    }

    /// @notice Checks if the given `account` bytes is registered as owner.
    ///
    /// @param account The account, should be ABI encoded address or public key.
    ///
    /// @return `true` if the account is an owner else `false`.
    function isOwnerBytes(bytes memory account) public view virtual returns (bool) {
        return _getMultiOwnableStorage().isOwner[account];
    }

    /// @notice Returns the owner bytes at the given `index`.
    ///
    /// @param index The index to lookup.
    ///
    /// @return The owner bytes (empty if no owner is registered at this `index`).
    function ownerAtIndex(uint256 index) public view virtual returns (bytes memory) {
        return _getMultiOwnableStorage().ownerAtIndex[index];
    }

    /// @notice Returns the next index that will be used to add a new owner.
    ///
    /// @return The next index that will be used to add a new owner.
    function nextOwnerIndex() public view virtual returns (uint256) {
        return _getMultiOwnableStorage().nextOwnerIndex;
    }

    /// @notice Returns the current number of owners
    ///
    /// @return The current owner count
    function ownerCount() public view virtual returns (uint256) {
        MultiOwnableStorage storage $ = _getMultiOwnableStorage();
        return $.nextOwnerIndex - $.removedOwnersCount;
    }

    /// @notice Tracks the number of owners removed
    ///
    /// @dev Used with `this.nextOwnerIndex` to avoid removing all owners
    ///
    /// @return The number of owners that have been removed.
    function removedOwnersCount() public view virtual returns (uint256) {
        return _getMultiOwnableStorage().removedOwnersCount;
    }

    /// @notice Initialize the owners of this contract.
    ///
    /// @dev Intended to be called contract is first deployed and never again.
    /// @dev Reverts if a provided owner is neither 64 bytes long (for public key) nor a valid address.
    ///
    /// @param owners The initial set of owners.
    function _initializeOwners(bytes[] memory owners) internal virtual {
        MultiOwnableStorage storage $ = _getMultiOwnableStorage();
        uint256 nextOwnerIndex_ = $.nextOwnerIndex;
        for (uint256 i; i < owners.length; i++) {
            if (owners[i].length != 32 && owners[i].length != 64) {
                revert InvalidOwnerBytesLength(owners[i]);
            }

            if (owners[i].length == 32 && uint256(bytes32(owners[i])) > type(uint160).max) {
                revert InvalidEthereumAddressOwner(owners[i]);
            }

            _addOwnerAtIndex(owners[i], nextOwnerIndex_++);
        }
        $.nextOwnerIndex = nextOwnerIndex_;
    }

    /// @notice Adds an owner at the given `index`.
    ///
    /// @dev Reverts if `owner` is already registered as an owner.
    ///
    /// @param owner The owner raw bytes to register.
    /// @param index The index to write to.
    function _addOwnerAtIndex(bytes memory owner, uint256 index) internal virtual {
        if (isOwnerBytes(owner)) revert AlreadyOwner(owner);

        MultiOwnableStorage storage $ = _getMultiOwnableStorage();
        $.isOwner[owner] = true;
        $.ownerAtIndex[index] = owner;

        emit AddOwner(index, owner);
    }

    /// @notice Removes owner at the given `index`.
    ///
    /// @dev Reverts if the owner is not registered at `index`.
    /// @dev Reverts if `owner` does not match bytes found at `index`.
    ///
    /// @param index The index of the owner to be removed.
    /// @param owner The ABI encoded bytes of the owner to be removed.
    function _removeOwnerAtIndex(uint256 index, bytes calldata owner) internal virtual {
        bytes memory owner_ = ownerAtIndex(index);
        if (owner_.length == 0) revert NoOwnerAtIndex(index);
        if (keccak256(owner_) != keccak256(owner)) {
            revert WrongOwnerAtIndex({index: index, expectedOwner: owner, actualOwner: owner_});
        }

        MultiOwnableStorage storage $ = _getMultiOwnableStorage();
        delete $.isOwner[owner];
        delete $.ownerAtIndex[index];
        $.removedOwnersCount++;

        emit RemoveOwner(index, owner);
    }

    /// @notice Checks if the sender is an owner of this contract or the contract itself.
    ///
    /// @dev Revert if the sender is not an owner fo the contract itself.
    function _checkOwner() internal view virtual {
        if (isOwnerAddress(msg.sender) || (msg.sender == address(this))) {
            return;
        }

        revert Unauthorized();
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
