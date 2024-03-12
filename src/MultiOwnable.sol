// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Storage layout used by this contract.
///
/// @custom:storage-location erc7201:coinbase.storage.MultiOwnable
struct MultiOwnableStorage {
    /// @dev Tracks the index of the next owner to add.
    uint256 nextOwnerIndex;
    /// @dev Mapping of indices to raw owner bytes, used to idenfitied owners by their
    ///      uint256 id.
    ///
    ///      Some uses —-such as signature validation for secp256r1 public key owners—-
    ///      requires the caller to assert which owner signed. To economize calldata,
    ///      we allow an index to identify an owner, so that the full owner bytes do
    ///      not need to be passed.
    ///
    ///      The underlying raw bytes can either be:
    ///         - An abi encoded ethereum address
    ///         - The abi encoded public key (x, y) coordinates when using passkey.
    mapping(uint256 index => bytes owner) ownerAtIndex;
    /// @dev Mapping of raw bytes accounts to booleans indicating whether or not the
    ///      account is an owner of this contract.
    mapping(bytes account => bool isOwner_) isOwner;
}

/// @title Multi Ownable
///
/// @notice Auth contract allowing multiple owners, each identified as bytes.
///
/// @author Coinbase (https://github.com/coinbase/smart-wallet)
contract MultiOwnable {
    /// @dev Slot for the `MultiOwnableStorage` struct in storage.
    ///      Computed from: keccak256(abi.encode(uint256(keccak256("coinbase.storage.MultiOwnable")) - 1)) & ~bytes32(uint256(0xff))
    ///      Follows ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201).
    bytes32 private constant MUTLI_OWNABLE_STORAGE_LOCATION =
        0x97e2c6aad4ce5d562ebfaa00db6b9e0fb66ea5d8162ed5b243f51a2e03086f00;

    /// @notice Thrown when the sender is not an owner and is trying to call a privileged function.
    error Unauthorized();

    /// @notice Thrown when trying to add an already registered owner.
    ///
    /// @param owner The raw abi encoded owner bytes.
    error AlreadyOwner(bytes owner);

    /// @notice Thrown when trying to remove an owner from an index that is empty.
    ///
    /// @param index The targeted index for removal.
    error NoOwnerAtIndex(uint256 index);

    /// @notice Thrown when trying to intialize the contracts owners if a provided owner is neither
    ///         64 bytes long (for passkey) nor a valid address.
    ///
    /// @param owner The invalid raw abi encoded owner bytes.
    error InvalidOwnerBytesLength(bytes owner);

    /// @notice Thrown when trying to intialize the contracts owners if a provided owner is 32 bytes
    ///         long but does not fit in an `address` type (`uint160`).
    ///
    /// @param owner The invalid raw abi encoded owner bytes.
    error InvalidEthereumAddressOwner(bytes owner);

    /// @notice Emitted when a new owner is registered.
    ///
    /// @param index The owner index.
    /// @param owner The raw abi encoded owner bytes.
    event AddOwner(uint256 indexed index, bytes owner);

    /// @notice Emitted when an owner is removed.
    ///
    /// @param index The owner index.
    /// @param owner The raw abi encoded owner bytes.
    event RemoveOwner(uint256 indexed index, bytes owner);

    /// @notice Access control modifier ensuring the caller is an authorized owner
    modifier onlyOwner() virtual {
        _checkOwner();
        _;
    }

    /// @notice Convenience function to add a new owner address.
    ///
    /// @param owner The owner address.
    function addOwnerAddress(address owner) public virtual onlyOwner {
        _addOwner(abi.encode(owner));
    }

    /// @notice Convenience function to add a new owner passkey.
    ///
    /// @param x The owner public key x coordinate.
    /// @param y The owner public key y coordinate.
    function addOwnerPublicKey(bytes32 x, bytes32 y) public virtual onlyOwner {
        _addOwner(abi.encode(x, y));
    }

    /// @notice Removes an owner from the given `index`.
    ///
    /// @dev Reverts if the owner is not registered at `index`.
    ///
    /// @param index The index to remove from.
    function removeOwnerAtIndex(uint256 index) public virtual onlyOwner {
        bytes memory owner = ownerAtIndex(index);
        if (owner.length == 0) revert NoOwnerAtIndex(index);

        delete _getMultiOwnableStorage().isOwner[owner];
        delete _getMultiOwnableStorage().ownerAtIndex[index];

        emit RemoveOwner(index, owner);
    }

    /// @notice Checks if the given `account` address is registered as owner.
    ///
    /// @param account The account address to check.
    ///
    /// @return `true` if the account is an owner, else `false`.
    function isOwnerAddress(address account) public view virtual returns (bool) {
        return _getMultiOwnableStorage().isOwner[abi.encode(account)];
    }

    /// @notice Checks if the given `account` public key is registered as owner.
    ///
    /// @param x The public key x coordinate.
    /// @param y The public key y coordinate.
    ///
    /// @return `true` if the account is an owner, else `false`.
    function isOwnerPublicKey(bytes32 x, bytes32 y) public view virtual returns (bool) {
        return _getMultiOwnableStorage().isOwner[abi.encode(x, y)];
    }

    /// @notice Checks if the given `account` raw bytes is registered as owner.
    ///
    /// @param account The account to check identified by its address or passkey.
    ///
    /// @return `true` if the account is an owner, else `false`.
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

    /// @notice Initialize the owners of this contract.
    ///
    /// @dev Intended to be called when the smart account is first deployed.
    /// @dev Reverts if a provided owner is neither 64 bytes long (for passkey) nor a valid address.
    ///
    /// @param owners The intiial list of owners to register.
    function _initializeOwners(bytes[] memory owners) internal virtual {
        for (uint256 i; i < owners.length; i++) {
            if (owners[i].length != 32 && owners[i].length != 64) {
                revert InvalidOwnerBytesLength(owners[i]);
            }

            if (owners[i].length == 32 && uint256(bytes32(owners[i])) > type(uint160).max) {
                revert InvalidEthereumAddressOwner(owners[i]);
            }

            _addOwnerAtIndex(owners[i], _getMultiOwnableStorage().nextOwnerIndex++);
        }
    }

    /// @notice Convenience function used to add the first 255 owners.
    ///
    /// @param owner The owner raw bytes to add.
    function _addOwner(bytes memory owner) internal virtual {
        _addOwnerAtIndex(owner, _getMultiOwnableStorage().nextOwnerIndex++);
    }

    /// @notice Adds an owner at the given `index`.
    ///
    /// @dev Reverts if `owner` is already registered as an owner.
    ///
    /// @param owner The owner raw bytes to register.
    /// @param index The index to write to.
    function _addOwnerAtIndex(bytes memory owner, uint256 index) internal virtual {
        if (isOwnerBytes(owner)) revert AlreadyOwner(owner);

        _getMultiOwnableStorage().isOwner[owner] = true;
        _getMultiOwnableStorage().ownerAtIndex[index] = owner;

        emit AddOwner(index, owner);
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
