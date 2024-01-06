// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @custom:storage-location erc7201:coinbase.storage.MultiOwnable
struct MultiOwnableStorage {
    /// @dev tracks the index of the next owner added, not useful after 255 owners added.
    uint8 nextOwnerIndex;
    /// @dev Allows an owner to be idenfitied by a uint8.
    /// Passkey verifier does not recover the address, but requires
    /// the X,Y coordinates to be passed for verification.
    /// In the context of checking whether something was signed by an owner
    /// this means that the signature needs to include an identifier of the owner.
    /// In an effort to economize calldata, we use a uint8 rather than passing the
    /// X,Y coordinates.
    mapping(uint8 => bytes) ownerAtIndex;
    mapping(bytes => bool) isOwner;
}

/// @notice Auth contract allowing multiple owners
/// identifies owners as bytes to allow for secp256r1 X,Y coordinates to
/// identify an owner.
/// Designed for use in smart account context.
contract MultiOwnable {
    /// keccak256(abi.encode(uint256(keccak256("coinbase.storage.MultiOwnable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant MultiOwnableStorageLocation =
        0x97e2c6aad4ce5d562ebfaa00db6b9e0fb66ea5d8162ed5b243f51a2e03086f00;

    error Unauthorized();
    error AlreadyOwner(bytes owner);
    error IndexNotEmpty(uint8 index, bytes owner);
    error UseAddOwner();
    error NoOwnerAtIndex(uint8 index);
    error InvalidOwnerBytesLength(bytes owner);
    error InvalidEthereumAddressOwner(bytes owner);

    event AddOwner(bytes indexed owner, bytes indexed addedBy, uint8 indexed index);
    event RemoveOwner(bytes indexed owner, bytes indexed removedBy, uint8 indexed index);

    modifier onlyOwner() virtual {
        _checkOwner();
        _;
    }

    /// @dev convenience function to add address owner
    /// can be used if nextOwnerIndex < 255
    function addOwner(address owner) public virtual onlyOwner {
        _addOwner(abi.encode(owner));
    }

    /// @dev convenience function to add passkey owner
    /// can be used if nextOwnerIndex < 255
    function addOwner(bytes32 x, bytes32 y) public virtual onlyOwner {
        _addOwner(abi.encode(x, y));
    }

    /// @dev adds an address owner at a specific index
    function addOwnerAtIndex(address owner, uint8 index) public virtual onlyOwner {
        _addOwnerAtIndex(abi.encode(owner), index);
    }

    /// @dev adds a passkey owner at a specific index
    function addOwnerAtIndex(bytes32 x, bytes32 y, uint8 index) public virtual onlyOwner {
        _addOwnerAtIndex(abi.encode(x, y), index);
    }

    /// @dev removes an owner, identified by a specific index
    function removeOwnerAtIndex(uint8 index) public virtual onlyOwner {
        bytes memory owner = ownerAtIndex(index);
        if (owner.length == 0) revert NoOwnerAtIndex(index);

        delete _getMultiOwnableStorage().isOwner[owner];
        delete _getMultiOwnableStorage().ownerAtIndex[index];

        // removedBy may be address(this) when used with smart account
        emit RemoveOwner(owner, abi.encode(msg.sender), index);
    }

    function isOwner(address account) public view virtual returns (bool) {
        return _getMultiOwnableStorage().isOwner[abi.encode(account)];
    }

    function isOwner(bytes calldata account) public view virtual returns (bool) {
        return _getMultiOwnableStorage().isOwner[account];
    }

    function isOwnerMemory(bytes memory account) public view virtual returns (bool) {
        return _getMultiOwnableStorage().isOwner[account];
    }

    function ownerAtIndex(uint8 index) public view virtual returns (bytes memory) {
        return _getMultiOwnableStorage().ownerAtIndex[index];
    }

    function nextOwnerIndex() public view virtual returns (uint8) {
        return _getMultiOwnableStorage().nextOwnerIndex;
    }

    function _initializeOwners(bytes[] memory owners) internal virtual {
        for (uint256 i = 0; i < owners.length; i++) {
            if (owners[i].length != 32 && owners[i].length != 64) {
                revert InvalidOwnerBytesLength(owners[i]);
            }
            if (owners[i].length == 32 && uint256(bytes32(owners[i])) > type(uint160).max) {
                revert InvalidEthereumAddressOwner(owners[i]);
            }
            _addOwnerAtIndexNoCheck(owners[i], _getMultiOwnableStorage().nextOwnerIndex++);
        }
    }

    /// @dev convenience function that can be used to add the first
    /// 255 owners.
    function _addOwner(bytes memory owner) public virtual onlyOwner {
        _addOwnerAtIndexNoCheck(owner, _getMultiOwnableStorage().nextOwnerIndex++);
    }

    /// @dev adds an owner, identified by a specific index
    /// Used after 255 addOwner calls
    /// reverts if nextOwnerIndex != 255
    /// reverts if ownerAtIndex[index] is set
    function _addOwnerAtIndex(bytes memory owner, uint8 index) public virtual onlyOwner {
        if (nextOwnerIndex() != 255) revert UseAddOwner();
        bytes memory existingOwner = ownerAtIndex(index);
        if (existingOwner.length != 0) revert IndexNotEmpty(index, existingOwner);

        _addOwnerAtIndexNoCheck(owner, index);
    }

    function _addOwnerAtIndexNoCheck(bytes memory owner, uint8 index) internal virtual {
        if (isOwnerMemory(owner)) revert AlreadyOwner(owner);

        _getMultiOwnableStorage().isOwner[owner] = true;
        _getMultiOwnableStorage().ownerAtIndex[index] = owner;

        emit AddOwner(owner, abi.encode(msg.sender), index);
    }

    /// @dev There is no logic in this contract
    /// to allow for address(this) to be msg.sender.
    /// This should be enabled in the inheriting contract
    /// to allow for a passkey owner to call these functions.
    function _checkOwner() internal view virtual {
        if (!isOwner(msg.sender)) if (msg.sender != address(this)) revert Unauthorized();
    }

    function _getMultiOwnableStorage() internal pure returns (MultiOwnableStorage storage $) {
        assembly {
            $.slot := MultiOwnableStorageLocation
        }
    }
}
