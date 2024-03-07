// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @custom:storage-location erc7201:coinbase.storage.MultiOwnable
struct MultiOwnableStorage {
    /// @dev tracks the index of the next owner added
    uint256 nextOwnerIndex;
    /// @dev Allows an owner to be idenfitied by a uint256.
    /// Some uses--such as signature validation for secp256r1 public
    /// key owners--requires the caller to assert which owner signed.
    /// To economize calldata, we allow an index to identify an owner,
    /// so that the full owner bytes do not need to be passed.
    /// Note, we use uint256 rather than a smaller uint because it
    /// provides flexibility at little to no cost.
    /// uint256 allows that we will (practically) never run out of owner indexes.
    /// And on L2, where calldata gas is a concern,
    /// we should not be charged for the extra 0 bytes.
    mapping(uint256 => bytes) ownerAtIndex;
    mapping(bytes => bool) isOwner;
}

/// @title Multi Ownable
/// @notice Auth contract allowing multiple owners, each identified as bytes.
/// @author Coinbase (https://github.com/coinbase/smart-wallet)
contract MultiOwnable {
    /// keccak256(abi.encode(uint256(keccak256("coinbase.storage.MultiOwnable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant MultiOwnableStorageLocation =
        0x97e2c6aad4ce5d562ebfaa00db6b9e0fb66ea5d8162ed5b243f51a2e03086f00;

    error Unauthorized();
    error AlreadyOwner(bytes owner);
    error NoOwnerAtIndex(uint256 index);
    error InvalidOwnerBytesLength(bytes owner);
    error InvalidEthereumAddressOwner(bytes owner);

    event AddOwner(uint256 indexed index, bytes owner);
    event RemoveOwner(uint256 indexed index, bytes owner);

    modifier onlyOwner() virtual {
        _checkOwner();
        _;
    }

    /// @dev convenience function to add address owner
    function addOwnerAddress(address owner) public virtual onlyOwner {
        _addOwner(abi.encode(owner));
    }

    /// @dev convenience function to add passkey owner
    function addOwnerPublicKey(bytes32 x, bytes32 y) public virtual onlyOwner {
        _addOwner(abi.encode(x, y));
    }

    /// @dev removes an owner, identified by a specific index
    function removeOwnerAtIndex(uint8 index) public virtual onlyOwner {
        bytes memory owner = ownerAtIndex(index);
        if (owner.length == 0) revert NoOwnerAtIndex(index);

        delete _getMultiOwnableStorage().isOwner[owner];
        delete _getMultiOwnableStorage().ownerAtIndex[index];

        // removedBy may be address(this) when used with smart account
        emit RemoveOwner(index, owner);
    }

    function isOwnerAddress(address account) public view virtual returns (bool) {
        return _getMultiOwnableStorage().isOwner[abi.encode(account)];
    }

    function isOwnerBytes(bytes memory account) public view virtual returns (bool) {
        return _getMultiOwnableStorage().isOwner[account];
    }

    function isOwnerPublicKey(bytes32 x, bytes32 y) public view virtual returns (bool) {
        return _getMultiOwnableStorage().isOwner[abi.encode(x, y)];
    }

    function ownerAtIndex(uint256 index) public view virtual returns (bytes memory) {
        return _getMultiOwnableStorage().ownerAtIndex[index];
    }

    function nextOwnerIndex() public view virtual returns (uint256) {
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
            _addOwnerAtIndex(owners[i], _getMultiOwnableStorage().nextOwnerIndex++);
        }
    }

    function _addOwner(bytes memory owner) internal virtual {
        _addOwnerAtIndex(owner, _getMultiOwnableStorage().nextOwnerIndex++);
    }

    function _addOwnerAtIndex(bytes memory owner, uint256 index) internal virtual {
        if (isOwnerBytes(owner)) revert AlreadyOwner(owner);

        _getMultiOwnableStorage().isOwner[owner] = true;
        _getMultiOwnableStorage().ownerAtIndex[index] = owner;

        emit AddOwner(index, owner);
    }

    /// @dev There is no logic in this contract
    /// to allow for address(this) to be msg.sender.
    /// This should be enabled in the inheriting contract
    /// to allow for a passkey owner to call these functions.
    function _checkOwner() internal view virtual {
        if (!isOwnerAddress(msg.sender)) if (msg.sender != address(this)) revert Unauthorized();
    }

    function _getMultiOwnableStorage() internal pure returns (MultiOwnableStorage storage $) {
        assembly ("memory-safe") {
            $.slot := MultiOwnableStorageLocation
        }
    }
}
