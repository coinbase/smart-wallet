// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.21;

import {Receiver} from "solady/src/accounts/Receiver.sol";
import {UUPSUpgradeable} from "solady/src/utils/UUPSUpgradeable.sol";
import {SignatureCheckerLib} from "solady/src/utils/SignatureCheckerLib.sol";
import {UserOperation, UserOperationLib} from "account-abstraction/contracts/interfaces/UserOperation.sol";

import {MultiOwnable} from "./MultiOwnable.sol";
import {WebAuthn} from "./WebAuthn.sol";
import {ERC1271} from "./ERC1271.sol";

/// @notice Coinbase ERC4337 account, built on Solady Simple ERC4337 account implementation.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC4337.sol)
/// @author Wilson Cusack
contract ERC4337Account is MultiOwnable, UUPSUpgradeable, Receiver, ERC1271 {
    /// @dev Struct passed as signature in the userOp when a passkey has signed with webauthn.
    struct PasskeySignature {
        bytes authenticatorData;
        string clientDataJSON;
        uint256 r;
        uint256 s;
    }

    /// @dev Call struct for the `executeBatch` function.
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    error InvalidSignatureLength(uint256 length);
    error Initialized();
    error InvalidOwnerForSignature(uint8 ownerIndex, bytes owner);
    error Forbidden();

    /// @dev Requires that the caller is the EntryPoint, the owner, or the account itself.
    modifier onlyEntryPointOrOwner() virtual {
        if (msg.sender != entryPoint()) _checkOwner();
        _;
    }

    /// @dev Sends to the EntryPoint (i.e. `msg.sender`) the missing funds for this transaction.
    /// Subclass MAY override this modifier for better funds management.
    /// (e.g. send to the EntryPoint more than the minimum required, so that in future transactions
    /// it will not be required to send again)
    ///
    /// `missingAccountFunds` is the minimum value this modifier should send the EntryPoint,
    /// which MAY be zero, in case there is enough deposit, or the userOp has a paymaster.
    modifier payPrefund(uint256 missingAccountFunds) virtual {
        _;
        /// @solidity memory-safe-assembly
        assembly {
            if missingAccountFunds {
                // Ignore failure (it's EntryPoint's job to verify, not the account's).
                pop(call(gas(), caller(), missingAccountFunds, codesize(), 0x00, codesize(), 0x00))
            }
        }
    }

    /// @dev Requires that the caller is the EntryPoint.
    modifier onlyEntryPoint() virtual {
        if (msg.sender != entryPoint()) revert Unauthorized();
        _;
    }

    constructor() {
        // implementation should not be initializable
        // does not affect proxies which use their own storage.
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(address(0));
        _initializeOwners(owners);
    }

    /// @dev Initializes the account with the owner. Can only be called once.
    function initialize(bytes[] calldata owners) public payable virtual {
        if (nextOwnerIndex() != 0) {
            revert Initialized();
        }

        _initializeOwners(owners);
    }

    /// @dev Validates the signature and nonce.
    /// The EntryPoint will make the call to the recipient only if
    /// this validation call returns successfully.
    ///
    /// Signature failure should be reported by returning 1 (see: `_validateSignature`).
    /// This allows making a "simulation call" without a valid signature.
    /// Other failures (e.g. nonce mismatch, or invalid signature format)
    /// should still revert to signal failure.
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        public
        payable
        virtual
        onlyEntryPoint
        payPrefund(missingAccountFunds)
        returns (uint256 validationData)
    {
        // 0xbf6ba1fc = bytes4(keccak256("executeWithoutChainIdValidation(bytes)"))
        if (userOp.callData.length > 4 && bytes4(userOp.callData[0:4]) == 0xbf6ba1fc) {
            userOpHash = getUserOpHashWithoutChainId(userOp);
        }
        bool success = _validateSignature(userOpHash, userOp.signature);

        /// @solidity memory-safe-assembly
        assembly {
            // Returns 0 if the recovered address matches the owner.
            // Else returns 1, which is equivalent to:
            // `(success ? 0 : 1) | (uint256(validUntil) << 160) | (uint256(validAfter) << (160 + 48))`
            // where `validUntil` is 0 (indefinite) and `validAfter` is 0.
            validationData := iszero(success)
        }
    }

    /// @dev validateUserOp will recompute the userOp hash without the chain id
    /// if this function is being called. This allow certain operations to be replayed
    /// for all accounts sharing the same address across chains.
    /// E.g. This may be useful for syncing owner changes
    function executeWithoutChainIdValidation(bytes calldata data)
        public
        payable
        virtual
        onlyEntryPoint
        returns (bytes memory result)
    {
        if (!canSkipChainIdValidation(bytes4(data[0:4]))) {
            revert Forbidden();
        }

        bool success;
        (success, result) = address(this).call(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /// @dev Execute a call from this account.
    function execute(address target, uint256 value, bytes calldata data)
        public
        payable
        virtual
        onlyEntryPointOrOwner
        returns (bytes memory result)
    {
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(0x40)
            calldatacopy(result, data.offset, data.length)
            if iszero(call(gas(), target, value, result, data.length, codesize(), 0x00)) {
                // Bubble up the revert if the call reverts.
                returndatacopy(result, 0x00, returndatasize())
                revert(result, returndatasize())
            }
            mstore(result, returndatasize()) // Store the length.
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize()) // Copy the returndata.
            mstore(0x40, add(o, returndatasize())) // Allocate the memory.
        }
    }

    /// @dev Execute a sequence of calls from this account.
    function executeBatch(Call[] calldata calls)
        public
        payable
        virtual
        onlyEntryPointOrOwner
        returns (bytes[] memory results)
    {
        /// @solidity memory-safe-assembly
        assembly {
            results := mload(0x40)
            mstore(results, calls.length)
            let r := add(0x20, results)
            let m := add(r, shl(5, calls.length))
            calldatacopy(r, calls.offset, shl(5, calls.length))
            for { let end := m } iszero(eq(r, end)) { r := add(r, 0x20) } {
                let e := add(calls.offset, mload(r))
                let o := add(e, calldataload(add(e, 0x40)))
                calldatacopy(m, add(o, 0x20), calldataload(o))
                // forgefmt: disable-next-item
                if iszero(call(gas(), calldataload(e), calldataload(add(e, 0x20)),
                    m, calldataload(o), codesize(), 0x00)) {
                    // Bubble up the revert if the call reverts.
                    returndatacopy(m, 0x00, returndatasize())
                    revert(m, returndatasize())
                }
                mstore(r, m) // Append `m` into `results`.
                mstore(m, returndatasize()) // Store the length,
                let p := add(m, 0x20)
                returndatacopy(p, 0x00, returndatasize()) // and copy the returndata.
                m := add(p, returndatasize()) // Advance `m`.
            }
            mstore(0x40, m) // Allocate the memory.
        }
    }

    function verifySignature(bytes32 message, PasskeySignature memory signature, uint256 x, uint256 y)
        public
        view
        returns (bool)
    {
        return WebAuthn.verifySignature({
            challenge: abi.encode(message),
            authenticatorData: signature.authenticatorData,
            requireUserVerification: false,
            clientDataJSON: signature.clientDataJSON,
            challengeLocation: 23,
            responseTypeLocation: 1,
            r: signature.r,
            s: signature.s,
            x: x,
            y: y
        });
    }

    /// @dev Returns the canonical ERC4337 EntryPoint contract.
    /// Override this function to return a different EntryPoint.
    function entryPoint() public view virtual returns (address) {
        return 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    }

    function getUserOpHashWithoutChainId(UserOperation calldata userOp)
        public
        view
        virtual
        returns (bytes32 userOpHash)
    {
        return keccak256(abi.encode(UserOperationLib.hash(userOp), entryPoint()));
    }

    function canSkipChainIdValidation(bytes4 functionSelector) public pure returns (bool) {
        if (
            functionSelector == MultiOwnable.addOwnerPublicKey.selector
                || functionSelector == MultiOwnable.addOwnerAddress.selector
                || functionSelector == MultiOwnable.addOwnerAddressAtIndex.selector
                || functionSelector == MultiOwnable.addOwnerPublicKeyAtIndex.selector
                || functionSelector == MultiOwnable.removeOwnerAtIndex.selector
                || functionSelector == UUPSUpgradeable.upgradeToAndCall.selector
        ) {
            return true;
        }
        return false;
    }

    /// @dev Validate user op and 1271 signatures
    function _validateSignature(bytes32 message, bytes calldata signaturePacked)
        internal
        view
        virtual
        override
        returns (bool)
    {
        uint8 ownerIndex = uint8(bytes1(signaturePacked[0:1]));
        bytes calldata signature = signaturePacked[1:];
        bytes memory ownerBytes = ownerAtIndex(ownerIndex);

        if (signature.length == 65) {
            if (ownerBytes.length != 32) revert InvalidOwnerForSignature(ownerIndex, ownerBytes);
            if (uint256(bytes32(ownerBytes)) > type(uint160).max) {
                revert InvalidOwnerForSignature(ownerIndex, ownerBytes);
            }

            address owner;
            /// @solidity memory-safe-assembly
            assembly {
                owner := mload(add(ownerBytes, 32))
            }
            return SignatureCheckerLib.isValidSignatureNowCalldata(owner, message, signature);
        }

        // Passkey signature
        if (signature.length > 65) {
            if (ownerBytes.length != 64) revert InvalidOwnerForSignature(ownerIndex, ownerBytes);

            PasskeySignature memory sig = abi.decode(signature, (PasskeySignature));

            (uint256 x, uint256 y) = abi.decode(ownerBytes, (uint256, uint256));
            return verifySignature(message, sig, x, y);
        }

        revert InvalidSignatureLength(signature.length);
    }

    /// @dev To ensure that only the owner or the account itself can upgrade the implementation.
    function _authorizeUpgrade(address) internal virtual override(UUPSUpgradeable) onlyOwner {}

    function _domainNameAndVersion() internal pure override returns (string memory, string memory) {
        return ("Coinbase Smart Account", "1");
    }
}
