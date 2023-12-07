// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import {Receiver} from "solady/src/accounts/Receiver.sol";
import {UUPSUpgradeable} from "solady/src/utils/UUPSUpgradeable.sol";
import {SignatureCheckerLib} from "solady/src/utils/SignatureCheckerLib.sol";

import {MultiOwnable} from "./MultiOwnable.sol";
import {Signature, PasskeyVerifier} from "./PasskeyVerifier.sol";

/// @notice Coinbase ERC4337 account, built on Solady Simple ERC4337 account implementation.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC4337.sol)
/// @author Wilson Cusack 
contract ERC4337 is MultiOwnable, UUPSUpgradeable, Receiver {
    /// @dev prevents reinitialization
    bool internal _initialized;

    /// @dev The ERC4337 user operation (userOp) struct.
    struct UserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        uint256 callGasLimit;
        uint256 verificationGasLimit;
        uint256 preVerificationGas;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        bytes paymasterAndData;
        bytes signature;
    }

    /// @dev Struct passed as signature in the userOp when a passkey has signed with webauthn.
    struct PasskeySignature {
        bytes authenticatorData;
        string clientDataJSON;
        uint256 r;
        uint256 s;
        uint8 ownerIndex;
    }

    /// @dev Call struct for the `executeBatch` function.
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    error InvalidSignatureLength(uint256 length);
    error Initialized();

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

    /// @dev Initializes the account with the owner. Can only be called once.
    function initialize(bytes[] calldata owners) public payable virtual {
        if (_initialized) revert Initialized();
        _initialized = true;
        _initializeOwner(owners);
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
        bool success = _validateSignature(abi.encode(userOpHash), userOp.signature);

        assembly {
            // Returns 0 if the recovered address matches the owner.
            // Else returns 1, which is equivalent to:
            // `(success ? 0 : 1) | (uint256(validUntil) << 160) | (uint256(validAfter) << (160 + 48))`
            // where `validUntil` is 0 (indefinite) and `validAfter` is 0.
            validationData := iszero(success)
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

    /// @dev Validates the signature with ERC1271 return,
    /// so that this account can also be used as a signer.
    function isValidSignature(bytes32 message, bytes calldata signature) public view virtual returns (bytes4 result) {
        if (_validateSignature(abi.encode(message), signature)) {
            return 0x1626ba7e; // ERC1271_MAGICVALUE
        }
        return 0xffffffff; // ERC1271_REJECT_MAGICVALUE
    }

    function verifySignature(bytes memory message, Signature memory signature, uint256 x, uint256 y)
        public
        view
        returns (bool)
    {
        return WebAuthn.verifySignature({
            challenge: message,
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

    /// @dev Validate `userOp.signature` for the `userOpHash`.
    function _validateSignature(bytes memory message, bytes calldata signature) public view virtual returns (bool) {
        // ECDA + 1 byte 
        if (signature.length == 66) {
            // first byte is owner index
            uint8 index = uint8(bytes1(signature[0:1]));
            bytes memory ownerBytes = ownerAtIndex[index];
            address owner;
            assembly {
                owner := mload(add(ownerBytes, 32))
            }
            return SignatureCheckerLib.isValidSignatureNow(owner, bytes32(message), signature[1:]);
        }

        // Passkey signature
        if (signature.length > 66) {
            Signature memory sig = abi.decode(signature, (Signature));
            (uint256 x, uint256 y) = abi.decode(ownerAtIndex[sig.ownerIndex], (uint256, uint256));
            return verifySignature(message, sig, x, y);
        }

        revert InvalidSignatureLength(signature.length);
    }

    /// @dev To ensure that only the owner or the account itself can upgrade the implementation.
    function _authorizeUpgrade(address) internal virtual override(UUPSUpgradeable) onlyOwner {}
}
