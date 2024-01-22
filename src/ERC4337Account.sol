// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.21;

import {Receiver} from "solady/src/accounts/Receiver.sol";
import {UUPSUpgradeable} from "solady/src/utils/UUPSUpgradeable.sol";
import {SignatureCheckerLib} from "solady/src/utils/SignatureCheckerLib.sol";
import {UserOperation, UserOperationLib} from "account-abstraction/contracts/interfaces/UserOperation.sol";
import {WebAuthn} from "./WebAuthn.sol";

import {MultiOwnable} from "./MultiOwnable.sol";
import {ERC1271} from "./ERC1271.sol";

/// @notice Coinbase ERC4337 account, built on Solady ERC4337 account implementation
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC4337.sol)
/// @author Wilson Cusack
contract ERC4337Account is MultiOwnable, UUPSUpgradeable, Receiver, ERC1271 {
    /// @dev Signature struct which should be encoded as bytes for any signature
    /// passed to this contract, via ERC-4337 or ERC-1271.
    struct SignatureWrapper {
        /// @dev Index indentifying owner, see MultiOwnable
        uint8 ownerIndex;
        /// @dev ECDSA signature or WebAuthnAuth struct
        bytes signatureData;
    }

    /// @dev Call struct for the `executeBatch` function.
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    /// @dev The nonce key reserve for UserOperations without
    /// chain id validation. Goal is to help ensure users
    /// have a single, sequential cross-chain history.
    uint256 public constant REPLAYABLE_NONCE_KEY = 8453;

    error InvalidSignatureLength(uint256 length);
    error Initialized();
    error InvalidOwnerForSignature(uint8 ownerIndex, bytes owner);
    error SelectorNotAllowed(bytes4 selector);
    error InvalidNonceKey(uint256 key);

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
        uint256 key = userOp.nonce >> 64;
        // 0xbf6ba1fc = bytes4(keccak256("executeWithoutChainIdValidation(bytes)"))
        if (userOp.callData.length >= 4 && bytes4(userOp.callData[0:4]) == 0xbf6ba1fc) {
            userOpHash = getUserOpHashWithoutChainId(userOp);
            if (key != REPLAYABLE_NONCE_KEY) {
                revert InvalidNonceKey(key);
            }
        } else {
            if (key == REPLAYABLE_NONCE_KEY) {
                revert InvalidNonceKey(key);
            }
        }

        // Returns 0 if the recovered address matches the owner.
        // Else returns 1, which is equivalent to:
        // `(success ? 0 : 1) | (uint256(validUntil) << 160) | (uint256(validAfter) << (160 + 48))`
        // where `validUntil` is 0 (indefinite) and `validAfter` is 0.
        if (_validateSignature(userOpHash, userOp.signature)) {
            return 0;
        }

        return 1;
    }

    /// @dev validateUserOp will recompute the userOp hash without the chain id
    /// if this function is being called. This allow certain operations to be replayed
    /// for all accounts sharing the same address across chains.
    /// E.g. This may be useful for syncing owner changes
    function executeWithoutChainIdValidation(bytes calldata data) public payable virtual onlyEntryPoint {
        bytes4 selector = bytes4(data[0:4]);
        if (!canSkipChainIdValidation(selector)) {
            revert SelectorNotAllowed(selector);
        }

        _call(address(this), 0, data);
    }

    /// @dev Execute a call from this account.
    function execute(address target, uint256 value, bytes calldata data) public payable virtual onlyEntryPointOrOwner {
        _call(target, value, data);
    }

    /// @dev Execute a sequence of calls from this account.
    function executeBatch(Call[] calldata calls) public payable virtual onlyEntryPointOrOwner {
        for (uint256 i = 0; i < calls.length;) {
            _call(calls[i].target, calls[i].value, calls[i].data);
            unchecked {
                ++i;
            }
        }
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

    // From https://github.com/alchemyplatform/light-account/blob/912340322f7855cbc1d333ddaac2d39c74b4dcc6/src/LightAccount.sol#L347C5-L354C6
    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /// @dev Validate user op and 1271 signatures
    function _validateSignature(bytes32 message, bytes calldata wrappedSignatureBytes)
        internal
        view
        virtual
        override
        returns (bool)
    {
        SignatureWrapper memory sigWrapper = abi.decode(wrappedSignatureBytes, (SignatureWrapper));
        bytes memory ownerBytes = ownerAtIndex(sigWrapper.ownerIndex);

        if (sigWrapper.signatureData.length == 65) {
            if (ownerBytes.length != 32) revert InvalidOwnerForSignature(sigWrapper.ownerIndex, ownerBytes);
            if (uint256(bytes32(ownerBytes)) > type(uint160).max) {
                revert InvalidOwnerForSignature(sigWrapper.ownerIndex, ownerBytes);
            }

            address owner;
            /// @solidity memory-safe-assembly
            assembly {
                owner := mload(add(ownerBytes, 32))
            }
            return SignatureCheckerLib.isValidSignatureNow(owner, message, sigWrapper.signatureData);
        }

        // Passkey signature
        if (sigWrapper.signatureData.length > 65) {
            if (ownerBytes.length != 64) revert InvalidOwnerForSignature(sigWrapper.ownerIndex, ownerBytes);

            (uint256 x, uint256 y) = abi.decode(ownerBytes, (uint256, uint256));

            WebAuthn.WebAuthnAuth memory auth = abi.decode(sigWrapper.signatureData, (WebAuthn.WebAuthnAuth));

            auth.origin = bytes(auth.origin).length > 0 ? auth.origin : "https://sign.coinbase.com";

            return WebAuthn.verify({challenge: abi.encode(message), webAuthnAuth: auth, x: x, y: y});
        }

        revert InvalidSignatureLength(sigWrapper.signatureData.length);
    }

    /// @dev To ensure that only the owner or the account itself can upgrade the implementation.
    function _authorizeUpgrade(address) internal virtual override(UUPSUpgradeable) onlyOwner {}

    function _domainNameAndVersion() internal pure override returns (string memory, string memory) {
        return ("Coinbase Smart Account", "1");
    }
}
