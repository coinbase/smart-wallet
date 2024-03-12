// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Receiver} from "solady/accounts/Receiver.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {UserOperation, UserOperationLib} from "account-abstraction/interfaces/UserOperation.sol";
import {WebAuthn} from "webauthn-sol/WebAuthn.sol";

import {ERC1271} from "./ERC1271.sol";
import {MultiOwnable} from "./MultiOwnable.sol";

/// @title Coinbase Smart Wallet
///
/// @notice ERC4337-compatible smart contract wallet, based on Solady ERC4337 account implementation
///         with inspiration from Alchemy's LightAccount and Daimo's DaimoAccount.
///
/// @author Coinbase (https://github.com/coinbase/smart-wallet)
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC4337.sol)
contract CoinbaseSmartWallet is MultiOwnable, UUPSUpgradeable, Receiver, ERC1271 {
    /// @notice Wrapper struct, used during signature validation, tie a signature with its signer.
    struct SignatureWrapper {
        /// @dev The index indentifying owner (see MultiOwnable) who signed.
        uint256 ownerIndex;
        /// @dev An ABI encoded ECDSA signature (r, s, v) or WebAuthnAuth struct.
        bytes signatureData;
    }

    /// @notice Wrapper struct, used in `executeBatch`, describing a raw call to execute.
    struct Call {
        /// @dev The target address to call.
        address target;
        /// @dev The value to associate with the call.
        uint256 value;
        /// @dev The raw call data.
        bytes data;
    }

    /// @notice Reserved nonce key (upper 192 bits of `UserOperation.nonce`) for cross-chain replayable
    ///         transactions.
    ///
    /// @dev Helps enforce sequential sequencing of replayable transactions.
    uint256 public constant REPLAYABLE_NONCE_KEY = 8453;

    /// @notice Thrown when trying to re-initialize an account.
    error Initialized();

    /// @notice Thrown when executing a `UserOperation` that requires the chain ID to be validated
    ///         but this validation has been omitted.
    ///
    /// @dev Whitelisting of `UserOperation`s that are allowed to skip the chain ID validation is
    ///      based on their call selectors (see `canSkipChainIdValidation()`).
    ///
    /// @param selector The user operation call selector that raised the error.
    error SelectorNotAllowed(bytes4 selector);

    /// @notice Thrown during a `UserOperation` validation when its key is invalid.
    ///
    /// @dev The `UserOperation` key validation is based on the `UserOperation` call selector.
    ///
    /// @param key The invalid `UserOperation` key.
    error InvalidNonceKey(uint256 key);

    /// @notice Reverts if the caller is not the EntryPoint.
    modifier onlyEntryPoint() virtual {
        if (msg.sender != entryPoint()) {
            revert Unauthorized();
        }

        _;
    }

    /// @notice Reverts if the caller is neither the EntryPoint, the owner, nor the account itself.
    modifier onlyEntryPointOrOwner() virtual {
        if (msg.sender != entryPoint()) {
            _checkOwner();
        }

        _;
    }

    /// @notice Sends to the EntryPoint (i.e. `msg.sender`) the missing funds for this transaction.
    ///
    /// @dev Subclass MAY override this modifier for better funds management (e.g. send to the
    ///      EntryPoint more than the minimum required, so that in future transactions it will not
    ///      be required to send again).
    ///
    /// @param missingAccountFunds The minimum value this modifier should send the EntryPoint which
    ///                            MAY be zero, in case there is enough deposit, or the userOp has a
    ///                            paymaster.
    modifier payPrefund(uint256 missingAccountFunds) virtual {
        _;

        assembly ("memory-safe") {
            if missingAccountFunds {
                // Ignore failure (it's EntryPoint's job to verify, not the account's).
                pop(call(gas(), caller(), missingAccountFunds, codesize(), 0x00, codesize(), 0x00))
            }
        }
    }

    constructor() {
        // Implementation should not be initializable (does not affect proxies which use their own storage).
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(address(0));
        _initializeOwners(owners);
    }

    /// @notice Initializes the account with the the given owners.
    ///
    /// @dev Reverts if the account has already been initialized.
    ///
    /// @param owners The initial array of owners to initialize this account with.
    function initialize(bytes[] calldata owners) public payable virtual {
        if (nextOwnerIndex() != 0) {
            revert Initialized();
        }

        _initializeOwners(owners);
    }

    /// @notice Custom implemenentation of the ERC-4337 `validateUserOp` method. The EntryPoint will
    ///         make the call to the recipient only if this validation call returns successfully.
    ///         See `IAccount.validateUserOp()`.
    ///
    /// @dev Signature failure should be reported by returning 1 (see: `_validateSignature()`). This
    ///      allows making a "simulation call" without a valid signature. Other failures (e.g. nonce
    ///      mismatch, or invalid signature format) should still revert to signal failure.
    /// @dev Reverts if the `UserOperation` key is invalid.
    /// @dev Reverts if the signature verification fails (except for the case mentionned earlier).
    ///
    /// @param userOp              The `UserOperation` to validate.
    /// @param userOpHash          The `UserOperation` hash (including the chain ID).
    /// @param missingAccountFunds The missing account funds that must be deposited on the Entrypoint.
    ///
    /// @return validationData The encoded `ValidationData` structure.
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

        // Return 0 if the recovered address matches the owner.
        if (_validateSignature(userOpHash, userOp.signature)) {
            return 0;
        }

        // Else return 1, which is equivalent to:
        // `(uint256(validAfter) << (160 + 48)) | (uint256(validUntil) << 160) | (success ? 0 : 1)`
        // where `validUntil` is 0 (indefinite) and `validAfter` is 0.
        return 1;
    }

    /// @notice Execute the given call from this account to this account (i.e., self call).
    ///
    /// @dev Can only be called by the Entrypoint.
    /// @dev Reverts if the given call is not authorized to skip the chain ID validtion.
    /// @dev `validateUserOp()` will recompute the `userOpHash` without the chain ID befor validatin
    ///      it if the `UserOperation` aims at executing this function. This allows certain operations
    ///      to be replayed for all accounts sharing the same address across chains. E.g. This may be
    ///      useful for syncing owner changes.
    ///
    /// @param data The `UserOperation` raw call data of the  execute.
    function executeWithoutChainIdValidation(bytes calldata data) public payable virtual onlyEntryPoint {
        bytes4 selector = bytes4(data[0:4]);
        if (!canSkipChainIdValidation(selector)) {
            revert SelectorNotAllowed(selector);
        }

        _call(address(this), 0, data);
    }

    /// @notice Execute the given call from this account.
    ///
    /// @dev Can only be called by the Entrypoint or an owner of this account (including itself).
    ///
    /// @param target The target call address.
    /// @param value  The call value to user.
    /// @param data   The raw call data.
    function execute(address target, uint256 value, bytes calldata data) public payable virtual onlyEntryPointOrOwner {
        _call(target, value, data);
    }

    /// @notice Execute the given list of calls from this account.
    ///
    /// @dev Can only be called by the Entrypoint or an owner of this account (including itself).
    ///
    /// @param calls The list of `Call`s to execute.
    function executeBatch(Call[] calldata calls) public payable virtual onlyEntryPointOrOwner {
        for (uint256 i; i < calls.length;) {
            _call(calls[i].target, calls[i].value, calls[i].data);
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Returns the address of the EntryPoint v0.6.
    ///
    /// @return The address of the EntryPoint v0.6
    function entryPoint() public view virtual returns (address) {
        return 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    }

    /// @notice Computes the hash of the `UserOperation` in the same way as EntryPoint v0.6, but
    ///         leaves out the chain ID.
    ///
    /// @dev This allows accounts to sign a hash that can be used on many chains.
    ///
    /// @param userOp The `UserOperation` to compute the hash for.
    ///
    /// @return userOpHash The `UserOperation` hash, not including the chain ID.
    function getUserOpHashWithoutChainId(UserOperation calldata userOp)
        public
        view
        virtual
        returns (bytes32 userOpHash)
    {
        return keccak256(abi.encode(UserOperationLib.hash(userOp), entryPoint()));
    }

    /// @notice Returns the implementation of the ERC1967 proxy.
    ///
    /// @return $ the address the implementation contract
    function implementation() public view returns (address $) {
        assembly {
            $ := sload(_ERC1967_IMPLEMENTATION_SLOT)
        }
    }

    /// @notice Check if the given function selector is whitelisted to skip the chain ID validation.
    ///
    /// @param functionSelector The function selector to check.
    ////
    /// @return `true` is the function selector is whitelisted to skip the chain ID validation, else `false`.
    function canSkipChainIdValidation(bytes4 functionSelector) public pure returns (bool) {
        if (
            functionSelector == MultiOwnable.addOwnerPublicKey.selector
                || functionSelector == MultiOwnable.addOwnerAddress.selector
                || functionSelector == MultiOwnable.removeOwnerAtIndex.selector
                || functionSelector == UUPSUpgradeable.upgradeToAndCall.selector
        ) {
            return true;
        }
        return false;
    }

    /// @notice Execute the given call from this account.
    ///
    /// @dev Reverts if the call reverted.
    /// @dev Impl taken from https://github.com/alchemyplatform/light-account/blob/main/src/LightAccount.sol#L347
    ///
    /// @param target The target call address.
    /// @param value  The call value to user.
    /// @param data   The raw call data.
    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /// @inheritdoc ERC1271
    ///
    /// @dev Used both for classic ERC-1271 signature AND `UserOperation` validations.
    /// @dev Reverts if the signer (based on the `ownerIndex`) is not compatible with the signature.
    /// @dev Reverts if the signature does not correspond to an ERC-1271 signature or to the abi
    ///      encoded version of a `WebAuthnAuth` struct.
    /// @dev Does NOT revert if the signature verification fails to allow making a "simulation call"
    ///      without a valid signature.
    ///
    /// @param signature The abi encoded `SignatureWrapper` struct.
    function _validateSignature(bytes32 message, bytes calldata signature)
        internal
        view
        virtual
        override
        returns (bool)
    {
        SignatureWrapper memory sigWrapper = abi.decode(signature, (SignatureWrapper));
        bytes memory ownerBytes = ownerAtIndex(sigWrapper.ownerIndex);

        if (ownerBytes.length == 32) {
            if (uint256(bytes32(ownerBytes)) > type(uint160).max) {
                // technically should be impossible given owners can only be added with
                // addOwnerAddress and addOwnerPublicKey, but we leave incase of future changes.
                revert InvalidEthereumAddressOwner(ownerBytes);
            }

            address owner;
            assembly ("memory-safe") {
                owner := mload(add(ownerBytes, 32))
            }

            return SignatureCheckerLib.isValidSignatureNow(owner, message, sigWrapper.signatureData);
        }

        if (ownerBytes.length == 64) {
            (uint256 x, uint256 y) = abi.decode(ownerBytes, (uint256, uint256));

            WebAuthn.WebAuthnAuth memory auth = abi.decode(sigWrapper.signatureData, (WebAuthn.WebAuthnAuth));

            return WebAuthn.verify({
                challenge: abi.encode(message),
                requireUserVerification: false,
                webAuthnAuth: auth,
                x: x,
                y: y
            });
        }

        revert InvalidOwnerBytesLength(ownerBytes);
    }

    /// @inheritdoc UUPSUpgradeable
    ///
    /// @dev Authorization logic is only based on the sender being an owner of this account.
    function _authorizeUpgrade(address) internal view virtual override(UUPSUpgradeable) onlyOwner {}

    /// @inheritdoc ERC1271
    function _domainNameAndVersion() internal pure override(ERC1271) returns (string memory, string memory) {
        return ("Coinbase Smart Wallet", "1");
    }
}
