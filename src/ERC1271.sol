// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {EIP712} from "solady/src/utils/EIP712.sol";

/// @notice ERC-1271 with guards for same signer being used on multiple accounts
/// Based on Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC1271.sol)
/// @author Wilson Cusack
abstract contract ERC1271 {
    /// @dev We use `bytes32 hash` rather than `bytes message`
    /// In the EIP-712 context, `bytes message` would be useful for showing users a full message
    /// they are signing in some wallet preview. But in this case, to prevent replay
    /// across accounts, we are always dealing with nested messages, and so the
    /// input should be a EIP-191 or EIP-712 output hash.
    /// E.g. The input hash would be result of
    ///
    ///  keccak256("\x19\x01" || someDomainSeparator || hashStruct(someStruct))
    ///
    ///  OR
    ///
    ///  keccak256("\x19Ethereum Signed Message:\n" || len(someMessage) || someMessage),
    ///
    bytes32 private constant _MESSAGE_TYPEHASH = keccak256("CoinbaseSmartWalletMessage(bytes32 hash)");

    /// @dev Validates the signature with ERC1271 return,
    /// so that this account can also be used as a signer.
    function isValidSignature(bytes32 hash, bytes calldata signature) public view virtual returns (bytes4 result) {
        if (_validateSignature(replaySafeHash(hash), signature)) {
            // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
            return 0x1626ba7e;
        }

        return 0xffffffff;
    }

    /// @dev Returns an EIP-712-compliant hash of `hash`,
    /// where the domainSeparator includes address(this) and block.chainId
    /// to protect against the same signature being used for many accounts.
    /// @return
    ///  keccak256(\x19\x01 || this.domainSeparator ||
    ///      hashStruct(CoinbaseSmartWalletMessage({
    ///          hash: `hash`
    ///      }))
    ///  )
    function replaySafeHash(bytes32 hash) public view virtual returns (bytes32) {
        return _eip712Hash(_hashStruct(hash));
    }

    /// @dev See: https://eips.ethereum.org/EIPS/eip-5267
    function eip712Domain()
        external
        view
        virtual
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        )
    {
        fields = hex"0f"; // `0b1111`.
        (name, version) = _domainNameAndVersion();
        chainId = block.chainid;
        verifyingContract = address(this);
        salt = salt; // `bytes32(0)`.
        extensions = extensions; // `new uint256[](0)`.
    }

    /// @dev EIP-712 compliant domainSeparator to be used for constructing
    /// valid input to isValidSignature
    function domainSeparator() public view returns (bytes32) {
        (string memory name, string memory version) = _domainNameAndVersion();
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                block.chainid,
                address(this)
            )
        );
    }

    /// @dev encode(domainSeparator : 𝔹²⁵⁶, message : 𝕊) = "\x19\x01" || domainSeparator || hashStruct(message)
    /// https://eips.ethereum.org/EIPS/eip-712
    function _eip712Hash(bytes32 hashStruct) internal view virtual returns (bytes32 digest) {
        digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), hashStruct));
    }

    /// @dev hashStruct(s : 𝕊) = keccak256(typeHash || encodeData(s))
    /// https://eips.ethereum.org/EIPS/eip-712
    function _hashStruct(bytes32 hash) internal view virtual returns (bytes32) {
        return keccak256(abi.encode(_MESSAGE_TYPEHASH, hash));
    }

    /// @dev Please override this function to return the domain name and version.
    function _domainNameAndVersion() internal view virtual returns (string memory name, string memory version);

    /// @dev Implement to verify signature
    function _validateSignature(bytes32 message, bytes calldata signature) internal view virtual returns (bool);
}
