// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.23;

import { CoinbaseSmartWallet } from "src/CoinbaseSmartWallet.sol";
import { StorageSlotUpgradeable } from "../openzeppelin-contracts-upgradeable/contracts/utils/StorageSlotUpgradeable.sol";
import { AddressUpgradeable } from "../openzeppelin-contracts-upgradeable/contracts/utils/AddressUpgradeable.sol";

contract CoinbaseSmartWalletHarness is CoinbaseSmartWallet {

    constructor() CoinbaseSmartWallet() {}

    /// @dev Upgrades the proxy's implementation to `newImplementation`.
    function upgradeToAndCall(address newImplementation, bytes calldata data) 
        public
        payable
        override
        onlyProxy
    {
        _authorizeUpgrade(newImplementation);
        _setImplementation(newImplementation);
    }

    /// @dev Sends to the EntryPoint (i.e. `msg.sender`) the missing funds for this transaction.
    modifier payPrefund(uint256 missingAccountFunds) override {
        _;
        assert (msg.sender == entryPoint());
        if(missingAccountFunds !=0) {
            (bool success, ) = entryPoint().call{gas: gasleft(), value: missingAccountFunds}("");
        }
    }

    /**
    * @dev Returns the current implementation address.
    */
    function _getImplementation() internal view returns (address) {
        return StorageSlotUpgradeable.getAddressSlot(_ERC1967_IMPLEMENTATION_SLOT).value;
    }

    /**
    * @dev Stores a new address in the EIP1967 implementation slot.
    */
    function _setImplementation(address newImplementation) private {
        require(AddressUpgradeable.isContract(newImplementation), "ERC1967: new implementation is not a contract");
        StorageSlotUpgradeable.getAddressSlot(_ERC1967_IMPLEMENTATION_SLOT).value = newImplementation;
    }

    function compareBytes(bytes memory a, bytes memory b) public pure returns (bool) {
        return keccak256(a) == keccak256(b);
    }
}
