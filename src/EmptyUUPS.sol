// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";

contract EmptyUUPS is UUPSUpgradeable {
    function _authorizeUpgrade(address newImplementation) internal override {}
}
