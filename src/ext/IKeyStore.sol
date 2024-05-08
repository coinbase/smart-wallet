// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

interface IKeyStore {
    function root() external view returns (uint256);
}
