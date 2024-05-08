// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

interface IVerifier {
    function Verify(bytes calldata proof, uint256[] calldata public_inputs) external view returns (bool);
}
