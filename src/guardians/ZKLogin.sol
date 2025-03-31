// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {Ownable} from "solady/auth/Ownable.sol";

interface IZKLoginVerifier {
    function verify(bytes calldata proof) external view returns (bool);
}

contract ZKLogin is Ownable {}
