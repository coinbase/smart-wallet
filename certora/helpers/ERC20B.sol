// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity =0.8.17;

import "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

contract ERC20B is ERC20 {
   constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {}
}