// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.23;

import { StakeManager } from "lib/account-abstraction/contracts/core/StakeManager.sol";
import { NonceManager } from "lib/account-abstraction/contracts/core/NonceManager.sol";

contract EntryPointMock is StakeManager, NonceManager {}