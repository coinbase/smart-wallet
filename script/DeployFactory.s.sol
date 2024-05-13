// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";
import {SafeSingletonDeployer} from "safe-singleton-deployer-sol/src/SafeSingletonDeployer.sol";

import {CoinbaseSmartWallet, CoinbaseSmartWalletFactory} from "../src/CoinbaseSmartWalletFactory.sol";

contract DeployFactoryScript is Script {
    address constant EXPECTED_IMPLEMENTATION = 0x0002002045f9a4865D6dFF3A15477Fe38bF2Dec4;
    address constant EXPECTED_FACTORY = 0x0BA5ED08ce9d8D797e51F22B697AA02648feF8B1;

    function run() public {
        console2.log("Deploying on chain ID", block.chainid);

        address keyStore = 0xa3c95c6fb0151b42C29754FEF66b38dd6Eaa2950;
        address stateVerifier = 0x3aEC28C4a6fc29daE0B2c4b8b4a5e6C107Ac8391;

        address implementation = SafeSingletonDeployer.broadcastDeploy({
            creationCode: type(CoinbaseSmartWallet).creationCode,
            args: abi.encode(keyStore, stateVerifier),
            salt: 0xf03769f23bd251f78c9c11bb5393df7daabf1ecf4d1bcce7144ef2e8295961b9
        });
        console2.log("implementation", implementation);
        assert(implementation == EXPECTED_IMPLEMENTATION);

        address factory = SafeSingletonDeployer.broadcastDeploy({
            creationCode: type(CoinbaseSmartWalletFactory).creationCode,
            args: abi.encode(EXPECTED_IMPLEMENTATION),
            salt: 0x67264d9e41d1a6804b80a30983d4965543fd14ebfbc290df88647615f5b0948f
        });
        console2.log("factory", factory);
        assert(factory == EXPECTED_FACTORY);
    }
}
