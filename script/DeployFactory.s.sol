// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";
import {SafeSingletonDeployer} from "safe-singleton-deployer-sol/src/SafeSingletonDeployer.sol";

import {CoinbaseSmartWallet, CoinbaseSmartWalletFactory} from "../src/CoinbaseSmartWalletFactory.sol";

contract DeployFactoryScript is Script {
    address constant EXPECTED_IMPLEMENTATION = 0x00010089CD648bBEB2Ed58b62599695c1cb05E8d;
    address constant EXPECTED_FACTORY = 0x0BA5ED0676E8DE77C118B1C7718246184BAB1b8E;

    function run() public {
        console2.log("Deploying on chain ID", block.chainid);

        address keyStore = 0xa3c95c6fb0151b42C29754FEF66b38dd6Eaa2950;
        address stateVerifier = 0x3aEC28C4a6fc29daE0B2c4b8b4a5e6C107Ac8391;

        address implementation = SafeSingletonDeployer.broadcastDeploy({
            creationCode: type(CoinbaseSmartWallet).creationCode,
            args: abi.encode(keyStore, stateVerifier),
            salt: 0x97e862b928e37871994e143c9fe474739d207728adeadc83c9a63c32b4edd149
        });
        console2.log("implementation", implementation);
        assert(implementation == EXPECTED_IMPLEMENTATION);

        address factory = SafeSingletonDeployer.broadcastDeploy({
            creationCode: type(CoinbaseSmartWalletFactory).creationCode,
            args: abi.encode(EXPECTED_IMPLEMENTATION),
            salt: 0x40272f9ad1c3d8b9b6b818526c5454ba5d7c3b7a40657e1b06bb359b18ef78eb
        });
        console2.log("factory", factory);
        assert(factory == EXPECTED_FACTORY);
    }
}
