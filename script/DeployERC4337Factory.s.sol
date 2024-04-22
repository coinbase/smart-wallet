// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";

import {CoinbaseSmartWallet, CoinbaseSmartWalletFactory} from "../src/CoinbaseSmartWalletFactory.sol";

contract ERC4337FactoryDeployScript is Script {
    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        CoinbaseSmartWallet c = new CoinbaseSmartWallet{salt: "0x1"}();
        CoinbaseSmartWalletFactory f = new CoinbaseSmartWalletFactory{salt: "0x1"}(address(c));
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(vm.addr(deployerPrivateKey));
        console2.log("implementation", address(c));
        console2.log("factory", address(f));
    }
}
