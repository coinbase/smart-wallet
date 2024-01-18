// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";

import {ERC4337Factory, ERC4337Account} from "../src/ERC4337Factory.sol";

contract ERC4337FactoryDeployScript is Script {
    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        ERC4337Account c = new ERC4337Account{salt: "0x1"}();
        ERC4337Factory f = new ERC4337Factory{salt: "0x1"}(address(c));
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(vm.addr(deployerPrivateKey));
        f.createAccount(owners, 0);
        console2.log(address(c));
        console2.log("factory", address(f));
    }
}
