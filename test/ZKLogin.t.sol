// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console2} from "forge-std/Test.sol";

import "../src/guardians/ZKLogin.sol";

contract ZKLoginTest is Test {
    ZKLogin zkLogin;

    address public google;

    function setUp() public {
        google = makeAddr("google");

        IDPOracle idpOracle = new IDPOracle();

        vm.prank(google);
        idpOracle.setPk({
            kid: "1234567890",
            pk: IDPOracle.Pk({
                n: hex"eff1fb028408181fab646221cfab9f4780a116990f06e76b3685db3c7b298ed324d4df1d6f53db15afafd725b43eff2e8e6fdec294102c9cfe2b1250cfcdfe7ae2203032a129673c59dfe57e346b47462aea9afb2477100ce378b7068c9e8f661df78540b90a588779865e1a429b3d4c4726fe3b0af0c2496d658a0e32a06cc8aed14ebe53e09d59b4a8cb8d94dfeb6b3b7e7db5341f0fc7fcae42b8224d8edc1b44817a19f26143b3ce0f47a21c602d91e41376e5b09ca4af3b0a1f4ac04b14d3973eca43e11fd001e84cb9ae247c819f77907c493def1906615f6962d4fbeb7921fc0987883feaf0e615765a8999b44e9632ee0f6bf55a7c156ece110ecdd5",
                e: hex"010001"
            })
        });

        zkLogin = new ZKLogin(address(idpOracle));
    }

    function test_recoverAccount() public {
        string memory jwtHeaderJson = '{"alg":"RS256","typ":"JWT","kid":"1234567890"}';

        zkLogin.recoverAccount({
            idp: google,
            jwtHash: bytes32(0),
            jwtHeaderJson: jwtHeaderJson,
            jwtSignature: hex"52c30c5edc502974fc73efe2931b2d7510ec30431c624d9ea337ca9a12d0feee9ced104cc8c26c5efa482a53f6485dcff9e8f4eeadb155e84b87d3fd2eb06365911f30d1bb792d676c2babf1f571c2e50ee3daae40df06cfbf3e2b8aa073162caf1a9224796c83650f4318c5dc8db5d5c6f69def1cceb9016e76f91867288c8b1721e6be1a399857da2a853205e0dca27ac6728a1cbca433101ff1d66a19c4ad6008d819c9ff9dddc625dacfb31d4638c0846bb927f39c9e4e62f2cb762eec4c1f44a6422c15dd00c8ec64e54417f497c77f14f4a6b8c1f2d24a85332f6a406dfa485753c28034534cedb01f6e148ee697df0800026dba75ca47b89f08f7d283"
        });
    }
}
