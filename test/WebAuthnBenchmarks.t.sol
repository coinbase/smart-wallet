// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// These tests do not run by default, running requires setting via_ir = true in foundry.toml and slows compile time

// import {Test, console2} from "forge-std/Test.sol";
// import {WebAuthn as DaimoWebAuthn} from "p256-verifier/src/WebAuthn.sol";
// import {FCL_WebAuthn, FCL_ecdsa_utils} from "FreshCryptoLib/FCL_Webauthn.sol";
// import "p256-verifier/src/P256.sol";
// import "p256-verifier/src/P256Verifier.sol";

// import {WebAuthn} from "../src/WebAuthn.sol";
// import {Utils, WebAuthnInfo} from "./Utils.sol";

// contract WebAuthnTest is Test {
//     FCLWrapper fclWrapper = new FCLWrapper();
//     DaimoWrapper daimoWrapper = new DaimoWrapper();
//     CBWrapper cbWrapper = new CBWrapper();
//     bytes32 digest = sha256("hello world");
//     uint256 privateKey = 0xa11ce;
//     string clientDataJSON;
//     bytes authenticatorData;
//     uint256 r;
//     uint256 s;
//     uint256[2] rs;
//     uint256 x;
//     uint256 y;
//     uint256[2] Q;
//     uint256 constant P256_N = uint(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551);

//     function setUp() public {
//         vm.etch(P256.VERIFIER, type(P256Verifier).runtimeCode);
//         WebAuthnInfo memory webAuthnInfo = Utils.getWebAuthnStruct(digest);
//         (bytes32 r_, bytes32 s_) = vm.signP256(privateKey, webAuthnInfo.messageHash);
//         r = uint256(r_);
//         s = uint256(s_);
//         if (s > P256_N / 2) {
//             s = P256_N - s;
//         }
//         rs[0] = r;
//         rs[1] = s;
//         (x, y) = FCL_ecdsa_utils.ecdsa_derivKpub(privateKey);
//         Q[0] = x;
//         Q[1] = y;
//         authenticatorData = webAuthnInfo.authenticatorData;
//         clientDataJSON = webAuthnInfo.clientDataJSON;
//     }

//     function test_FCL() public view {
//         bool valid = fclWrapper.checkSignature({
//             authenticatorData: authenticatorData,
//             authenticatorDataFlagMask: hex"01",
//             clientData: bytes(clientDataJSON),
//             clientChallenge: digest,
//             clientChallengeDataOffset: 36,
//             rs: rs,
//             Q: Q
//         });

//         assert(valid);
//     }

//     function test_FCLCalldataSize() public view {
//         bytes memory data = abi.encode(
//             authenticatorData,
//             hex"01",
//             bytes(clientDataJSON),
//             digest,
//             36,
//             rs,
//             Q
//         );

//         console2.log('FCL calldata', data.length);
//     }

//     function test_Daimo() public view {
//         bool valid = daimoWrapper.verifySignature({
//             challenge: abi.encode(digest),
//             authenticatorData: authenticatorData,
//             requireUserVerification: false,
//             clientDataJSON: clientDataJSON,
//             challengeLocation: 23,
//             responseTypeLocation: 1,
//             r: r,
//             s: s,
//             x: x,
//             y: y
//         });

//         assert(valid);
//     }

//     function test_DaimoCalldataSize() public view {
//         bytes memory data = abi.encode(
//             abi.encode(digest),
//             authenticatorData,
//             false,
//             clientDataJSON,
//             23,
//             1,
//             r,
//             s,
//             x,
//             y
//         );

//         console2.log('Daimo calldata', data.length);
//     }

//     function test_CB() public view {
//       bool valid = cbWrapper.verify({
//         challenge: abi.encode(digest),
//         webAuthnAuth: WebAuthn.WebAuthnAuth({
//           authenticatorData: authenticatorData,
//           origin: "",
//           crossOrigin: false,
//           additionalData: "",
//           r: r,
//           s: s
//         }),
//         x: x,
//         y: y
//       });

//       assert(valid);
//     }

//     function test_CBCalldataSize() public view {
//         bytes memory data = abi.encode(
//             abi.encode(digest),
//             WebAuthn.WebAuthnAuth({
//                 authenticatorData: authenticatorData,
//                 origin: "",
//                 crossOrigin: false,
//                 additionalData: "",
//                 r: r,
//                 s: s
//             }),
//             x,
//             y
//         );

//         console2.log('CB calldata with default origin', data.length);
//     }

//     function test_CBCalldataSize2() public view {
//       bytes memory data = abi.encode(
//             abi.encode(digest),
//             WebAuthn.WebAuthnAuth({
//                 authenticatorData: authenticatorData,
//                 origin: "https://sign.coinbase.com",
//                 crossOrigin: false,
//                 additionalData: "",
//                 r: r,
//                 s: s
//             }),
//             x,
//             y
//         );

//         console2.log('CB calldata with custom origin', data.length);
//     }
// }

// contract CBWrapper {
//   function verify(
//     bytes calldata challenge,
//     WebAuthn.WebAuthnAuth calldata webAuthnAuth,
//     uint256 x,
//     uint256 y
//   ) external view returns (bool) {
//     return WebAuthn.verify({
//       challenge: challenge,
//       webAuthnAuth: webAuthnAuth,
//       x: x,
//       y: y
//     });
//   }
// }

// contract DaimoWrapper {
//     function verifySignature(
//         bytes calldata challenge,
//         bytes calldata authenticatorData,
//         bool requireUserVerification,
//         string calldata clientDataJSON,
//         uint256 challengeLocation,
//         uint256 responseTypeLocation,
//         uint256 r,
//         uint256 s,
//         uint256 x,
//         uint256 y
//     ) external view returns (bool) {
//         return DaimoWebAuthn.verifySignature({
//             challenge: challenge,
//             authenticatorData: authenticatorData,
//             requireUserVerification: requireUserVerification,
//             clientDataJSON: clientDataJSON,
//             challengeLocation: challengeLocation,
//             responseTypeLocation: responseTypeLocation,
//             r: r,
//             s: s,
//             x: x,
//             y: y
//         });
//     }
// }

// contract FCLWrapper {
//     function checkSignature(
//         bytes calldata authenticatorData,
//         bytes1 authenticatorDataFlagMask,
//         bytes calldata clientData,
//         bytes32 clientChallenge,
//         uint256 clientChallengeDataOffset,
//         uint256[2] calldata rs,
//         uint256[2] calldata Q
//     ) external view returns (bool) {
//         return FCL_WebAuthn.checkSignature({
//             authenticatorData: authenticatorData,
//             authenticatorDataFlagMask: authenticatorDataFlagMask,
//             clientData: clientData,
//             clientChallenge: clientChallenge,
//             clientChallengeDataOffset: clientChallengeDataOffset,
//             rs: rs,
//             Q: Q
//         });
//     }
// }
