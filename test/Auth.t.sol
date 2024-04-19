// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test, console2} from "forge-std/Test.sol";
import {ERC20} from "solady/tokens/ERC20.sol";

import {CoinbaseSmartWallet} from "../src/CoinbaseSmartWallet.sol";
import {CoinbaseSmartWalletFactory} from "../src/CoinbaseSmartWalletFactory.sol";

contract AuthTest is Test {
  CoinbaseSmartWallet account;
    uint256 fundedEOAPK = 0xa11ce;
    uint256 signerEOAPK = 0xb0b;
    address fundedEOA = vm.addr(fundedEOAPK);
    address signer = vm.addr(signerEOAPK);
    bytes[] owners;

    function setUp() public virtual {
        CoinbaseSmartWalletFactory f = new CoinbaseSmartWalletFactory(address(new CoinbaseSmartWallet()));
        owners.push(abi.encode(fundedEOA));
        owners.push(abi.encode(signer));
        account = f.createAccount(owners, 0);
    }

    function test_setAuth() public {
        CoinbaseSmartWallet.Commit memory commit = CoinbaseSmartWallet.Commit({
          validAfter: 0, 
          validUntil: type(uint32).max,
          data: bytes24("")
        });
        bytes32 commitEncoded = bytes32(abi.encode(commit));
        bytes32 digest = account.getDigest(commitEncoded);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fundedEOAPK, digest);
        account.setAuth(commitEncoded, fundedEOA, v, r, s);

        assertEq(account.authInfo(commitEncoded).owner, fundedEOA);
    }

    function test_executeAuthCallBatch() public {
      CoinbaseSmartWallet.Commit memory commit = CoinbaseSmartWallet.Commit({
          validAfter: 0, 
          validUntil: type(uint32).max,
          data: bytes24("")
        });
        bytes32 commitEncoded = bytes32(abi.encode(commit));
        bytes32 digest = account.getDigest(commitEncoded);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fundedEOAPK, digest);
        account.setAuth(commitEncoded, fundedEOA, v, r, s);

        Token token = new Token();
        uint amount = 1e18;
        token.mint(fundedEOA, amount);
        address receiver = makeAddr("receiver");


        vm.prank(signer);
        CoinbaseSmartWallet.Call memory call = CoinbaseSmartWallet.Call({
          value: 0,
          data: abi.encodeWithSelector(ERC20.transfer.selector, receiver, amount),
          target: address(token)
        });
        
        CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](1);
        calls[0] = call;
        account.executeAuthCallBatch(calls, abi.encode(commit));
    }
}

contract Token is ERC20 {
  function mint(address to, uint value) public {
    _mint(to, value);
  }

  function name() public view override returns (string memory) {
    return "test";
  }

  function symbol() public view override returns (string memory) {
    return "TEST";
  }
}