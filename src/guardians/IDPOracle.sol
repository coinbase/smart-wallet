// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

contract IDPOracle {
    struct Pk {
        bytes n;
        bytes e;
    }

    mapping(address idp => mapping(string kid => Pk pk)) private _pks;

    function getPk(address idp, string calldata kid) external view returns (Pk memory) {
        return _pks[idp][kid];
    }

    function setPk(string calldata kid, Pk calldata pk) external {
        _pks[msg.sender][kid] = pk;
    }

    function removePk(string calldata kid) external {
        delete _pks[msg.sender][kid];
    }
}
