using EntryPointMock as EntryPoint;

methods {
    function SignatureCheckerLib.isValidSignatureNow(address signer, bytes32 hash, bytes memory signature) internal returns (bool)
        with (env e) => isValidSignatureNowCVL(e.block.timestamp, signer, hash, signature);
    function SignatureCheckerLib.isValidSignatureNowCalldata(address signer, bytes32 hash, bytes calldata signature) internal returns (bool)
        with (env e) => isValidSignatureNowCVL(e.block.timestamp, signer, hash, signature);
    function WebAuthn.verify(bytes memory, bool, WebAuthn.WebAuthnAuth memory, uint256, uint256) internal returns (bool) => NONDET;
    function EntryPoint.balanceOf(address account) external returns (uint256) envfree;

    function nextOwnerIndex() external returns (uint256) envfree;
    function ownerAtIndex(uint256) external returns (bytes) envfree;
    function isOwnerAddress(address) external returns (bool) envfree;
    function isOwnerBytes(bytes) external returns (bool) envfree;
    function compareBytes(bytes, bytes) external returns (bool) envfree;
    function entryPoint() external returns (address) envfree;
}

persistent ghost signatureValidTime(bytes32,uint256) returns bool;
persistent ghost validSignature(address,bytes32,bytes32) returns bool;


function isValidSignatureNowCVL(uint256 time, address signer, bytes32 hash, bytes signature) returns bool {
    bytes32 hashSignature = keccak256(signature);
    return signatureValidTime(hashSignature, time) && validSignature(signer, hash, hashSignature);
}


// STATUS - verified
// "Can’t have the same owner at two different indices i ownerAtIndex" and "For any index i if ownerAtIndex[i].length != 0 => isOwner[ownerAtIndex[i]"
invariant notTheSameOwnerAgain(uint256 i, uint256 j)
    (
        (i != j 
            // indexes outside of nextOwnerIndex are empty, so can be equal. Tool takes two indexes outside of nextOwnerIndex. Invariant noMoreThanNextOwnerIndex verifies cases outside of nextOwnerIndex
            // for constructor case: https://prover.certora.com/output/3106/84dd177a742d443e9262c1a3a62fe71a/?anonymousKey=ba5fa322bddf50487adca5995bcbd5d369905801
            // && i < nextOwnerIndex()
            // indexes outside of nextOwnerIndex are empty, so can be equal. Tool takes two indexes outside of nextOwnerIndex. Invariant noMoreThanNextOwnerIndex verifies cases outside of nextOwnerIndex                   
            // && j < nextOwnerIndex()
            // you can remove owner at any index, in this case, two indexes with removed owners will be equal (assuming that one of them was originally empty/removed)               
            && ownerAtIndex(i).length != 0
            // you can remove owner at any index, in this case, two indexes with removed owners will be equal (assuming that one of them was originally empty/removed)     
            && ownerAtIndex(j).length != 0
        )
        => !compareBytes(ownerAtIndex(i), ownerAtIndex(j))
    )
    && (ownerAtIndex(i).length != 0 <=> isOwnerBytes(ownerAtIndex(i)))
    && (ownerAtIndex(j).length != 0 <=> isOwnerBytes(ownerAtIndex(j)))
    {
        preserved removeOwnerAtIndex(uint256 index) with (env e2) {
            require i == index;
            bytes empty;
            require empty.length == 0;
            require !isOwnerBytes(empty);
        }
    }
