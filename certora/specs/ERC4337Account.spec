using EntryPointMock as EntryPoint;
use builtin rule sanity;

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



definition initialized() returns bool = nextOwnerIndex() > 0;



function isValidSignatureNowCVL(uint256 time, address signer, bytes32 hash, bytes signature) returns bool {
    bytes32 hashSignature = keccak256(signature);
    return signatureValidTime(hashSignature, time) && validSignature(signer, hash, hashSignature);
}



// STATUS - verified
// After initialise has been called, nextOwnerIndex > 0
rule afterInitialize(env e) {
    bytes[] owners;

    require owners.length > 0;  // if owners array is empty, nothing happens

    initialize(e, owners);

    assert nextOwnerIndex() > 0, "Remember, with great power comes great responsibility.";
}


// STATUS - verified
// Initialize can't be called twice.
rule cantInitTwice(env e1, env e2, env e3, method f) filtered { 
    f -> f.selector != sig:initialize(bytes[]).selector   // calling initialize() in f will lead to unreachability 
} {
    bytes[] owners1;
    bytes[] owners2;

    require owners1.length > 0;  // if owners array is empty, nothing happens

    initialize(e1, owners1);
    calldataarg args;
    f(e3, args);                // checking if something can make initialize callable twice
    initialize@withrevert(e2, owners2);

    bool isReverted = lastReverted;

    assert isReverted, "Remember, with great power comes great responsibility.";
}


// STATUS - verified
// After initialisation, if ownerAtIndex[i] changes, msg.sender must be an owner
rule onlyOwnerCanChangeOwnerAtIndex(env e, method f) filtered { 
    f -> !f.isView  // view functions aren't state-changing, so no reason to check them
        && f.selector != sig:initialize(bytes[]).selector   // we are in a state after initialization, so initialize() fails vacuity anyway 
} {
    uint256 i;

    bytes ownerAtIndexBefore = ownerAtIndex(i);
    bool ownerBefore = e.msg.sender == currentContract || isOwnerAddress(e.msg.sender); // owner can remove themselves

    require initialized();

    calldataarg args;
    f(e, args);

    bytes ownerAtIndexAfter = ownerAtIndex(i);

    assert !compareBytes(ownerAtIndexBefore, ownerAtIndexAfter) 
            => ownerBefore;
}


// STATUS - verified
// After initialisation, If isOwner[i] changes, msg.sender must be an owner
rule onlyOwnerCanChangeIsOwnerBytes(env e, method f) filtered { 
    f -> !f.isView  // view functions aren't state-changing, so no reason to check them
        && f.selector != sig:initialize(bytes[]).selector   // we are in a state after initialization, so initialize() fails vacuity anyway 
} {
    bytes account;

    bool isOwnerBytesBefore = isOwnerBytes(account);
    bool ownerBefore = e.msg.sender == currentContract || isOwnerAddress(e.msg.sender); // owner can remove themselves

    require initialized();

    calldataarg args;
    f(e, args);

    bool isOwnerBytesAfter = isOwnerBytes(account);

    assert isOwnerBytesBefore != isOwnerBytesAfter => ownerBefore;
}


// STATUS - verified
// Only owner or self can call addOwnerAddress, addOwnerPublicKey,
// removeOwnerAtIndex, upgradeToAndCall(harnessed)
rule OnlyOwnerOrSelf(env e, method f) filtered {
    // added filter so advanced sanity check doesn't fail on other functions. 
    // There is no difference between filtering functions and using them as a lhs of implication
    f -> f.selector == sig:addOwnerAddress(address).selector 
        || f.selector == sig:addOwnerPublicKey(bytes32, bytes32).selector
        || f.selector == sig:removeOwnerAtIndex(uint256).selector 
        || f.selector == sig:upgradeToAndCall(address, bytes).selector 
} {
    bool ownerBefore = e.msg.sender == currentContract || isOwnerAddress(e.msg.sender); // owner can remove themselves

    calldataarg args;
    f@withrevert(e, args);
    bool isReverted = lastReverted; // added revert case so advanced sanity check doesn't fail

    assert !isReverted => ownerBefore;
}


// STATUS - verified
// Only EntryPoint, owner, or self can call execute, executeBatch
rule OnlyOwnerSelfOrEntryPoint(env e, method f) filtered {    
    // added filter so advanced sanity check doesn't fail on other functions. 
    // There is no difference between filtering functions and using them as a lhs of implication
    f -> f.selector == sig:execute(address, uint256, bytes).selector 
        || f.selector == sig:executeBatch(CoinbaseSmartWallet.Call[]).selector
} {
    bool ownerBefore = e.msg.sender == currentContract 
                        || isOwnerAddress(e.msg.sender) 
                        || e.msg.sender == entryPoint();

    calldataarg args;
    f@withrevert(e, args);
    bool isReverted = lastReverted; // added revert case so advanced sanity check doesn't fail

    assert !isReverted => ownerBefore;
}


// STATUS - verified
// Only EntryPoint can call executeWithoutChainIdValidation, validateUserOp
rule OnlyEntryPoint(env e, method f) filtered {    
    // added filter so advanced sanity check doesn't fail on other functions. 
    // There is no difference between filtering functions and using them as a lhs of implication
    f -> f.selector == sig:validateUserOp(EntryPointMock.UserOperation, bytes32, uint256).selector 
        || f.selector == sig:executeWithoutChainIdValidation(bytes).selector
} {
    bool ownerBefore = e.msg.sender == entryPoint();

    calldataarg args;
    f@withrevert(e, args);
    bool isReverted = lastReverted; // added revert case so advanced sanity check doesn't fail

    assert !isReverted => ownerBefore;
}


// STATUS - verified
// There is no owner at index greater or equal to nextOwnerIndex
invariant noMoreThanNextOwnerIndex(uint256 i)
    i >= nextOwnerIndex() && nextOwnerIndex() < max_uint256 => ownerAtIndex(i).length == 0;


// STATUS - verified
// nextOwnerIndex should grow monotonically
rule newUserIndexMonotonicGrowth(env e, method f){
    uint256 _index = nextOwnerIndex();
    
    calldataarg args;
    f(e, args);
    
    uint256 index_ = nextOwnerIndex();

    assert index_ >= _index,"next owner index cannot decrease";
}


// STATUS - verified
// unless it's the initialize function, index should grow by 1 only
rule newUserIndexGrowsBy1(env e, method f) 
filtered { f -> f.selector != sig:initialize(bytes[]).selector }{
    uint256 _index = nextOwnerIndex();
    
    calldataarg args;
    f(e, args);
    
    uint256 index_ = nextOwnerIndex();

    assert index_ == _index || _index + 1 == to_mathint(index_),"index can increase by 1 only";
}


// STATUS - verified
// Owner with length == 0 can’t be an owner 
invariant emptyInNotAnOwner(bytes empty)
    empty.length == 0 => !isOwnerBytes(empty);


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


// STATUS - verified
// Eth balance of account should decrease by at least missing account funds
rule ethBalanceDecreaseByMissingAccountFunds(env e){
    uint256 _ethBalance = nativeBalances[currentContract];
    EntryPointMock.UserOperation userOp;
    bytes32 userOpHash;
    uint256 missingAccountFunds;
    
    require e.msg.value == 0;
    require _ethBalance >= missingAccountFunds;
    require missingAccountFunds + nativeBalances[e.msg.sender] <= max_uint256;
    require EntryPoint == entryPoint();

    require EntryPoint.balanceOf(currentContract) + missingAccountFunds <= max_uint112;
    validateUserOp(e, userOp, userOpHash, missingAccountFunds);
    
    uint256 ethBalance_ = nativeBalances[currentContract];

    assert ethBalance_ + missingAccountFunds <= to_mathint(_ethBalance),"eth balance of account should go down by atleast missingAccountFunds";
}


// STATUS - verified
// When we add an owner and index isn't max_uint256 => only the latest index was changed and length is increased by 1
rule addNewOwnerCheck(env e, method f) filtered { 
    f -> f.selector == sig:addOwnerAddress(address).selector
            || f.selector == sig:addOwnerPublicKey(bytes32, bytes32).selector
} {
    uint256 index; uint256 anotherIndex;

    bytes ownerAtIndexBefore = ownerAtIndex(index);
    bytes ownerAtIndexAnotherBefore = ownerAtIndex(anotherIndex);
    uint256 nextOwnerIndexBefore = nextOwnerIndex();

    require index != anotherIndex;                              // make sure indexes are different to check taht only the latest one was changed
    require anotherIndex < nextOwnerIndex();                    // make sure anotherIndex exists, so it should be unchanged
    require isOwnerBytes(ownerAtIndex(anotherIndex));           // set a correlation between ownerAtIndex and isOwnerBytes 
    require index == nextOwnerIndex();                          // checking "only the latest index was changed"                
    requireInvariant noMoreThanNextOwnerIndex(index);           // making non-existing indexes empty. Counter-example without it: https://prover.certora.com/output/3106/39c21239f0f346739dfb640d5f2fda74/?anonymousKey=a259bd2451300d394634d97b3310888dc8429887
    requireInvariant noMoreThanNextOwnerIndex(anotherIndex);    // making non-existing indexes empty

    calldataarg args;
    f(e, args);

    bytes ownerAtIndexAfter = ownerAtIndex(index);
    bytes ownerAtIndexAnotherAfter = ownerAtIndex(anotherIndex);
    uint256 nextOwnerIndexAfter = nextOwnerIndex();

    assert to_mathint(nextOwnerIndexBefore) == nextOwnerIndexAfter - 1;
    assert !compareBytes(ownerAtIndexBefore, ownerAtIndexAfter);
    assert compareBytes(ownerAtIndexAnotherBefore, ownerAtIndexAnotherAfter);
}
