rule sanity(method f) {
    env e;
    calldataarg args;
    currentContract.f(e, args);
    assert false;
}