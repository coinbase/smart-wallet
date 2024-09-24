deploy :; \
  source .env && \
  export FOUNDRY_PROFILE=deploy && \
  forge script script/DeployFactory.s.sol \
    --rpc-url $${RPC_URL} \
    --account $${ACCOUNT} \
    --broadcast \
    $(if $(ETHERSCAN_API_KEY),--verify)
