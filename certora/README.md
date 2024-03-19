# How to run Certora Prover

1. Get certora key by filling in the form on [Certora's website](https://www.certora.com/signup?plan=prover). You should get an email with the key and all necessary instructions.
2. Make sure to install everything that is mentioned in [instructions](https://docs.certora.com/en/latest/docs/user-guide/getting-started/index.html).
3. To run the spec use the following command in your terminal from the root of your project:
```
certoraRun certora/confs/ERC4337Account.conf
```
or
```
certoraRun certora/confs/ERC4337AccountInv.conf
```
Depending on what spec you want to run.

## Notes
- You might need to remove `"solc":"solc8.23"` from conf file in `certora/confs/*`.