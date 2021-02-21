# How to use

The easiest way to use this code is with VSCode, as a `.devcontainer.json` file is included in this directory.
Otherwise, you can run the docker container manually (mount `nodeHome` as `/home/node` in the container).

## Common setup
### Create accounts
These steps needs to be done both for the service-dependent as the fully-decentralised setup.

From a shell in the container, run `npm install` from this directory to install npm dependencies.

Create the file which will hold the test accounts information:
```
cp common/TestAccountsInfo.ts.sample common/TestAccountsInfo.ts
```
and fill the `servicePrivateKey` with the private key you want to use as `service` account. This is the account that will need to be funded.
If you don't have an account, you need to create one. You can do this by using the CLI command `symbol-cli` to [create the account](https://docs.symbolplatform.com/guides/account/creating-an-account.html),
or alternatively by generating private key with
```
openssl rand -hex 32
```
and then import it in CLI with
```
symbol-cli profile import -n TEST_NET
```
so that you can use it both from the CLI as from the scripts.
Similarly, create a second service account for cosigning and put its private keys value in `serviceCosignPrivateKey`.

Once this is done, you can
```
./runs.sh common/createAccounts.ts
```
which will print the address and private keys of the following accounts for the fully-decentralised scenario:
* `msig`
* `cosign1`
* `cosign2`
and these accounts for the service-dependent scenario:
* `SD_msig`
* `SD_cosign1`
* `SD_cosign2`

Use this info to fill in all the private keys variables in `common/TestAccountsInfo.ts`, even if you plan to only use one scenario as missing keys are not handled in the scripts.

Until now, no XYM were required, but at this time you will need to ensure that the `service` account has XYMs. On the testnet, which we use, you can use a [faucet](http://faucet.testnet.symboldev.network/).

### Create Namespaces

```
./common/setup_namespace.sh secd
```
then
```
./common/setup_subnamespace.sh secd token
```

### CreateMosaic
Use
```
./run.sh common/createMosaic.ts
```
This create Mosaic with id `1433489E52719E00`.

### Link subnamespace to mosaic
```
./common/link_ns_to_mosaic.sh 1433489E52719E00 secd.token
```

### Send tokens to the multisig account
We will only consider transaction sending our token to our `service` account, so as part of the user's accounts setup, we need to send it some tokens.
We will send 50 tokens to each msig account we created:
```
# msig
./run.sh common/transferTokensTo.ts TBFNWB-M4YJFB-A3UJ27-J4H4V4-E5Z65T-KRAK5S-IJY
# SD_msig
./run.sh common/transferTokensTo.ts TBRPOC-SS6DEP-YVRLO7-XCPMMT-EPAL3M-ZTR7A2-E4A

```
In production this operation will only be done when the account has been correctly linked to a publishing platform account.

## Service-dependent setup
### Convert multisig
When all accounts have been created, we can convert the `SD_msig` account in a 3 of 4 multisig account, with the following cosigners:
* `service`
* `serviceCosign`
* `SD_cosign1`
* `SD_cosign2`
We set 2 service accounts as co-sign, should the user loose access to one of its cosigning accounts.
To convert the multisig account, run 
```
./run.sh ./service-dependent/convertMultisig.ts
```
The output printed includes the accounts addresses, and the hash of the transaction broadcasted:
```
...
will announce transaction ${transaction_hash_value}
...
```
And you can check [on the explorer](http://explorer.testnet.symboldev.network/) that the transaction was successful. Here is an [example successful transaction](http://explorer.testnet.symboldev.network/transactions/AF1CA2924F352ED9D419EB90858E569893810389245B65F431A498E390599B67) of multisig conversion.

### Publish a file hash
We can now publish a file hash from the multisig by calling
```
./run.sh service-dependent/sendFileHashMsig.ts cosign
```
Passing the cosign argument will make the script listen for and cosign the aggregate transaction with the accounts `SD_cosign1` and `SD_cosign2`.
The output of the script includes the hash of the aggregate transaction:
```
...
Aggregate transaction to check: C4B757B1B72EA287FFA84E4EE932248534A8B7E4453E2BAFC725A1234D757A9C
...
```
and [this transaction appears as confirmed](http://explorer.testnet.symboldev.network/transactions/C4B757B1B72EA287FFA84E4EE932248534A8B7E4453E2BAFC725A1234D757A9C) as it has been cosigned.
If you want to just announce the aggregate transaction without cosigning it immediately, you can leave out the argument cosign:

```
./run.sh service-dependent/sendFileHashMsig.ts
```
Now the output of the script includes also warns that the transaction was not automatically cosigned:
```
...
Aggregate transaction to check: C225B090A7C8A31757BBE60018DCF166ED016C7BB1DDF621CE8BFC89F2E884C6
!!!!!!!!!!!  transaction was not cosigned, pass argument 'cosign' to have it cosigned immediately
...
```
If you check out the transaction on the [blockchain explorer](http://explorer.testnet.symboldev.network/), you'll see the transaction reported with Status success and confirmation partial until
all cosignatories cosign the transaction.
.
If you imported the cosignatories into `symbol-cli` profiles, you can easily cosign it:
```
symbol-cli transaction cosign --profile SD_cosign1 --hash C225B090A7C8A31757BBE60018DCF166ED016C7BB1DDF621CE8BFC89F2E884C6
```
and then
```
symbol-cli transaction cosign --profile SD_cosign2 --hash C225B090A7C8A31757BBE60018DCF166ED016C7BB1DDF621CE8BFC89F2E884C6
```

## Common operations
### Tag multisig account with metadata
Metadata is used to link a publisher account to a Symbol multisig account. It is done by putting an identitying string in the key, and the value to true.
It is done so because metadata can only be searched by key, and not by value.
As an example, the account nemtech on github would get the metadata `github:nemtech = true`.
Assigning the metadata is done with
```
./run.sh common/tagAccount.ts TBRPOCSS6DEPYVRLO7XCPMMTEPAL3MZTR7A2E4A 'github:asfaload'
```
The transaction has to be confirmed by the target account, and as it is a multisig, the cosignatories have to cosign the transaction.
The output of the script gives the transaction hash to be cosigned. You can do so with the `symbol-cli` if you have created the profiles for the
cosignatories, for example:
```
symbol-cli transaction cosign --profile SD_cosign1 --hash 946936FD8F1F6E5E9C20AE62AFBFB670333D0E9D70A980F94630A459F3C13865
symbol-cli transaction cosign --profile SD_cosign2 --hash 946936FD8F1F6E5E9C20AE62AFBFB670333D0E9D70A980F94630A459F3C13865
```
As this operation requires the `service` account to lock 10XYMs, the transaction should only be broadcasted after the user has confirmed ownership of the
publisher account.

### Finding the account with a metadata
This can be done with
```
./run.sh common/findAccountWithMetadata.ts github:asfaload
```
which prints the account found in its output:
```
...
Account found:   TBRPOC-SS6DEP-YVRLO7-XCPMMT-EPAL3M-ZTR7A2-E4A
```
