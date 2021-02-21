# Introduction
## Non-technical overview
AsfaLoad allows file publishers and their consumers to easily validate the authenticity of the files available for download.
Publishers make authenticity verification data available and downloaders can easily verify this data. Read on for more details.
## Problem description
More and more software is proposed for download as an executable or archive, but authenticity of the file is hard to verify. For example, a lots of software is now published through Github's Releases. At best, the developer then publishes checksums along the published files, but this puts the burden on the user for validation, and is far from foolproof. If the developer's Github account gets compromised, a bad actor can easily edit or publish new releases and publish malware infected software and update the checksums. Even big actors such as [Microsoft](https://threatpost.com/report-microsofts-github-account-gets-hacked/155587/) and [Ubuntu](https://cisomag.eccouncil.org/canonicals-github-account-hacked/) have had incidents with their GitHub account.

AsfaLoad aims to propose a solution by:
* storing the checksum in an immutable form on the Symbol blockchain. This ensures that if an existing software release is updated, it will immediately be detected by downloaders
* using Multi Factor Authentication by requiring multiple accounts on different devices (preferably mobile) accept the checksum publication. This ensures that even if one developer's device is compromised, publishing checksum is still not possible
* easing integration of the validation in existing tools, using Symbol's REST API. This removes the burden of verification from the user.
"easing the publication of checksums by the developers by making it integratable in their release processes, such at Github Actions or Gitlab CI/CD.

# Economics
Checking a file validity is available to all and for free. No account is required on the Symbol blockchain.
Publishing file validity information is different. Sending transactions on the blockchain incurs small costs. Even though those are small, it requires the accounts used to maintain sufficient levels of XYMs to be able to announce the transactions.
With the aim of making our solution available with a minimum of effort required from the user, we want to propose a use-case backed by a centralised service hiding all blockchain related operations to the end-user. We call this the service-dependent setup.
The case where the end user maintains the Symbol accounts is not the focus at this time but is called the decentralised setup.

The goal is for this solution to work in both a decentralized setup where the user maintains the accounts, and a service-dependent setup, where the user does not need to maintain the accounts.

## Decentralized setup
This is the path we should ideally take, but it requires users to manage their own Symbol accounts and funds, the reason why an alternative approach, called the service-dependent setup, is also developed and acutallymade the initial focus.
In th decentralised setup, the publication of new file hashes is only dependent on the blockchain. The downside is that the users have to maintain sufficient of XYMs levels in their accounts themselves.

## Service-dependent setup
The advantage of this approach is that the user does not need to handle XYMs, the blockchain's native token used to pay fees, and ensure the accounts used are refilled in a timely manner. The downside is that the user is now dependent on an additional service maintained by a third-party.

The biggest change is that the `msig` account of the user is now a multisig 3 of 4 account, with `cosign1` and `cosign2` controlled by the end user as in the decentralised scenario, and with 2 additional cosignatories `service` and `serviceCosign2` controlled by the service.
The user will submit a new release with file hashes to be published to a webservice operating the `service` account. It is `service` that will anounce a aggregate bonded transaction to publish the new file hash. This bonded aggregate transaction will contain one transaction from the `msig` account with 2 characteristics:

* It sends a `asfaload.token` from `msig` to `serviceAccount`
* It includes an attached message to publish the file hashes of the release as requested by the user.

The advantage is that the end users don't have to manage the blockchain's native token (XYM) as fees are paid by the `service` account.
> **⚠PROBLEM:** There is a Denial Of Service (DOS) risk that has to be mitigated though: to broadcast a multisig transaction, the `service` account has to lock 10 XYMs. Solutions can be found, but the impact on the barrier to entry for end user needs to be assessed (requiring users to deposit funds to cover the locking, block accounts causing the loss of the locked amount, ... Collecting these funds could be done in the mobile app used for signing transactions)

Once this transaction is broadcasted, the remaining operations to be done by the end user are the same as in the decentralised scenario.

# Technical information
AsfaLoad uses the Symbol blockchain to publish files fingerprints of files proposed for downloads by the file's publisher. Being on the blockchain ensure that the fingerprint for a file will not be altered.
Symbol proposes unique features that match particularly well with our goals:
* multisig accounts are a native feature and are handled on-chain
* it is easy and practical to create application specific tokens
* restriction can be applied to both tokens and accounts, protecting from transactions spam
* metadata can be attached to accounts, facilitating the link between a Symbol account and a github or gitlab account

The directory `demo` contains script validating the approach described below, and has a README file that was written while running the scripts.
Below is some technical info without the hands-on approach found in the `demo/` directory.

## Creating User Accounts
* Create the account which will send the transactions with the file hashes. We call this account `msig`.
    * Send initial amount of `asfaload` token.
    * This account doesn't need any XYM
* Create the first cosignatory account, let's call it `cosign1`.
    * This account doesn't need any XYM
* Create the second cosignatory account, let's call it `cosign2`.
    * This account doesn't need any XYM

## Convert account to multisig
* Send multisig change as a AggregateComplete transaction. As at tge time of setting up the accounts our service has access to the privates keys of the accounts, an AggregateComplete transaction can be created and cosigned as needed.
    * add the user accounts `cosign1` and `cosign2` as cosignatories.
    * Both `service` and `serviceCosign` accounts are also added as cosignatories and the `msig` account is make a 3 of 4 multisig account. (For the decentralised scenario, only serviceCosign is added, and `msig` is 2 of 3 multisig).
    * `msig` needs to have the funds to pay the multisig conversion
    * the `service` account locks the 10 XYMs required to broadcast the aggregate bonded transaction.
* Cosign the transaction by all cosignatories.

## Link a Github account

To ensure the user registering a publishing account (github or gitlab) is the owner of the account, the user must create a new repo with the name communicated. This is similar to [LetsEncrypt](https://letsencrypt.org/)'s approach to validate domain ownership.
When the repository has been created and the service has validated it, the `msig` symbol account is tagged by the `service` account with the data `github:${account} = true`.
The information is put in the key as only the key of account metadata can be searched.
**TODO** check scaling of account search.

## Publish file hash
Payload format:
```
{
    version: "0.21.3',
    service: "github",
    service_account: "asfaload",
    files: [
        {
            hash: ${hash_scheme}:${hash_value},
            filename: ${filename},
        },
        {
            hash: ${hash_scheme}://${hash_value},
            filename: ${filename},
        }
    ]
```
The only `hash_sheme` supported at launch will be `sha256`, resulting in a `hash_value` of 256 bits, represented as 64 hexadecimal characters.
The message of a Symbol transaction can be [up to 1023 characters long](https://docs.symbolplatform.com/concepts/transfer-transaction.html#message).
One file entry in the message will thus look as
```
{
            hash: "sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
            filename: "secure_downloader"
},
```
using a typical 110 characters.
Considering the header and wrapping
```
{version:"0.21.3',service:"github",service_account:"asfaload",files:[]}
```
with a realistic length of 77 characters. We can reasonably expect the header to not exceed 90 characters, leaving 933 characters for the files signatures, corresponding to 8 file entries.
It is not unusual thought to have project publish more than 8 files per release. As an example, [this yq release](https://github.com/mikefarah/yq/releases/tag/v4.6.0) publishes 46 files for download.
This should not be a problem though, and will not increase the burden on the user: the AggregateBonded transaction will just include more than one transfer transaction from the `msig` account to the `service` account. The user accounts `cosign1` and `cosign2` will only have to cosign the aggregate bonded transaction, not the individual transfer transactions.
For the yq example publishing 46 files, the AggregateBonded transaction will include 6 transfer transactions (5 transactions covering 8 files, 1 covering 6 files).



### Service-dependent operation
In that mode:
* a developer asks our service to publish a new release
* our service prepares an AggregateBonded transaction of 1 `asfaload:token` and the message with the release info, from the user's multisig account to our service account.
* our service account signs the Aggregate bonded transaction and broadcasts it
* to be included, the transaction needs two additional signatures.
* `cosign1` and `cosign2` need to cosign the transaction for it to be included in the blockchain. If any fails to do so, the transaction is not published **and the locked XYMs are paid as fees**

**PROBLEM**: how to we prevent bad actors from emptying our service account? Do we require users to fund their account with 10$ from which we take the lost locks?

### Fully decentralised operation
In this case, it is a user's account, either `cosign1` or `cosign2` that broadcasts the AggregateBonded transaction, and to do so it needs to lock 10XYMs and pay the transaction fees. Hence the user needs to ensure the account(s) broadcasting the transaction has enough funds.

## Checking Authenticity of a downloaded file

* download file
* possibly identify the service account to use (based on namespace or tagging from a central service account)
* identify symbol account for this file
*  * look for account tagged from the `service` account with data `github:$username` available from the release download url
*  * retrieve 1 `asfaload:token` transfer transactions from that account to the `service` account
*  * identify the transaction that corresponds to the download url. This requires to loop through all releases and check the json payload in the message. As most downloads will be for the latest release, we can limit our search to the latest transactions and go back in time if needed. This should ease concerns regarding scalability of the solution. We see that operating this way covers the situation when a release published more files than can fit in one transaction message, as we will retrieve all transactions for the release until we find the one holding the hash for the downloaded file.
*  * from the json payload of the right message, extract the sha scheme and expected result
* compute sha of the downloaded file
* compare computed sha to expected sha

## Service-dedicated accounts
One option, to be evaluated, it so have a dedicated service account per publishing platform (eg github).
This would allow the publishing platforms to manage it as they see fit. The publishing platform probably also have possibilities to limit bad actors.
Implementing this is easy: associate the service account to a subnamespace, eg `asfaload:services:github`, or tag it from the central service account with `services:github = true`. The latter allows the use of multiple service account per publishing platform. While this may complicate the search, it might also bring additional flexibility.


## Definitions
* publishing a file: make the file available for download
* publishing platform: third party operated service that lets user publish files, eg github, gitlab.
* service account: a Symbol account to which users send transactions with the message holding information about published files. It is transaction send to a service account that will be searched to find a published file's information.

## Attention points
### Spam protections
The service account will only accept transactions involving our own token. This will prevent bad actors to spam our service account with transactions.
Only our service account can send our tokens to accounts, and those account can only send it back to our account. This also prevents spam an allow to limit the number of transaction by account if needed.
