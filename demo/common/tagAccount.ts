// This script assigns metadata with key "provider" and value "service1"
// to the msig account found in TestAccountsInfo.ts
// The announced transaction then has to be cosigned by both msig cosignatories.
// This script action should be included in setupAccounts.ts
import { 
    Account,
    AccountMetadataTransaction,
    Address,
    AggregateTransaction,
    Deadline,
    HashLockTransaction,
    KeyGenerator,
    Mosaic,
    NetworkType,
    PlainMessage,
    RepositoryFactoryHttp,
    TransferTransaction,
    UInt64,
} from 'symbol-sdk';

import {
  repositoryFactory,
  getEpochAdjustment,
  getNetworkType,
  getGenerationHash,
  getCurrency,
  getTransactionService
}  from './Core'

import {
    serviceAccount,
    msigAccount,
    printAccountsInfo
} from './TestAccountsInfo';

printAccountsInfo()

const address:string = process.argv[2];
const keyString:string = process.argv[3];
if (keyString==undefined || address ==undefined) {
  console.log("provide the address and value to tag with as arguments to the script")
  process.exit(1);
}
const key = KeyGenerator.generateUInt64Key(keyString);
const value = "true";

const main = async (): Promise<void> => {
    const networkType = await getNetworkType();
    const epochAdjustment = await getEpochAdjustment();
    const networkGenerationHash = await getGenerationHash()
    const currency = await getCurrency();
    const listener = repositoryFactory.createListener();
    const transactionService = getTransactionService();


    const accountMetadataTransaction = AccountMetadataTransaction.create(
        Deadline.create(epochAdjustment),
        Address.createFromRawAddress(address),
        key,
        value.length,
        value,
        networkType,
      );

      const aggregateTransaction = AggregateTransaction.createBonded(
        Deadline.create(epochAdjustment),
        [accountMetadataTransaction.toAggregate(serviceAccount.publicAccount)],
        networkType,
        [],
        UInt64.fromUint(2000000),
      );

      const signedTransaction = serviceAccount.sign(
        aggregateTransaction,
        networkGenerationHash,
      );

    const hashLockTransaction = HashLockTransaction.create(
        Deadline.create(epochAdjustment),
        new Mosaic(
            currency.mosaicId,
            UInt64.fromUint(10 * Math.pow(10, currency.divisibility)),
        ),
        UInt64.fromUint(480),
        signedTransaction,
        networkType,
        UInt64.fromUint(2000000),
    );

    const signedHashLockTransaction = serviceAccount.sign(
        hashLockTransaction,
        networkGenerationHash,
      );
      listener.open().then(() => {
        console.log('will announce')
        transactionService
          .announceHashLockAggregateBonded(
            signedHashLockTransaction,
            signedTransaction,
            listener,
          )
          .subscribe(
            (x) => console.log("aggregate tx hash: " + x.transactionInfo.hash),
            (err) => console.log(err),
            () => listener.close(),
          );
      });
      
      

}

main().then();