import {
    Account,
    AccountMetadataTransaction,
    Address,
    AggregateTransaction,
    Deadline,
    HashLockTransaction,
    KeyGenerator,
    Metadata,
    MetadataSearchCriteria,
    MetadataType,
    Mosaic,
    NetworkType,
    Page,
    PlainMessage,
    RepositoryFactoryHttp,
    TransferTransaction,
    UInt64,
} from 'symbol-sdk';

import {
  cosignAggregateBondedTransaction,
  createFileHashTx,
  createSignedHashLockTx,
  wrapTransactionTxInMsig,
  repositoryFactory,
  cosignPartialTx,
  getEpochAdjustment,
  getNetworkType,
  getGenerationHash,
  getCurrency,
  getTransactionService
}  from './Core'

import {
    serviceAccount,
    msigAccount,
    cosign1Account,
    cosign2Account,
    printAccountsInfo
} from './TestAccountsInfo';


const main = async (): Promise<void> => {
    printAccountsInfo();
    const networkType = await getNetworkType();
    const epochAdjustment = await getEpochAdjustment();
    const networkGenerationHash = await getGenerationHash()
    const currency = await getCurrency();
    const listener = repositoryFactory.createListener();
    const transactionService = getTransactionService();
    const metadataHttp = repositoryFactory.createMetadataRepository();
    const key = process.argv[2];
    if (process.argv[2] == undefined) {
      console.log("provide the key to be found as argument to this script")
      process.exit(1)
    }
    const searchCriteria: MetadataSearchCriteria = {
        sourceAddress: serviceAccount.address,
        metadataType: MetadataType.Account,
        scopedMetadataKey: KeyGenerator.generateUInt64Key(key).toHex()
      };



      metadataHttp.search(searchCriteria).subscribe(
        (metadataEntries: Page<Metadata>) => {
          if (metadataEntries.pageSize > 0) {
            console.log('Page', metadataEntries.pageNumber);
            metadataEntries.data.map((entry: Metadata) => {
              const metadataEntry = entry.metadataEntry;
              console.log(
                'Account found:\t',
                metadataEntry.targetAddress.pretty(),
              );
            });
          } else {
            console.log('\n The address does not have metadata entries assigned.');
          }
        },
        (err) => console.log(err),
      );
}

main().then()