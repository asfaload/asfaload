import {
    Address,
    MosaicId,
    Page,
    PublicAccount,
    Transaction,
    TransactionGroup,
    TransactionSearchCriteria,
    TransactionType,
    TransferTransaction,
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
    printAccountsInfo,
    mosaicId
} from './TestAccountsInfo';


const main = async (): Promise<void> => {
    printAccountsInfo();
    const networkType = await getNetworkType();
    const epochAdjustment = await getEpochAdjustment();
    const networkGenerationHash = await getGenerationHash()
    const currency = await getCurrency();
    const listener = repositoryFactory.createListener();
    const transactionService = getTransactionService();
    const transactionHttp = repositoryFactory.createTransactionRepository();

    const publicKey = process.argv[2]
    if (publicKey==undefined){
      console.log("provide ipublic key of account to list transactions for")
      process.exit(1)
    }
    // Search for transfer transactions of our token from the user's msig account to our service account.
    // Those give access to the payload
    const searchCriteria: TransactionSearchCriteria= {
        recipientAddress: serviceAccount.address,
        type: [TransactionType.TRANSFER],
        embedded: true,
        group: TransactionGroup.Confirmed,
        transferMosaicId: new MosaicId(mosaicId),
        signerPublicKey: publicKey,
      };



      transactionHttp.search(searchCriteria).subscribe(
        (metadataEntries: Page<Transaction>) => {
          if (metadataEntries.pageSize > 0) {
            console.log('Page', metadataEntries.pageNumber);
            metadataEntries.data.map((entry: Transaction) => {
              var tt = entry as TransferTransaction;
              console.log("message: " + (tt.message.payload));
            });
          } else {
            console.log('\n The address does not have corresponding transactions.');
          }
        },
        (err) => console.log(err),
      );
}

main().then()
