import {
    Account,
    Address,
    AggregateTransaction,
    CosignatureTransaction,
    CosignatureSignedTransaction,
    Deadline,
    HashLockTransaction,
    MultisigAccountModificationTransaction,
    Mosaic,
    NetworkType,
    PlainMessage,
    RepositoryFactoryHttp,
    TransactionService,
    TransferTransaction,
    UInt64,
    TransactionGroup,
} from 'symbol-sdk';

import { map, mergeMap } from 'rxjs/operators';

import {
  printAccountsInfo,
  serviceAccount,
  SD_msigAccount,
  SD_cosign1Account,
  SD_cosign2Account} from '../common/TestAccountsInfo'
import {
  cosignAggregateBondedTransaction,
  cosignPartialTx,
  createFileHashTx,
  createSignedHashLockTx,
  repositoryFactory,
  wrapTransactionTxInMsig
}  from '../common/Core'

const main = async (): Promise<void> => {
    const epochAdjustment = await repositoryFactory.getEpochAdjustment().toPromise();
    const networkType = await repositoryFactory.getNetworkType().toPromise();
    const networkGenerationHash = await repositoryFactory.getGenerationHash().toPromise();
    const transactionRepository = repositoryFactory.createTransactionRepository();
    const listener = repositoryFactory.createListener();
    const receiptHttp = repositoryFactory.createReceiptRepository();
    const transactionHttp = repositoryFactory.createTransactionRepository();
    const transactionService = new TransactionService(transactionHttp, receiptHttp);
    // Returns the network main currency, symbol.xym
    const { currency } = await repositoryFactory.getCurrencies().toPromise();

    printAccountsInfo();
  const transferTransaction = await createFileHashTx()

  // To get an inner tx, call toAggregate(sender_account)
  const aggregateTransaction = await wrapTransactionTxInMsig(
    [ transferTransaction.toAggregate(SD_msigAccount.publicAccount),
    ])
  console.log("inner transactions size: " + aggregateTransaction.innerTransactions.length)

  const signedTransaction = serviceAccount.sign(
    aggregateTransaction,
    networkGenerationHash,
  );
  console.log("signer address: " + signedTransaction.getSignerAddress().pretty())

//  // lock 10 xym as spam prevention
  var signedHashLockTransaction
  try{
    signedHashLockTransaction = await createSignedHashLockTx(signedTransaction, serviceAccount)
    console.log(`signed hashlock tx: ${signedHashLockTransaction.hash}`)
  }
  catch(e){
    console.log("exception catched!")
    console.log(e)
  }

  listener.open().then(() => {
    console.log("will announce aggregate bonded")
    console.log("hashlock signer : " + signedHashLockTransaction.getSignerAddress().pretty())
    console.log("signedTransaction signer : " + signedTransaction.getSignerAddress().pretty())
    transactionService
      .announceHashLockAggregateBonded(
        signedHashLockTransaction,
        signedTransaction,
        listener,
      )
      .subscribe(
        (x) => {
          console.log("Aggregate transaction to check: " + x.transactionInfo.hash);
          if (process.argv[2] == "cosign") {
            console.log("transaction is automatically cosigned with cosign2. To prevent, pass 'partial' as first argument to the script ")
            cosignPartialTx(SD_cosign1Account, x)
              .subscribe(
                (x) => { console.log("Cosignature 1 result tx:" + x.message) },
                (err) => console.log("Cosignature1 error:" + err),
                () => console.log("Cosignature1: done?"),
              )
            cosignPartialTx(SD_cosign2Account, x)
              .subscribe(
                (x) => { console.log("Cosignature 2 result tx:" + x.message) },
                (err) => console.log("Cosignature2 error:" + err),
                () => console.log("Cosignature2: done?"),
              )
          } else {
            console.log("!!!!!!!!!!!  transaction was not cosigned, pass argument 'cosign' to have it cosigned immediately");
          }

        },
        (err) => console.log("Error with signedTx: " + err),
        () => { console.log("Closing listener");listener.close() },
      );
  })
  .then(() => console.log("after announce"));
}
main().then()
