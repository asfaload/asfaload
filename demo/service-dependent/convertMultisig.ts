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
    SignedTransaction,
    TransactionMapping,
} from 'symbol-sdk';

import {
  createHashLockTxForSignedTx,
  createSignedHashLockTx,
  repositoryFactory
} from '../common/Core'

import {
    SD_cosign1Account,
    SD_cosign2Account,
    SD_msigAccount,
    serviceCosignAccount,
    serviceAccount,
    printAccountsInfo
} from '../common/TestAccountsInfo'

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

    printAccountsInfo()

  const cosignAggregateCompleteTransaction = (
    transaction: SignedTransaction,
    account: Account,
  ): CosignatureSignedTransaction => {

    return CosignatureTransaction.signTransactionPayload(
      account,
      transaction.payload,
      networkGenerationHash,
    );

  };

    const multisigAccountModificationTransaction = MultisigAccountModificationTransaction.create(
        Deadline.create(epochAdjustment),
        3, // minApprovalDelta
        3, // minRemovalDelta
        [SD_cosign1Account.address, SD_cosign2Account.address, serviceCosignAccount.address, serviceAccount.address], // address additions
        [], // address deletions
        networkType,
    );
    const aggregateTransactionNotComplete = AggregateTransaction.createComplete(
        Deadline.create(epochAdjustment),
        [multisigAccountModificationTransaction.toAggregate(SD_msigAccount.publicAccount)],
        networkType,
        [], // cosignatures
        UInt64.fromUint(2000000), //maxFee
    );
    const serviceSignedTransactionNotComplete = serviceAccount.sign(
      aggregateTransactionNotComplete,
      networkGenerationHash,
    );
    console.log(`service signed not complete transaction hash : ${serviceSignedTransactionNotComplete.hash}`);

    //var signedTransaction = [SD_msigAccount,SD_cosign1Account,SD_cosign2Account].reduce<CosignatureSignedTransaction>( (acc,account) => cosignAggregateCompleteTransaction(acc,account),
    //cosignAggregateCompleteTransaction(serviceSignedTransactionNotComplete,serviceCosignAccount)
    //)

    const msigSigned = cosignAggregateCompleteTransaction(serviceSignedTransactionNotComplete,SD_msigAccount)
    const cosign1Signed = cosignAggregateCompleteTransaction(serviceSignedTransactionNotComplete,SD_cosign1Account)
    const cosign2Signed = cosignAggregateCompleteTransaction(serviceSignedTransactionNotComplete,SD_cosign2Account)
    const serviceCosignSigned = cosignAggregateCompleteTransaction(serviceSignedTransactionNotComplete,serviceCosignAccount)

    const cosignatureSignedTransactions = 
      [msigSigned, cosign1Signed, cosign2Signed,serviceCosignSigned]
      .map(
        (v) => 
          new CosignatureSignedTransaction(
            v.parentHash,
            v.signature,
            v.signerPublicKey ))

    const aggregateTransaction = TransactionMapping.createFromPayload(
      serviceSignedTransactionNotComplete.payload,
    ) as AggregateTransaction;

    const signedAggregateComplete = serviceAccount.signTransactionGivenSignatures(
      aggregateTransaction,
      cosignatureSignedTransactions,
      networkGenerationHash,
    );

    console.log("will announce transaction " + signedAggregateComplete.hash)
    transactionHttp
      .announce(signedAggregateComplete)
      .subscribe(
        (v) => console.log(v),
        (err) => console.log("error: " + err)
      )
}
main().then()
