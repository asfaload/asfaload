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
    printAccountsInfo
} from '../common/TestAccountsInfo'
import { msigAccount } from '../common/TestAccountsInfo';

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
        2, // minApprovalDelta
        2, // minRemovalDelta
        [SD_cosign1Account.address, SD_cosign2Account.address], // address additions
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
    const msigSignedTransactionNotComplete = msigAccount.sign(
      aggregateTransactionNotComplete,
      networkGenerationHash,
    );
    console.log(`service signed not complete transaction hash : ${msigSignedTransactionNotComplete.hash}`);

    //var signedTransaction = [SD_msigAccount,SD_cosign1Account,SD_cosign2Account].reduce<CosignatureSignedTransaction>( (acc,account) => cosignAggregateCompleteTransaction(acc,account),
    //cosignAggregateCompleteTransaction(serviceSignedTransactionNotComplete,serviceCosignAccount)
    //)

    const cosign1Signed = cosignAggregateCompleteTransaction(msigSignedTransactionNotComplete,SD_cosign1Account)
    const cosign2Signed = cosignAggregateCompleteTransaction(msigSignedTransactionNotComplete,SD_cosign2Account)

    const cosignatureSignedTransactions = 
      [cosign1Signed, cosign2Signed]
      .map(
        (v) => 
          new CosignatureSignedTransaction(
            v.parentHash,
            v.signature,
            v.signerPublicKey ))

    const aggregateTransaction = TransactionMapping.createFromPayload(
      msigSignedTransactionNotComplete.payload,
    ) as AggregateTransaction;

    const signedAggregateComplete = SD_msigAccount.signTransactionGivenSignatures(
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
