import {
    Account,
    Address,
    AggregateTransaction,
    CosignatureSignedTransaction,
    CosignatureTransaction,
    Currency,
    Deadline,
    HashLockTransaction,
    InnerTransaction,
    Mosaic,
    MosaicId,
    NamespaceId,
    NetworkType,
    PlainMessage,
    PublicAccount,
    RawAddress,
    RepositoryFactoryHttp,
    SignedTransaction,
    TransactionAnnounceResponse,
    TransactionGroup,
    TransactionService,
    TransferTransaction,
    UInt64,
} from 'symbol-sdk';
import { map, mergeMap } from 'rxjs/operators';
import {
    mosaicId,
    serviceAccount
} from './TestAccountsInfo'

const apiNode = 'http://api-01.eu-west-1.testnet.symboldev.network:3000';
export const repositoryFactory = new RepositoryFactoryHttp(apiNode);
const transactionRepository = repositoryFactory.createTransactionRepository();


function getProvider() {
    var knownProviders = ["provider1", "domain2", "service3"]
    return knownProviders[Math.floor(Math.random() * knownProviders.length)]
}
function randomShortString() {
    return Math.random().toString(36).substring(2, 15);
}
function randomString() {
    const iterations = Math.floor(Math.random() * 10) + 1;
    var i = 0;
    var s = "";
    while (i < iterations) {
        s += randomShortString()
        i++;
    }
    return s
}
export const getEpochAdjustment = async() => {
    return await repositoryFactory.getEpochAdjustment().toPromise();
}

export const getNetworkType = async() => {
    return await repositoryFactory.getNetworkType().toPromise();
}

export const getGenerationHash = async() => {
    return await repositoryFactory.getGenerationHash().toPromise();
}

export const getCurrency = async() => {
    const { currency } = await repositoryFactory.getCurrencies().toPromise();
    return currency
}

export function getTransactionService() {
    const receiptHttp = repositoryFactory.createReceiptRepository();
    const transactionHttp = repositoryFactory.createTransactionRepository();
    return new TransactionService(transactionHttp, receiptHttp);
}

export function getTransactionHttp() {
    return repositoryFactory.createTransactionRepository();
}

export const createServiceMosaicTransferTx = async(address:Address, message:string, mosaic:Mosaic):Promise<TransferTransaction> => {
    const epochAdjustment = await repositoryFactory.getEpochAdjustment().toPromise();
    const networkType = await repositoryFactory.getNetworkType().toPromise();
    const transferTransaction = TransferTransaction.create(
        Deadline.create(epochAdjustment),
        address,
        [mosaic],
        PlainMessage.create(message),
        networkType,
        UInt64.fromUint(2000000),
    );
    return transferTransaction
}

export const createServiceXymTransferTx = async(address:Address, amount:number, message:string):Promise<TransferTransaction> => {
    // Returns the network main currency, symbol.xym
    const { currency } = await repositoryFactory.getCurrencies().toPromise();
    return createServiceMosaicTransferTx(address,message,currency.createRelative(amount));
}

export const createServiceTokenTransferTx = async(address:Address, amount:number, message:string):Promise<TransferTransaction> => {
    const mosaic = new Mosaic(new MosaicId(mosaicId), UInt64.fromUint(amount))
    return createServiceMosaicTransferTx(address,message,mosaic);
}

export const signServiceTransferTx = async (transferTransaction: TransferTransaction): Promise<SignedTransaction> => {
    const networkGenerationHash = await repositoryFactory.getGenerationHash().toPromise();
    return serviceAccount.sign(
        transferTransaction,
        networkGenerationHash,
    );
}

export async function transferServiceXymAmount(recipient: Address, amount: number, message: string): Promise<TransactionAnnounceResponse> {
    const transferTransaction = await createServiceXymTransferTx(recipient, amount, message);
    const signedTransaction = await signServiceTransferTx(transferTransaction);
    const response = await transactionRepository
        .announce(signedTransaction)
        .toPromise();
    return response;
}

export async function transferServiceTokenAmount(recipient: Address, amount: number, message: string): Promise<TransactionAnnounceResponse> {
    const transferTransaction = await createServiceTokenTransferTx(recipient, amount, message);
    const signedTransaction = await signServiceTransferTx(transferTransaction);
    const response = await transactionRepository
        .announce(signedTransaction)
        .toPromise();
    return response;
}
export const createFileHashTx = async (): Promise<TransferTransaction> => {
    const message = `{"provider": "${getProvider()}", "filename":"${randomString()}", "hash":"${randomString()}"}`;
    const epochAdjustment = await repositoryFactory.getEpochAdjustment().toPromise();
    // Returns the network main currency, symbol.xym
    const mosaic = new Mosaic(new MosaicId(mosaicId), UInt64.fromUint(1))
    const networkType = await repositoryFactory.getNetworkType().toPromise();
    const transferTransaction = TransferTransaction.create(
        Deadline.create(epochAdjustment),
        serviceAccount.address,
        [mosaic],
        PlainMessage.create(message),
        networkType,
        UInt64.fromUint(2000000),
    );
    return transferTransaction
}

export const sendFileHash = async (sender: Account): Promise<string> => {
    const networkGenerationHash = await repositoryFactory.getGenerationHash().toPromise();
    const transferTransaction = await createFileHashTx();
    const signedTransaction = sender.sign(
        transferTransaction,
        networkGenerationHash,
    );
    const response = await transactionRepository
        .announce(signedTransaction)
        .toPromise();
    return transferTransaction.message.payload;
}

type txToWrap = TransferTransaction|TransferTransaction[]|InnerTransaction|InnerTransaction[]
export const wrapTransactionTxInMsig = async (transferTransactions:txToWrap, defaultSenderAccount?:PublicAccount): Promise<AggregateTransaction> => {
    const epochAdjustment = await repositoryFactory.getEpochAdjustment().toPromise();
    const networkType = await repositoryFactory.getNetworkType().toPromise();
    var txs;
    if (Array.isArray(transferTransactions)) {
        if (transferTransactions.every( (t) => ("signer" in t) )) {
            // checks for the type InnerTransaction cannot be tested the same way as TransfertTransaction because it is not defined as a class.
            // but it's only possibility in our case, so we can go ahead
            var it = transferTransactions as InnerTransaction[];
            console.log('we got inner transactions, using them as is')
            txs =transferTransactions
        } else{
            console.log("got arry of transactions, will map them")
            var t = transferTransactions as TransferTransaction[];
            txs =t.map((t:TransferTransaction) => t.toAggregate(defaultSenderAccount))
        }
    }
    else {
        if ("signer" in transferTransactions)  {
            console.log("got single transaction, will map and put in array")
            txs = [transferTransactions.toAggregate(defaultSenderAccount)]
        } else {
            // checks for the type InnerTransaction cannot be tested the same way as TransfertTransaction because it is not defined as a class.
            // but it's only possibility in our case, so we can go ahead
            console.log('we got inner transactions, putting it in an array as is')
            txs = [transferTransactions]
        }
    }
    const aggregateTransaction = AggregateTransaction.createBonded(
        Deadline.create(epochAdjustment),
        txs,
        networkType,
        [],
        UInt64.fromUint(2000000), //maxFee
    );
    return aggregateTransaction

}

export const createHashLockTxForSignedTx = async(signedTransaction:SignedTransaction):Promise<HashLockTransaction> => {
    const { currency } = await repositoryFactory.getCurrencies().toPromise();
    const epochAdjustment = await repositoryFactory.getEpochAdjustment().toPromise();
    const networkType = await repositoryFactory.getNetworkType().toPromise();
    return HashLockTransaction.create(
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
}

export const signHashLockTx = async(hashLockTransaction:HashLockTransaction, account:Account) : Promise<SignedTransaction> => {
    const networkGenerationHash = await repositoryFactory.getGenerationHash().toPromise();
    return account.sign(
        hashLockTransaction,
        networkGenerationHash,
      );
}

export const createSignedHashLockTx = async(signedTransaction:SignedTransaction,account:Account): Promise<SignedTransaction> => {
    const hashLockTx = await createHashLockTxForSignedTx(signedTransaction);
    return await signHashLockTx(hashLockTx,account);
}

export const cosignAggregateBondedTransaction = (
    transaction: AggregateTransaction,
    account: Account,
): CosignatureSignedTransaction => {
    const cosignatureTransaction = CosignatureTransaction.create(transaction);
    return account.signCosignatureTransaction(cosignatureTransaction);
};

export const cosignPartialTx= (cosignAccount: Account, aggregateTransaction: AggregateTransaction) => {
    const transactionHttp = repositoryFactory.createTransactionRepository();
    const cosignTx = cosignAggregateBondedTransaction(aggregateTransaction,cosignAccount);
    return transactionHttp.announceAggregateBondedCosignature(cosignTx)
// you should subscribe to the returned value like this:
//    .subscribe(
//    (x) => { console.log("Cosignature result tx:" + x.message)},
//    (err) => console.log("Cosignature error:"+err),
//    () => console.log("Cosignature: done!"));
}

export const cosignPartialTxHash = (cosignAccount: Account, hash: string) => {
    const transactionHttp = repositoryFactory.createTransactionRepository();

    transactionHttp
        .getTransaction(hash, TransactionGroup.Partial)
        .pipe(
            map((transaction) =>
                cosignAggregateBondedTransaction(
                    transaction as AggregateTransaction,
                    cosignAccount,
                ),
            ),
            mergeMap((cosignatureSignedTransaction) =>
                transactionHttp.announceAggregateBondedCosignature(
                    cosignatureSignedTransaction,
                ),
            ),
        )
        .subscribe(
            (announcedTransaction) => console.log("cosign2 tx: " + announcedTransaction.message),
            (err) => console.error("cosign2 error: " + err),
        );
}