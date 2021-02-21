import {
    Account,
    Address,
    Deadline,
    NetworkType,
    PlainMessage,
    RepositoryFactoryHttp,
    TransferTransaction,
    UInt64,
} from 'symbol-sdk';

import {
        transferServiceTokenAmount,
}  from './Core'

// This file loop 1000 time to create an account, send it 20 XYM, and then send
// from that account a transaction with json payload about file hash.


async function main()  {
    const apiNode = 'http://api-01.eu-central-1.testnet.symboldev.network:3000';
    const repositoryFactory = new RepositoryFactoryHttp(apiNode);
    const epochAdjustment = await repositoryFactory.getEpochAdjustment().toPromise();
    const networkType = await repositoryFactory.getNetworkType().toPromise();
    const networkGenerationHash = await repositoryFactory.getGenerationHash().toPromise();
    const transactionRepository = repositoryFactory.createTransactionRepository();
    // Returns the network main currency, symbol.xym
    const { currency } = await repositoryFactory.getCurrencies().toPromise();

    let recipient: string = process.argv[2];
    let amount: number = 50;
    console.log(`recipient = ${recipient} and amount = ${amount}`)
    const res = await transferServiceTokenAmount(Address.createFromRawAddress(recipient), amount, "service transfer");
    return res;

}

main().then( (r) => {console.log(`response: ${r.message}`)});
