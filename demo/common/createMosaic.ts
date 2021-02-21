import {
    AggregateTransaction,
    Deadline,
    UInt64,
    MosaicDefinitionTransaction,
    MosaicFlags,
    MosaicId,
    MosaicNonce,
    MosaicSupplyChangeAction,
    MosaicSupplyChangeTransaction,
} from 'symbol-sdk';

import { map, mergeMap } from 'rxjs/operators';

import { 
  serviceAccount} from './TestAccountsInfo'
import {
  getEpochAdjustment,
  getGenerationHash,
  getNetworkType,
  getTransactionHttp,
}  from './Core'

// ----------------------
// Mosaic characteristics
// ----------------------
// 0 for non expiring mosaic
const duration=UInt64.fromUint(0);
const isSupplyMutable = true;
// this mosaic can only be transferred back to our service account
const isTransferable = false;
// we will probably define restrictions on the mosaic.
const isRestrictable = true;
const divisibility = 0;
const supply = 1000000;

const main = async (): Promise<void> => {
    const epochAdjustment = await getEpochAdjustment();
    const networkType = await getNetworkType();
    const networkGenerationHash = await getGenerationHash()
    const nonce = MosaicNonce.createRandom();

    // define mosaic
    const mosaicDefinitionTransaction = MosaicDefinitionTransaction.create(
        Deadline.create(epochAdjustment),
        nonce,
        MosaicId.createFromNonce(nonce, serviceAccount.address),
        MosaicFlags.create(isSupplyMutable, isTransferable, isRestrictable),
        divisibility,
        duration,
        networkType,
    );

    // define supply
    const delta = supply;
    const mosaicSupplyChangeTransaction = MosaicSupplyChangeTransaction.create(
        Deadline.create(epochAdjustment),
        mosaicDefinitionTransaction.mosaicId,
        MosaicSupplyChangeAction.Increase,
        UInt64.fromUint(delta * Math.pow(10, divisibility)),
        networkType,
    );

    // aggregate tx with mosaic definition and supply change
    const aggregateTransaction = AggregateTransaction.createComplete(
        Deadline.create(epochAdjustment),
        [
          mosaicDefinitionTransaction.toAggregate(serviceAccount.publicAccount),
          mosaicSupplyChangeTransaction.toAggregate(serviceAccount.publicAccount),
        ],
        networkType,
        [],
        UInt64.fromUint(2000000),
    );

    // sign aggregate transaction
    const signedTransaction = serviceAccount.sign(
        aggregateTransaction,
        networkGenerationHash,
      );
    
    const transactionHttp = getTransactionHttp();
    transactionHttp.announce(signedTransaction).subscribe(
        (x) => console.log(x.message),
        (err) => console.error(err),
      );


}

main().then();