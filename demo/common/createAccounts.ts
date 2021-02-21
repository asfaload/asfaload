// Setup accounts for service dependent operations:
// th emsig account is 3 of 4 with the serviceCosignAccount as a cosignatory
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
import { serviceAccount,serviceCosignAccount, } from '../common/TestAccountsInfo';


const main = async (): Promise<void> => {
    console.log(
      'Your service account address is:',
      serviceAccount.address.pretty(),
      'and its private key',
      serviceAccount.privateKey,
    );

    console.log(
      'Your service cosign account address is:',
      serviceCosignAccount.address.pretty(),
      'and its private key',
      serviceCosignAccount.privateKey,
    );

    const msigAccount = Account.generateNewAccount(NetworkType.TEST_NET);
    console.log(
      'Your new msig account address is:',
      msigAccount.address.pretty(),
      'and its private key',
      msigAccount.privateKey,
    );

    const cosign1Account = Account.generateNewAccount(NetworkType.TEST_NET);
    console.log(
      'Your new cosign1 account address is:',
      cosign1Account.address.pretty(),
      'and its private key',
      cosign1Account.privateKey,
    );

    const cosign2Account = Account.generateNewAccount(NetworkType.TEST_NET);
    console.log(
      'Your new cosign2 account address is:',
      cosign2Account.address.pretty(),
      'and its private key',
      cosign2Account.privateKey,
    );


    // Service dependent accounts
    const SD_msigAccount = Account.generateNewAccount(NetworkType.TEST_NET);
    console.log(
      'Your new SD_msig account address is:',
      SD_msigAccount.address.pretty(),
      'and its private key',
      SD_msigAccount.privateKey,
    );

    const SD_cosign1Account = Account.generateNewAccount(NetworkType.TEST_NET);
    console.log(
      'Your new SD_cosign1 account address is:',
      SD_cosign1Account.address.pretty(),
      'and its private key',
      SD_cosign1Account.privateKey,
    );

    const SD_cosign2Account = Account.generateNewAccount(NetworkType.TEST_NET);
    console.log(
      'Your new SD_cosign2 account address is:',
      SD_cosign2Account.address.pretty(),
      'and its private key',
      SD_cosign2Account.privateKey,
    );
}
main().then()
