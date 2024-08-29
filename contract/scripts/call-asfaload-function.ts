// 1. Update imports
import { ethers } from "ethers";
import { getDefaultProvider } from 'ethers';
import { Contract } from 'ethers';
import * as fs from 'fs';

//*******************************************************************************
// Multi chain support
//*******************************************************************************
// Import contract address as type macro to have it evaluated at compile time
// https://bun.sh/docs/bundler/macros
var contractAddress;
const backingChain = "dev";
var privateKey: string = "0x5fb92d6e98884f76de468fa3f6278f8807c48bebc13595d45af5bdc4da702133";
if (process.env.ASFALOAD_ADDRESS != undefined) {
  contractAddress = process.env.ASFALOAD_ADDRESS!;
}
else {
  console.error("No contract address in ASFALOAD_ADDRESS.");
  process.exit(1)
}
if (process.env.ASFALOAD_PRIVATE_KEY != undefined) {
  privateKey = process.env.ASFALOAD_PRIVATE_KEY!;
}
const provider = new ethers.JsonRpcProvider('http://127.0.0.1:9944', {
  chainId: 1281,
  name: "dev",
});

console.log(`Working on chain ${backingChain} with contract ${contractAddress}`);
//*******************************************************************************
// We can read the abi from the contract's artifacts
var info = JSON.parse(fs.readFileSync('../contract/artifacts/contracts/Asfaload.sol/Asfaload.json', 'utf8'));
const abi = info.abi

const contract = new Contract(contractAddress, abi, provider);

// 4. Create get function
const get = async () => {
  console.log(`Making a call to contract at address: ${contractAddress}`);

  // 5. Call contract
  const data = await contract[process.argv[2]](...process.argv.slice(3));

  console.log(`The value returned is: ${data}`);
};

// 6. Call get function
get();
