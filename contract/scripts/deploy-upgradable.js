const { ethers, upgrades } = require("hardhat");
const fs = require("fs");

async function main() {
  const Asfaload = await ethers.getContractFactory("Asfaload");
  const asfaload = await upgrades.deployProxy(Asfaload, []);
  await asfaload.waitForDeployment();
  const asfaloadAddress = await asfaload.getAddress();
  const envVar = `ASFALOAD_ADDRESS=${asfaloadAddress}`;
  fs.writeFileSync(`.asfaload_address_${(process.env.NETWORK) ? process.env.NETWORK : "dev"}`, envVar);
  console.log("Asfaload deployed to:", asfaloadAddress);
  console.log(" !!! Take note of the deployed address for future upgrades !!!");
}

main();
