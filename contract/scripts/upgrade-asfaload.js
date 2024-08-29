const { ethers, upgrades } = require("hardhat");
const fs = require("fs");
const dotenv = require("dotenv");
dotenv.config({ path: `.asfaload_address_${process.env.CHAIN ? process.env.CHAIN : "dev"}` })
const ASFALOAD_ADDRESS = process.env.ASFALOAD_ADDRESS;
async function main() {
  const Asfaload = await ethers.getContractFactory("Asfaload");
  const asfaload = await upgrades.upgradeProxy(ASFALOAD_ADDRESS, Asfaload);
  console.log(`Asfaload upgraded at ${ASFALOAD_ADDRESS}`);
}

main();
