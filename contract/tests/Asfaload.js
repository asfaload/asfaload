// Import Ethers
const { ethers } = require('hardhat');

// Import Chai to use its assertion functions here
const { expect } = require('chai');


describe('Asfaload contract', function () {

  async function deployAsfaload() {
    const asfaloadFactory = await ethers.getContractFactory(
      'Asfaload'
    );

    try {

      const Asfaload = await ethers.getContractFactory("Asfaload");
      const asfaload = await upgrades.deployProxy(Asfaload, []);
      await asfaload.waitForDeployment();
      return { deployedAsfaload: asfaload };

    } catch (error) {
      console.error('Failed to deploy contract:', error);
      return null; // Return null to indicate failure
    }
  }
  describe('Deployment', function () {
    it('should have lastUserId be 0', async function () {
      const deployment = await deployAsfaload();
      if (!deployment || !deployment.deployedAsfaload) {
        throw new Error('Deployment failed; Asfaload contract was not deployed.');
      }
      const { deployedAsfaload } = deployment;

      expect(await deployedAsfaload.getLastUserId()).to.equal(
        0n
      );
    });

    it('should export', async function () {
      const deployment = await deployAsfaload();
      if (!deployment || !deployment.deployedAsfaload) {
        throw new Error('Deployment failed; Asfaload contract was not deployed.');
      }
      const { deployedAsfaload } = deployment;

      expect(await deployedAsfaload.export()).to.deep.equal(
        [
          0n,
          0n,
          []
        ]
      );
    });

  });
})
