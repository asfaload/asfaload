// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

// Notes on limiting contract size:
// https://ethereum.org/en/developers/tutorials/downsizing-contracts-to-fight-the-contract-size-limit/
// The code below uses a lot of assignments of intermediate variables for readability, but this adds to the  bytecode size....
// Thorten error messages
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "./User.sol";
import "./ChainAddress.sol";
import "./Export.sol";
import "./Utils.sol";

contract Asfaload is Initializable, OwnableUpgradeable {
    using UsersFun for UsersStore;
    UsersStore users;
    using ChainAddressesFun for ChainAddressesStore;
    ChainAddressesStore addresses;

    // Create a new user with it chain address
    function createUser(
        string calldata chainAddressString
    ) public returns (UserId userId) {
        // Convert string representation of address to an address
        address chainAddress = AsfaloadUtils.stringToAddress(
            chainAddressString
        );
        // Create user in store, then set its chainAddress
        userId = users.createUser();
        addresses.setUserChainAddress(userId, chainAddress);
    }

    // Get the current lastUserId
    function getLastUserId() public view returns (uint) {
        return users.lastId;
    }

    // We want to be able to export the data managed by the contract for 2 reasons:
    // - it is useful for tests
    // - in case we need need to migrate to another contract or blockchain. Not in the plans, but better safe than sorry later on.
    // Our data is stored in structs holding the data, and mappings are used as indexes on fields of these structs.
    // This means that we only need to export the structs, and the mappings can be reconstructed.
    function export() public view returns (AsfaloadExport.ExportData memory) {
        // ChainAddresses
        // --------------
        // Initialise an array of the size of the last chain address id, which is by
        // definition the highest number of items we will possibly export.
        ChainAddress[] memory addressesExport = new ChainAddress[](
            addresses.lastId
        );
        // Put all chain addresses in the array
        for (uint i = 1; i <= addresses.lastId; i++) {
            addressesExport[i] = addresses.chainAddresses[
                ChainAddressId.wrap(i)
            ];
        }

        // Build the struct to be returned
        AsfaloadExport.ExportData memory exportData = AsfaloadExport.ExportData(
            users.lastId,
            addresses.lastId,
            addressesExport
        );

        return exportData;
    }
}
