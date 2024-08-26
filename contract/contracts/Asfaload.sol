// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

// Notes on limiting contract size:
// https://ethereum.org/en/developers/tutorials/downsizing-contracts-to-fight-the-contract-size-limit/
// The code below uses a lot of assignments of intermediate variables for readability, but this adds to the  bytecode size....
// Thorten error messages
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "./User.sol";
import "./ChainAddress.sol";
import "./Utils.sol";

contract Asfaload is Initializable {
    using UsersFun for UsersStore;
    UsersStore users;
    using ChainAddressesFun for ChainAddressesStore;
    ChainAddressesStore addresses;

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
}
