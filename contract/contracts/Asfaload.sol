// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

// Notes on limiting contract size:
// https://ethereum.org/en/developers/tutorials/downsizing-contracts-to-fight-the-contract-size-limit/
// The code below uses a lot of assignments of intermediate variables for readability, but this adds to the  bytecode size....
// Thorten error messages
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "./Utils.sol";
////////////////////////////////////////////////////////////////////////////////
// Users
////////////////////////////////////////////////////////////////////////////////
// We don't store PII in the contract, but every user gets a UserId assigned
type UserId is uint;

struct User {
    UserId id;
}
// Users storage. OpenZeppelin's iterable mappings don't support
// user defined structs.
// As the mapping is not iterable, we collects the keys in an array ourselves.
struct UsersStore {
    mapping(UserId => User) users;
    uint lastId;
}

////////////////////////////////////////////////////////////////////////////////
// ChainAddresses
////////////////////////////////////////////////////////////////////////////////

// A ChainAddress is a blockchain address that is (or was) used by a user.
type ChainAddressId is uint;
struct ChainAddress {
    ChainAddressId id;
    address account;
    uint expiry;
    UserId userId;
}

struct ChainAddressesStore {
    // ChainAddress
    mapping(ChainAddressId => ChainAddress) chainAddresses;
    mapping(address => ChainAddressId) address2ChainAddressId;
    mapping(UserId => ChainAddressId[]) userId2ChainAddressId;
    uint lastId;
}

contract Asfaload is Initializable {
    UsersStore users;
    ChainAddressesStore addresses;

    function createUser(
        string calldata chainAddressString
    ) public returns (UserId userId) {
        // get next id
        userId = UserId.wrap(++users.lastId);
        // Initialise user
        User memory user = User(userId);
        // Store in id mapping
        users.users[userId] = user;

        address chainAddress = AsfaloadUtils.stringToAddress(
            chainAddressString
        );
        setUserChainAddress(userId, chainAddress);

        return userId;
    }

    function setUserChainAddress(UserId userId, address account) public {
        // Get next id
        ChainAddressId chainAddressId = ChainAddressId.wrap(++addresses.lastId);
        // Initialise address
        ChainAddress memory newChainAddress = ChainAddress(
            chainAddressId,
            account,
            0,
            userId
        );
        // Store in all address id mappign
        addresses.chainAddresses[chainAddressId] = newChainAddress;
        // Store in account mapping
        addresses.address2ChainAddressId[account] = chainAddressId;
        ChainAddressId[] storage userChainAddressIds = addresses
            .userId2ChainAddressId[userId];
        // Update current address
        if (userChainAddressIds.length > 0) {
            uint lastIndex = userChainAddressIds.length - 1;
            ChainAddressId currentChainAddressId = userChainAddressIds[
                lastIndex
            ];
            ChainAddress storage currentChainAddress = addresses.chainAddresses[
                currentChainAddressId
            ];
            currentChainAddress.expiry = block.timestamp;
        }
        // Append new address
        addresses.chainAddresses[newChainAddress.id] = newChainAddress;
        userChainAddressIds.push(newChainAddress.id);
    }
}
