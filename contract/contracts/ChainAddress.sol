// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

import "./User.sol";

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

library ChainAddressesFun {
    function setUserChainAddress(
        ChainAddressesStore storage store,
        UserId userId,
        address account
    ) internal {
        // Get next id
        ChainAddressId chainAddressId = ChainAddressId.wrap(++store.lastId);
        // Initialise address
        ChainAddress memory newChainAddress = ChainAddress(
            chainAddressId,
            account,
            0,
            userId
        );
        // Store in all address id mappign
        store.chainAddresses[chainAddressId] = newChainAddress;
        // Store in account mapping
        store.address2ChainAddressId[account] = chainAddressId;
        ChainAddressId[] storage userChainAddressIds = store
            .userId2ChainAddressId[userId];
        // Update current address
        if (userChainAddressIds.length > 0) {
            uint lastIndex = userChainAddressIds.length - 1;
            ChainAddressId currentChainAddressId = userChainAddressIds[
                lastIndex
            ];
            ChainAddress storage currentChainAddress = store.chainAddresses[
                currentChainAddressId
            ];
            currentChainAddress.expiry = block.timestamp;
        }
        // Append new address
        store.chainAddresses[newChainAddress.id] = newChainAddress;
        userChainAddressIds.push(newChainAddress.id);
    }
}
