// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

import "./Utils.sol";
import "./ChainAddress.sol";

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

library UsersFun {
    function createUser(
        UsersStore storage store
    ) public returns (UserId userId) {
        // get next id
        userId = UserId.wrap(++store.lastId);
        // Initialise user
        User memory user = User(userId);
        // Store in id mapping
        store.users[userId] = user;

        return userId;
    }
}
