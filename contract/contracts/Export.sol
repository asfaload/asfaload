// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;
import "./ChainAddress.sol";

library AsfaloadExport {
    // When we export the data of this contract, we build one struct of this type and return it.
    struct ExportData {
        // For users, we only export the last id as it doesn't store more data
        uint lastUserId;
        // For ChainAddresses, we store the last id even though it could be extracted
        // from the addresses array as it seems the easiest and most reliable.
        uint lastChainAddressId;
        ChainAddress[] addresses;
    }
}
