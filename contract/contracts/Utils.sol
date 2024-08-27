// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.24;

library AsfaloadUtils {
    // Inspired from https://ethereum.stackexchange.com/a/163672
    function hexCharToByte(bytes1 char) internal pure returns (uint8) {
        uint8 byteValue = uint8(char);
        if (
            byteValue >= uint8(bytes1("0")) && byteValue <= uint8(bytes1("9"))
        ) {
            return byteValue - uint8(bytes1("0"));
        } else if (
            byteValue >= uint8(bytes1("a")) && byteValue <= uint8(bytes1("f"))
        ) {
            return 10 + byteValue - uint8(bytes1("a"));
        } else if (
            byteValue >= uint8(bytes1("A")) && byteValue <= uint8(bytes1("F"))
        ) {
            return 10 + byteValue - uint8(bytes1("A"));
        }
        revert("Invalid hex character");
    }

    // Converts a string representation of an address to an address
    function stringToAddress(
        string memory str
    ) internal pure returns (address) {
        bytes memory stringBytes = bytes(str);
        require(stringBytes.length == 42, "Address length incorrect");
        bytes memory addressBytes = new bytes(20);

        for (uint i = 0; i < 20; i++) {
            addressBytes[i] = bytes1(
                hexCharToByte(stringBytes[2 + i * 2]) *
                    16 +
                    hexCharToByte(stringBytes[3 + i * 2])
            );
        }

        return address(uint160(bytes20(addressBytes)));
    }
}
