// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {DataEntryRegistry} from "./Registry/DataEntryRegistry.sol";
import {MetaTransaction, EIP712} from "./Utils/MetaTransaction.sol";

contract DataEntry is DataEntryRegistry, MetaTransaction {
    constructor(
        address _rbacAddress,
        string memory _name,
        string memory _version
    )
        DataEntryRegistry(_rbacAddress)
        EIP712(_name, _version)
        MetaTransaction(msg.sender)
    {}
    function submitData(
        bytes32 metadataHash,
        bytes calldata signature
    ) external {
        _submitData(metadataHash, signature);
    }

    function getDataEntry(
        bytes32 dataHash
    ) external view returns (DataEntry memory entry) {
        return _getDataEntry(dataHash);
    }

    function isDataSubmitted(
        bytes32 hash
    ) external view returns (bool submitted) {
        return _isDataSubmitted(hash);
    }
}
