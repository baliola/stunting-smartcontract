// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title IMetaTransaction - Interface for EIP-712-based meta-transaction support contracts
/// @notice Defines the essential structures, errors, and events for gasless transaction forwarding systems.
/// @dev Used in conjunction with contracts implementing MetaTransaction functionality (e.g., relayer-based execution).
interface IMetaTransaction {
    // ================================================================================
    //                                     ERRORS
    // ================================================================================

    /// @notice Thrown when a signer is not authorized for the attempted operation.
    /// @param signer The address attempting the action without permission.
    error Unauthorized(address signer);

    /// @notice Thrown when the provided nonce does not match the expected nonce.
    error InvalidNonce();

    /// @notice Thrown when the signature does not match the expected signer.
    error InvalidSignature();

    /// @notice Thrown when the execution of a meta-transaction fails.
    /// @param data The revert reason extracted from the failed call.
    error MetaTransactionFailed(string data);

    // ================================================================================
    //                                     STRUCTS
    // ================================================================================

    /// @notice Represents a signed meta-transaction request payload.
    /// @dev Contains signer, replay-protecting nonce, and calldata.
    struct Transaction {
        address from;
        uint256 nonce;
        bytes functionCall;
    }

    // ================================================================================
    //                                     EVENTS
    // ================================================================================

    /// @notice Emitted when a meta-transaction is successfully executed.
    /// @param user The original signer of the meta-transaction.
    /// @param functionCall The raw data representing the function that was executed.
    event MetaTransactionExecuted(address indexed user, bytes functionCall);

    // ================================================================================
    //                               EXTERNAL FUNCTIONS
    // ================================================================================

    /// @notice Allows a whitelisted relayer to execute a user-signed function on a target contract.
    /// @dev Implementation must handle signature verification and nonce checking internally.
    /// @param from Signer of the meta-transaction. 
    /// @param nonce Replay-protecting nonce.
    /// @param functionCall ABI-encoded function call (including selector and arguments).
    /// @param signature The user's signature over the typed meta-transaction.
    function executeMetaTransaction(
        address from,
        uint256 nonce,
        bytes calldata functionCall,
        bytes calldata signature
    ) external;
}
