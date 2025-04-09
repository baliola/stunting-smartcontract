// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title ITransparency - Interface for emitting system activity logs for traceability and auditability.
/// @author @anggadanarp
/// @notice Defines the logging mechanism for recording user actions related to data and report interactions.
/// @dev Implemented by TransparencyRegistry. Used across modules like StuntingRegistry and PerformanceReportRegistry.
interface ITransparency {
    // ================================================================================
    //                                     EVENTS
    // ================================================================================

    /// @notice Emitted when an action occurs within the system and needs to be tracked for transparency.
    /// @param actor The address performing the action (e.g., petugas, evaluator, admin).
    /// @param action A descriptive string of the action (e.g., "SUBMIT", "VERIFY", "VIEW").
    /// @param relatedHash The keccak256 hash of the associated data or report (e.g., metadata or report hash).
    /// @param timestamp The block timestamp when the action occurred.
    event ActivityLogged(
        address indexed actor,
        string action,
        bytes32 indexed relatedHash,
        uint256 timestamp
    );

    // ================================================================================
    //                                EXTERNAL FUNCTIONS
    // ================================================================================

    /// @notice Logs a specific action performed by a user within the system.
    /// @dev Should be called by other contracts to track activities for audit purposes.
    /// @param actor The address initiating the action.
    /// @param action A string describing the action taken (must be consistent with frontend/backend).
    /// @param relatedHash The reference hash related to the action (e.g., metadataHash, reportHash).
    function logActivity(
        address actor,
        string calldata action,
        bytes32 relatedHash
    ) external;
}
