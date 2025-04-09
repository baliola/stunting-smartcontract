// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ITransparency} from "../Interface/ITransparency.sol";

/// @title TransparencyRegistry
/// @author @anggadanarp
/// @notice Emits on-chain logs of important actions performed within the E-PENTING ecosystem.
/// @dev Stateless and gas-efficient registry for audit trails. All logs are emitted as events.
contract TransparencyRegistry is ITransparency {
    // ================================================================================
    //                               LOGGING FUNCTION
    // ================================================================================
    /// @notice Log an activity to the blockchain for auditing and traceability.
    /// @param actor Address that performed the action.
    /// @param action Description of the action (free-form string).
    /// @param relatedHash The metadata hash or reference being acted upon.
    function logActivity(
        address actor,
        string calldata action,
        bytes32 relatedHash
    ) external {
        emit ActivityLogged(actor, action, relatedHash, block.timestamp);
    }
}
