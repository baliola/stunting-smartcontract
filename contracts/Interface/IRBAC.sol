// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title IRBAC - Interface for Role-Based Access Control registry
/// @author @anggadanarp
/// @notice Defines standard RBAC functions and events for modular access control in integrated contracts.
/// @dev This interface is implemented by RBACRegistry. Used for access validation, role assignment, and suspension.
interface IRBAC {
    // ================================================================================
    //                                     ERRORS
    // ================================================================================

    /// @notice Thrown when attempting to register a role that already exists.
    /// @param role The role identifier (keccak256 hash) that caused the conflict.
    error RoleAlreadyRegistered(bytes32 role);

    /// @notice Thrown when attempting to assign a role that hasn't been registered.
    /// @param role The role identifier that is not yet registered.
    error RoleNotRegistered(bytes32 role);

    // ================================================================================
    //                                     EVENTS
    // ================================================================================

    /// @notice Emitted when a new role is registered in the system.
    /// @param role The role identifier (e.g., keccak256("DATA_ENTRY_ROLE")).
    /// @param adminRole The role that will manage this role (assign/revoke).
    event RoleRegistered(bytes32 indexed role, address indexed adminRole);

    /// @notice Emitted when a role is assigned to a user.
    /// @param role The role assigned.
    /// @param user The user receiving the role.
    event RoleAssigned(bytes32 indexed role, address indexed user);

    /// @notice Emitted when a role is revoked from a user.
    /// @param role The role revoked.
    /// @param user The user losing the role.
    event RoleRevoked(bytes32 indexed role, address indexed user);

    /// @notice Emitted when access is checked (typically with logging).
    /// @param user The address whose access is checked.
    /// @param role The role being checked.
    /// @param granted True if access is granted, false otherwise.
    event AccessChecked(
        address indexed user,
        bytes32 indexed role,
        bool granted
    );

    // ================================================================================
    //                             EXTERNAL ROLE FUNCTIONS
    // ================================================================================

    /// @notice Registers a new role and assigns an admin role to manage it.
    /// @param role The identifier of the new role to register.
    function registerRole(bytes32 role) external;

    /// @notice Assigns a role to a specific user address.
    /// @param user The address receiving the role.
    /// @param role The role to assign.
    function assignRole(address user, bytes32 role) external;

    /// @notice Revokes a specific role from a user.
    /// @param user The address losing the role.
    /// @param role The role being revoked.
    function revokeRoleFrom(address user, bytes32 role) external;

    /// @notice Checks access for a user and emits an `AccessChecked` event.
    /// @param user The address being checked.
    /// @param role The role required.
    /// @return granted True if the user has the role and is not suspended.
    function checkAccessLog(
        address user,
        bytes32 role
    ) external returns (bool granted);

    // ================================================================================
    //                             EXTERNAL SUSPENSION FUNCTIONS
    // ================================================================================
    /// @notice Returns whether a role is registered in the system.
    /// @param role The role identifier to check.
    /// @return True if the role is registered, false otherwise.
    function getIsRoleRegistered(bytes32 role) external view returns (bool);
}
