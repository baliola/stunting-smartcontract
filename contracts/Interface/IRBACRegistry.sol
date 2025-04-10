// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title IRBACRegistry - Interface for Role-Based Access Control registry using string-to-hash mapping architecture
/// @author @anggadanarp
/// @notice Standardized interface for managing dynamic roles, access validation, and permission control.
/// @dev All roles are stored as keccak256 hashes of their string identifiers for gas efficiency.
interface IRBACRegistry {
    // ================================================================================
    //                                     ERRORS
    // ================================================================================

    /// @notice Thrown when assigning ADMIN_ROLE fails.
    error AssignRoleAdminFailed(address user);

    /// @notice Thrown when revoking ADMIN_ROLE fails.
    error RevokeRoleAdminFailed(address user);

    /// @notice Thrown when trying to register a role that already exists.
    error RoleAlreadyRegistered(bytes32 role);

    /// @notice Thrown when trying to assign or revoke a role that has not been registered.
    error RoleNotRegistered(bytes32 role);

    /// @notice Thrown when assigning a role to a user fails.
    error AssignRoleFailed(bytes32 role, address user);

    /// @notice Thrown when revoking a role from a user fails.
    error RevokeRoleFailed(bytes32 role, address user);

    // ================================================================================
    //                                     EVENTS
    // ================================================================================

    /// @notice Emitted when a new role is registered.
    /// @param roleName The human-readable role name (e.g., "DATA_ENTRY").
    /// @param roleHash The keccak256 hash of the role name.
    event RoleCreated(string roleName, bytes32 roleHash);

    /// @notice Emitted when a role is assigned to a user.
    /// @param account The address receiving the role.
    /// @param roleName The string name of the role.
    event RoleAssigned(address indexed account, string roleName);

    /// @notice Emitted when a role is revoked from a user.
    /// @param account The address losing the role.
    /// @param roleName The string name of the role.
    event RoleRevoked(address indexed account, string roleName);

    /// @notice Emitted when an account is granted admin rights.
    /// @param account The address promoted to admin.
    event AdminAdded(address indexed account);

    /// @notice Emitted when an account is removed from admin rights.
    /// @param account The address removed from admin.
    event AdminRemoved(address indexed account);

    // ================================================================================
    //                             EXTERNAL ADMIN FUNCTIONS
    // ================================================================================

    /// @notice Grants ADMIN_ROLE to an account.
    /// @param account The address to be added as admin.
    function addAdmin(address account) external;

    /// @notice Revokes ADMIN_ROLE from an account.
    /// @param account The address to be removed from admin.
    function removeAdmin(address account) external;

    // ================================================================================
    //                             EXTERNAL ROLE FUNCTIONS
    // ================================================================================

    /// @notice Registers a new role by string name.
    /// @param roleName The human-readable role name to be registered.
    function createRole(string calldata roleName) external;

    /// @notice Assigns a registered role to an address.
    /// @param account The address to assign the role to.
    /// @param role The human-readable role name.
    function assignRole(address account, string calldata role) external;

    /// @notice Revokes a registered role from an address.
    /// @param account The address to remove the role from.
    /// @param role The human-readable role name.
    function revokeRole(address account, string calldata role) external;

    // ================================================================================
    //                            EXTERNAL VIEW FUNCTIONS
    // ================================================================================

    /// @notice Checks whether a user has a role (permission) assigned.
    /// @param _account The address to be checked.
    /// @param _permission The human-readable role name to check.
    /// @return True if the account has the permission.
    function hasPermission(address _account, string calldata _permission) external view returns (bool);
}
