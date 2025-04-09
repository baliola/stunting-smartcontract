// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IRBAC} from "../Interface/IRBAC.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title RBACRegistry
/// @author @anggadanarp
/// @notice Abstract contract implements a modular Role-Based Access Control (RBAC) system
///         with dynamic role registration, access validation, and user suspension.
/// @dev Built on top of OpenZeppelin's AccessControl (v5) for standardized role logic.
abstract contract RBACRegistry is IRBAC, AccessControl {
    // ================================================================================
    //                                    STORAGE
    // ================================================================================
    /// @notice Default administrator role identifier.
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    /// @dev Tracks suspension status of users.
    mapping(address => bool) private _isSuspended;

    /// @dev Tracks which roles have been registered for use in the system.
    mapping(bytes32 => bool) private _registeredRoles;

    // ================================================================================
    //                              ROLE MANAGEMENT
    // ================================================================================
    /// @notice Registers a new role with a specified admin role.
    /// @dev The adminRole will control future assignments and revocations of this role.
    /// @param role Role identifier (usually a keccak256 hash of a string).
    /// @param adminRole Role that will have admin permissions over the new role.
    function _registerRole(
        bytes32 role,
        bytes32 adminRole
    ) internal onlyRole(ADMIN_ROLE) {
        if (_registeredRoles[role]) revert RoleAlreadyRegistered(role);
        _registeredRoles[role] = true;
        _setRoleAdmin(role, adminRole);
        emit RoleRegistered(role, msg.sender);
    }

    /// @notice Assigns a role to a user.
    /// @param user Address to be granted the role.
    /// @param role Role identifier to be granted.
    function _assignRole(
        address user,
        bytes32 role
    ) internal onlyRole(getRoleAdmin(role)) {
        if (!_registeredRoles[role]) revert RoleNotRegistered(role);
        _grantRole(role, user);
        emit RoleAssigned(role, user);
    }

    /// @notice Revokes a role from a user.
    /// @param user Address from which the role will be revoked.
    /// @param role Role identifier to be revoked.
    function _revokeRoleFrom(
        address user,
        bytes32 role
    ) internal onlyRole(getRoleAdmin(role)) {
        _revokeRole(role, user);
        emit RoleRevoked(role, user);
    }

    // ================================================================================
    //                                     ACCESS CONTROL
    // ================================================================================
    /// @notice Checks whether a user has a role and is not suspended.
    /// @param user Address to check.
    /// @param role Role identifier to verify.
    /// @return True if the user has the role and is active.
    function _checkAccess(
        address user,
        bytes32 role
    ) internal view returns (bool) {
        return hasRole(role, user) && !_isSuspended[user];
    }

    /// @notice Performs access check and emits a log for auditing.
    /// @param user Address to check.
    /// @param role Role identifier to verify.
    /// @return granted True if the user has the role and is active.
    function _checkAccessLog(
        address user,
        bytes32 role
    ) internal returns (bool granted) {
        granted = _checkAccess(user, role);
        emit AccessChecked(user, role, granted);
    }

    // ================================================================================
    //                                 SUSPENSION MANAGEMENT
    // ================================================================================
    /// @notice Suspends a user, preventing them from accessing roles.
    /// @param user Address to suspend.
    function _suspendUser(address user) internal onlyRole(ADMIN_ROLE) {
        if (_isSuspended[user]) revert AlreadySuspended(user);
        _isSuspended[user] = true;
        emit UserSuspended(user);
    }

    /// @notice Re-enables a suspended user.
    /// @param user Address to unsuspend.
    function _unsuspendUser(address user) internal onlyRole(ADMIN_ROLE) {
        if (!_isSuspended[user]) revert UserNotSuspended(user);
        _isSuspended[user] = false;
        emit UserUnsuspended(user);
    }

    // ================================================================================
    //                                 INTERNAL VIEWS
    // ================================================================================
    /// @notice Internal getter for suspension status (for use in child contracts).
    /// @param user Address to check.
    /// @return True if the user is suspended.
    function _getIsSuspended(address user) internal view returns (bool) {
        return _isSuspended[user];
    }

    /// @notice Internal getter to check if a role has been registered.
    /// @param role Role identifier to check.
    /// @return True if the role is registered.
    function _getIsRoleRegistered(bytes32 role) internal view returns (bool) {
        return _registeredRoles[role];
    }
}
