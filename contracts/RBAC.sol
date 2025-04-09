// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {RBACRegistry} from "./Registry/RBACRegistry.sol";
import {MetaTransaction, EIP712} from "./Utils/MetaTransaction.sol";

/// @title RBAC - Main Role-Based Access Control contract with MetaTransaction support
/// @author @anggadanarp
/// @notice Centralized contract for managing dynamic roles, access verification, and gasless interactions.
/// @dev Inherits both `RBACRegistry` (role logic) and `MetaTransaction` (meta-tx execution).
contract RBAC is RBACRegistry, MetaTransaction {
    // ================================================================================
    //                                CONSTRUCTOR
    // ================================================================================

    /// @notice Deploys the RBAC contract with initial admin and EIP712 configuration.
    /// @param initialAdmin The first wallet to be granted the ADMIN_ROLE.
    /// @param _name The EIP712 domain name.
    /// @param _version The EIP712 domain version.
    constructor(
        address initialAdmin,
        string memory _name,
        string memory _version
    ) EIP712(_name, _version) MetaTransaction(msg.sender) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _registerRole(ADMIN_ROLE, ADMIN_ROLE);
        _grantRole(ADMIN_ROLE, initialAdmin);
    }

    // ================================================================================
    //                                ROLE MANAGEMENT
    // ================================================================================

    /// @notice Registers a new role and its admin role.
    /// @param role The role identifier to register.
    /// @param adminRole The admin role that will manage this role.
    function registerRole(bytes32 role, bytes32 adminRole) external {
        _registerRole(role, adminRole);
    }

    /// @notice Assigns a registered role to a specific user.
    /// @param user The address to be granted the role.
    /// @param role The role to assign.
    function assignRole(address user, bytes32 role) external {
        _assignRole(user, role);
    }

    /// @notice Revokes a role from a user.
    /// @param user The address from which the role will be revoked.
    /// @param role The role to be removed.
    function revokeRoleFrom(address user, bytes32 role) external {
        _revokeRoleFrom(user, role);
    }

    // ================================================================================
    //                              ACCESS & AUDIT CHECK
    // ================================================================================

    /// @notice Checks whether a user has a specific role and emits an access log.
    /// @param user The address to check.
    /// @param role The role identifier to verify.
    /// @return granted True if the user has the role and is not suspended.
    function checkAccessLog(
        address user,
        bytes32 role
    ) external returns (bool granted) {
        return _checkAccessLog(user, role);
    }

    // ================================================================================
    //                            SUSPENSION MANAGEMENT
    // ================================================================================

    /// @notice Suspends a user from using any assigned role.
    /// @param user The address to suspend.
    function suspendUser(address user) external {
        _suspendUser(user);
    }

    /// @notice Unsuspends a previously suspended user.
    /// @param user The address to unsuspend.
    function unsuspendUser(address user) external {
        _unsuspendUser(user);
    }

    /// @notice Returns whether a user is currently suspended.
    /// @param user The address to check.
    /// @return True if the user is suspended, false otherwise.
    function getIsSuspended(address user) external view returns (bool) {
        return _getIsSuspended(user);
    }

    // ================================================================================
    //                              ROLE REGISTRY VIEW
    // ================================================================================

    /// @notice Checks whether a role has been registered.
    /// @param role The role identifier to check.
    /// @return True if the role is registered, false otherwise.
    function getIsRoleRegistered(bytes32 role) external view returns (bool) {
        return _getIsRoleRegistered(role);
    }

    // ================================================================================
    //                           META-TRANSACTION EXECUTION
    // ================================================================================

    /// @notice Executes a meta-transaction submitted by a relayer on behalf of a user.
    /// @param from The address of the original signer.
    /// @param nonce The nonce tied to the user for replay protection.
    /// @param functionCall The encoded function call to execute.
    /// @param signature The EIP712 signature from the user.
    function executeMetaTransaction(
        address from,
        uint256 nonce,
        bytes calldata functionCall,
        bytes calldata signature
    ) external {
        _executeMetaTransaction(from, nonce, functionCall, signature);
    }
}
