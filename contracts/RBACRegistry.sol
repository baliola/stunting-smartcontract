// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IRBACRegistry} from "./Interface/IRBACRegistry.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title RBACRegistry - Role-Based Access Control Registry with string-to-hash abstraction on top of OpenZeppelin AccessControl (v5)
/// @author @anggadanarp
/// @notice Manages dynamic role registration, admin delegation, and permission-based access control.
/// @dev Role names are hashed using keccak256 and stored as bytes32 keys.
contract RBACRegistry is IRBACRegistry, AccessControl {
    // ================================================================================
    //                                     STORAGE
    // ================================================================================

    /// @notice Default administrator role (can manage other admins).
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    /// @dev Tracks which roles have been registered.
    mapping(bytes32 => bool) private _roleNames;

    // ================================================================================
    //                                  CONSTRUCTOR
    // ================================================================================

    /// @dev Initializes contract and assigns deployer as DEFAULT_ADMIN_ROLE.
    constructor() {
        require(
            _grantRole(DEFAULT_ADMIN_ROLE, msg.sender),
            "AccessControl: Assign role failed"
        );
    }

    // ================================================================================
    //                              ADMIN MANAGEMENT
    // ================================================================================

    /// @inheritdoc IRBACRegistry
    function addAdmin(address _account) external {
        _addAdmin(_account);
        emit AdminAdded(_account);
    }

    /// @inheritdoc IRBACRegistry
    function removeAdmin(address _account) external {
        _removeAdmin(_account);
        emit AdminRemoved(_account);
    }

    /// @notice Grants ADMIN_ROLE to an address internally.
    /// @param _account The address to be added as admin.
    function _addAdmin(
        address _account
    ) internal onlyRole(getRoleAdmin(DEFAULT_ADMIN_ROLE)) {
        if (!_grantRole(ADMIN_ROLE, _account)) {
            revert AssignRoleAdminFailed(_account);
        }
    }

    /// @notice Revokes ADMIN_ROLE from an address internally.
    /// @param _account The address to remove.
    function _removeAdmin(
        address _account
    ) internal onlyRole(getRoleAdmin(DEFAULT_ADMIN_ROLE)) {
        if (!_revokeRole(ADMIN_ROLE, _account)) {
            revert RevokeRoleAdminFailed(_account);
        }
    }

    // ================================================================================
    //                              ROLE MANAGEMENT
    // ================================================================================

    /// @inheritdoc IRBACRegistry
    function createRole(string calldata _roleName) external {
        bytes32 _hashRole = keccak256(abi.encodePacked(_roleName));
        _createRole(_hashRole);
        emit RoleCreated(_roleName, _hashRole);
    }

    /// @inheritdoc IRBACRegistry
    function assignRole(address _account, string calldata _role) external {
        bytes32 _hashRole = keccak256(abi.encodePacked(_role));
        _assignRole(_account, _hashRole);
        emit RoleAssigned(_account, _role);
    }

    /// @inheritdoc IRBACRegistry
    function revokeRole(address _account, string calldata _role) external {
        bytes32 _hashRole = keccak256(abi.encodePacked(_role));
        _revokeRole(_account, _hashRole);
        emit RoleRevoked(_account, _role);
    }

    /// @notice Registers a new role using hashed identifier.
    /// @param _roleName The hashed keccak256 value of the role name.
    function _createRole(bytes32 _roleName) internal {
        if (_roleNames[_roleName]) revert RoleAlreadyRegistered(_roleName);
        _roleNames[_roleName] = true;
    }

    /// @notice Grants a registered role to a user.
    function _assignRole(
        address _account,
        bytes32 _role
    ) internal onlyRole(getRoleAdmin(ADMIN_ROLE)) {
        if (!_roleNames[_role]) revert RoleNotRegistered(_role);
        if (!_grantRole(_role, _account)) {
            revert AssignRoleFailed(_role, _account);
        }
    }

    /// @notice Revokes a registered role from a user.
    function _revokeRole(
        address _account,
        bytes32 _role
    ) internal onlyRole(getRoleAdmin(ADMIN_ROLE)) {
        if (!_roleNames[_role]) revert RoleNotRegistered(_role);
        if (!_revokeRole(_role, _account)) {
            revert RevokeRoleFailed(_role, _account);
        }
    }

    // ================================================================================
    //                              PERMISSION CHECK
    // ================================================================================

    /// @inheritdoc IRBACRegistry
    function hasPermission(
        address _account,
        string calldata _permission
    ) external view returns (bool) {
        return
            _hasPermission(_account, keccak256(abi.encodePacked(_permission)));
    }

    /// @notice Checks if a user has a role based on hash.
    function _hasPermission(
        address _account,
        bytes32 _permission
    ) internal view returns (bool) {
        return _roleNames[_permission] && hasRole(_permission, _account);
    }
}
