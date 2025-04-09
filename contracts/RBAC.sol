// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {RBACRegistry} from "./Registry/RBACRegistry.sol";
import {MetaTransaction} from "./Utils/MetaTransaction.sol";

contract RBAC is RBACRegistry {
    constructor(address initialAdmin) {
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(ADMIN_ROLE, initialAdmin);
        _registerRole(ADMIN_ROLE, ADMIN_ROLE);
    }

    function registerRole(bytes32 role, bytes32 adminRole) external {
        _registerRole(role, adminRole);
    }

    function assignRole(address user, bytes32 role) external {
        _assignRole(user, role);
    }

    function revokeRoleFrom(address user, bytes32 role) external {
        _revokeRoleFrom(user, role);
    }

    function checkAccessLog(
        address user,
        bytes32 role
    ) external returns (bool granted) {
        return _checkAccessLog(user, role);
    }

    function suspendUser(address user) external {
        _suspendUser(user);
    }

    function unsuspendUser(address user) external {
        _unsuspendUser(user);
    }

    function getIsSuspended(address user) external view returns (bool) {
        return _getIsSuspended(user);
    }

    function getIsRoleRegistered(bytes32 role) external view returns (bool) {
        return _getIsRoleRegistered(role);
    }
}
