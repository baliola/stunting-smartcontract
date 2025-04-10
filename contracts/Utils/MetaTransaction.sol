// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IMetaTransaction} from "../Interface/IMetaTransaction.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title MetaTransaction - EIP-712-Based Meta-Transaction Forwarder Contract with Relayer Whitelisting
/// @author @anggadanarp
/// @notice Enables gasless transaction execution by verifying signed function calls on behalf of users.
/// @dev Provides per-user nonce tracking, signature verification, and relayer control via owner.
abstract contract MetaTransaction is EIP712, IMetaTransaction {
    // ================================================================================
    //                                    STORAGE
    // ================================================================================

    /// @notice The contract owner address.
    address private _OWNER;

    /// @notice Tracks per-user nonce to protect against replay attacks.
    mapping(address => uint256) private _nonces;

    /// @notice Stores addresses authorized to relay meta-transactions.
    mapping(address => bool) private _relayer;

    // ================================================================================
    //                                  CONSTRUCTOR
    // ================================================================================

    /// @notice Initializes the contract with the specified owner address.
    /// @param _owner The address designated as the contract owner.
    constructor(address _owner) {
        _OWNER = _owner;
    }

    // ================================================================================
    //                                    MODIFIERS
    // ================================================================================

    /// @notice Restricts function to only be callable by the owner.
    modifier onlyOwner() {
        if (msg.sender != _OWNER) revert Unauthorized(msg.sender);
        _;
    }

    /// @notice Restricts function to be called only by whitelisted relayers.
    modifier onlyRelayer() {
        if (!_relayer[msg.sender]) revert Unauthorized(msg.sender);
        _;
    }

    // ================================================================================
    //                             INTERNAL META TX LOGIC
    // ================================================================================

    /// @notice Executes a verified meta-transaction on behalf of the original signer.
    /// @param _from The address who signed the request.
    /// @param _nonce The expected nonce associated with `_from`.
    /// @param _functionCall The encoded function call to be executed.
    /// @param _signature The user's signature over the typed meta-transaction.
    function _executeMetaTransaction(
        address _from,
        uint256 _nonce,
        bytes calldata _functionCall,
        bytes calldata _signature
    ) internal {
        uint256 currentNonce = _nonces[_from];

        if (_nonce != currentNonce) revert InvalidNonce();
        if (!_verify(_from, _nonce, _functionCall, _signature)) revert InvalidSignature();

        _nonces[_from] = currentNonce + 1;

        (bool success, bytes memory returnData) = address(this).call(
            abi.encodePacked(_functionCall, _from)
        );

        if (!success) {
            string memory errorMessage = _extractRevertMsg(returnData);
            revert MetaTransactionFailed(errorMessage);
        }

        emit MetaTransactionExecuted(_from, _functionCall);
    }

    /// @notice Adds a new relayer address, callable only by owner.
    /// @param _newRelayer The address to whitelist as a trusted relayer.
    function _addRelayer(address _newRelayer) internal onlyOwner {
        _relayer[_newRelayer] = true;
    }

    // ================================================================================
    //                            PRIVATE VERIFICATION LOGIC
    // ================================================================================

    /// @notice Verifies the authenticity of the meta-transaction using EIP-712 and ECDSA.
    /// @dev Internal hashing and signature recovery.
    /// @param _from The expected signer of the request.
    /// @param _nonce The expected nonce for the signer.
    /// @param _functionCall The calldata that was signed.
    /// @param _signature The signature over the hashed typed data.
    /// @return True if signature is valid, false otherwise.
    function _verify(
        address _from,
        uint256 _nonce,
        bytes calldata _functionCall,
        bytes calldata _signature
    ) private view returns (bool) {
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    keccak256(
                        "MetaTransaction(address from,uint256 nonce,bytes functionCall)"
                    ),
                    _from,
                    _nonce,
                    keccak256(_functionCall)
                )
            )
        );

        address recoveredSigner = ECDSA.recover(digest, _signature);
        return recoveredSigner == _from;
    }

    /// @notice Decodes revert reason from a failed low-level call.
    /// @param _returnData The returned data from the failed call.
    /// @return The extracted revert message string.
    function _extractRevertMsg(
        bytes memory _returnData
    ) private pure returns (string memory) {
        if (_returnData.length < 68) return "Transaction reverted";

        assembly {
            _returnData := add(_returnData, 0x04)
        }

        return abi.decode(_returnData, (string));
    }
}
