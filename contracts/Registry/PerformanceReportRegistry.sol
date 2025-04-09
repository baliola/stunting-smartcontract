// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IRBAC} from "../Interface/IRBAC.sol";
import {ITransparency} from "../Interface/ITransparency.sol";
import {IPeformanceReport} from "../Interface/IPerformanceReport.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title PerformanceReportRegistry
/// @author @anggadanarp
/// @notice Stores, tracks, and verifies performance reports from field officers and evaluators.
/// @dev Uses RBAC for role validation and emits logs to a connected TransparencyRegistry.
abstract contract PerformanceReportRegistry is IPeformanceReport, IRBAC, ITransparency {
    using ECDSA for bytes32;

    // ================================================================================
    //                                    CONSTANTS
    // ================================================================================
    bytes32 public constant REPORT_SUBMITTER_ROLE =
        keccak256("REPORT_SUBMITTER_ROLE");
    bytes32 public constant EVALUATOR_ROLE = keccak256("EVALUATOR_ROLE");

    // ================================================================================
    //                                    STORAGE
    // ================================================================================
    mapping(bytes32 => Report) private _reports;
    mapping(bytes32 => bool) private _isSubmitted;

    ITransparency public transparency;
    IRBAC public rbac;

    // ================================================================================
    //                                  CONSTRUCTOR
    // ================================================================================
    /// @param transparencyRegistry Address of the TransparencyRegistry contract.
    constructor(address transparencyRegistry, address rbcaRegistry) {
        transparency = ITransparency(transparencyRegistry);
        rbac = IRBAC(rbcaRegistry);
    }

    // ================================================================================
    //                               INTERNAL FUNCTIONS
    // ================================================================================
    /// @notice Submit a report hash with a valid signature from the submitter.
    /// @param reportHash The keccak256 hash of the performance report.
    /// @param signature The submitter's signature over the reportHash.
    function _submitReport(
        bytes32 reportHash,
        bytes calldata signature
    ) internal {
        require(!_isSubmitted[reportHash], "Report already submitted");

        address signer = _recoverSigner(reportHash, signature);

        if (!rbac.checkAccessLog(signer, REPORT_SUBMITTER_ROLE))
            revert Unauthorized(signer);
        if (signer != msg.sender) revert InvalidSignature(signer, msg.sender);

        _reports[reportHash] = Report({
            submitter: signer,
            submittedAt: block.timestamp,
            signature: signature,
            status: ReportStatus.Pending,
            evaluatedBy: address(0),
            evaluatedAt: 0
        });

        _isSubmitted[reportHash] = true;

        emit ReportSubmitted(reportHash, signer, block.timestamp);
        transparency.logActivity(msg.sender, "SUBMIT_REPORT", reportHash);
    }

    /// @notice Verifies (approves/rejects) a submitted report.
    /// @param reportHash The hash of the report to verify.
    /// @param approved True to approve, false to reject.
    function _verifyReport(bytes32 reportHash, bool approved) internal {
        require(_isSubmitted[reportHash], "Report not found");

        if (!rbac.checkAccessLog(msg.sender, EVALUATOR_ROLE))
            revert Unauthorized(msg.sender);

        Report storage report = _reports[reportHash];
        require(report.status == ReportStatus.Pending, "Already verified");

        report.status = approved
            ? ReportStatus.Approved
            : ReportStatus.Rejected;
        report.evaluatedBy = msg.sender;
        report.evaluatedAt = block.timestamp;

        emit ReportVerified(reportHash, msg.sender, approved, block.timestamp);
        transparency.logActivity(
            msg.sender,
            approved ? "APPROVE_REPORT" : "REJECT_REPORT",
            reportHash
        );
    }

    // ================================================================================
    //                                   INTERNAL VIEW
    // ================================================================================
    /// @notice Returns report data by its hash.
    function _getReport(
        bytes32 reportHash
    ) internal view returns (Report memory) {
        return _reports[reportHash];
    }

    /// @notice Checks whether a report has been submitted.
    function _getIsSubmitted(bytes32 reportHash) internal view returns (bool) {
        return _isSubmitted[reportHash];
    }

    // ================================================================================
    //                                 PRIVATE HELPERS
    // ================================================================================
    function _recoverSigner(
        bytes32 hash,
        bytes memory signature
    ) private pure returns (address) {
        return MessageHashUtils.toEthSignedMessageHash(hash).recover(signature);
    }
}
