// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @notice Append-only anchor for NyayVault audit-ledger entry hashes.
/// Only a hash + minimal metadata is stored on-chain; full audit payloads
/// stay in the application's Postgres audit_ledger table.
contract AuditAnchor {
    struct Anchor {
        bytes32 entryHash;
        uint256 timestamp;
        address anchoredBy;
    }

    mapping(uint256 => Anchor) public anchors;

    event HashAnchored(
        uint256 indexed ledgerEntryId,
        string entityType,
        string entityId,
        bytes32 entryHash,
        uint256 timestamp
    );

    function anchorHash(
        uint256 ledgerEntryId,
        string calldata entityType,
        string calldata entityId,
        bytes32 entryHash
    ) external {
        require(anchors[ledgerEntryId].timestamp == 0, "Already anchored");

        anchors[ledgerEntryId] = Anchor({
            entryHash: entryHash,
            timestamp: block.timestamp,
            anchoredBy: msg.sender
        });

        emit HashAnchored(ledgerEntryId, entityType, entityId, entryHash, block.timestamp);
    }

    function getAnchor(uint256 ledgerEntryId)
        external
        view
        returns (bytes32 entryHash, uint256 timestamp, address anchoredBy)
    {
        Anchor storage entry = anchors[ledgerEntryId];
        return (entry.entryHash, entry.timestamp, entry.anchoredBy);
    }
}
