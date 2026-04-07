// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title SecureDataManagement
 * @notice On-chain registry for encrypted file metadata, access control,
 *         and immutable audit logging with anomaly tracking.
 */
contract SecureDataManagement {
    // ─── Enums ────────────────────────────────────────────────────────────────

    enum Permission { NONE, READ, WRITE, FULL }

    // ─── Structs ──────────────────────────────────────────────────────────────

    struct FileRecord {
        string  fileId;
        string  fileHash;
        string  fileName;
        uint256 fileSize;
        address owner;
        uint256 timestamp;
        bool    isActive;
    }

    struct ChunkInfo {
        string  chunkId;
        string  chunkHash;
        uint256 chunkSize;
        string  chunkLocation;
    }

    struct AccessLog {
        address user;
        string  fileId;
        string  action;
        string  ipAddress;
        uint256 timestamp;
        bool    success;
        bool    anomalyFlag;
    }

    // ─── State ────────────────────────────────────────────────────────────────

    mapping(string => FileRecord)                      private files;
    mapping(string => ChunkInfo[])                     private fileChunks;
    mapping(string => mapping(address => Permission))  private permissions;

    AccessLog[]  private accessLogs;
    uint256[]    private anomalyLogIndices;

    // ─── Events ───────────────────────────────────────────────────────────────

    event FileRegistered(
        string  indexed fileId,
        address indexed owner,
        string  fileHash,
        uint256 fileSize,
        uint256 timestamp
    );

    event AccessGranted(
        string  indexed fileId,
        address indexed user,
        Permission permission,
        uint256 timestamp
    );

    event AccessRevoked(
        string  indexed fileId,
        address indexed user,
        uint256 timestamp
    );

    event AccessLogged(
        string  indexed fileId,
        address indexed user,
        string  action,
        bool    success,
        bool    anomalyFlag,
        uint256 timestamp
    );

    event AnomalyDetected(
        string  indexed fileId,
        address indexed user,
        string  action,
        uint256 indexed logIndex,
        uint256 timestamp
    );

    // ─── Modifiers ────────────────────────────────────────────────────────────

    modifier onlyOwner(string memory fileId) {
        require(
            files[fileId].owner == msg.sender,
            "SecureDataManagement: caller is not the file owner"
        );
        _;
    }

    modifier fileExists(string memory fileId) {
        require(
            files[fileId].isActive,
            "SecureDataManagement: file does not exist or is inactive"
        );
        _;
    }

    // ─── Write Functions ──────────────────────────────────────────────────────

    /**
     * @notice Register a new file on-chain. msg.sender becomes the owner.
     * @param fileId        Unique file identifier (UUID or hash)
     * @param fileHash      SHA-256 of the full plaintext file
     * @param fileName      Original file name
     * @param fileSize      File size in bytes
     * @param chunkIds      MinIO object keys for each chunk
     * @param chunkHashes   SHA-256 hash of each chunk (pre-encryption)
     * @param chunkSizes    Size of each chunk in bytes
     * @param chunkLocations MinIO URIs for each chunk
     */
    function registerFile(
        string   memory fileId,
        string   memory fileHash,
        string   memory fileName,
        uint256         fileSize,
        string[] memory chunkIds,
        string[] memory chunkHashes,
        uint256[] memory chunkSizes,
        string[] memory chunkLocations
    ) external {
        require(bytes(fileId).length > 0,   "SecureDataManagement: fileId cannot be empty");
        require(!files[fileId].isActive,    "SecureDataManagement: file already registered");
        require(
            chunkIds.length == chunkHashes.length &&
            chunkIds.length == chunkSizes.length  &&
            chunkIds.length == chunkLocations.length,
            "SecureDataManagement: chunk array length mismatch"
        );

        files[fileId] = FileRecord({
            fileId:    fileId,
            fileHash:  fileHash,
            fileName:  fileName,
            fileSize:  fileSize,
            owner:     msg.sender,
            timestamp: block.timestamp,
            isActive:  true
        });

        for (uint256 i = 0; i < chunkIds.length; i++) {
            fileChunks[fileId].push(ChunkInfo({
                chunkId:       chunkIds[i],
                chunkHash:     chunkHashes[i],
                chunkSize:     chunkSizes[i],
                chunkLocation: chunkLocations[i]
            }));
        }

        // Owner implicitly has FULL permission
        permissions[fileId][msg.sender] = Permission.FULL;

        emit FileRegistered(fileId, msg.sender, fileHash, fileSize, block.timestamp);
    }

    /**
     * @notice Grant access permission to a user for a file.
     */
    function grantAccess(
        string  memory fileId,
        address        user,
        Permission     permission
    ) external onlyOwner(fileId) fileExists(fileId) {
        require(user != address(0), "SecureDataManagement: zero address");
        permissions[fileId][user] = permission;
        emit AccessGranted(fileId, user, permission, block.timestamp);
    }

    /**
     * @notice Revoke all access from a user for a file.
     */
    function revokeAccess(
        string  memory fileId,
        address        user
    ) external onlyOwner(fileId) fileExists(fileId) {
        require(user != files[fileId].owner, "SecureDataManagement: cannot revoke owner access");
        permissions[fileId][user] = Permission.NONE;
        emit AccessRevoked(fileId, user, block.timestamp);
    }

    /**
     * @notice Log a file access event. Any caller can log their own access.
     */
    function logAccess(
        string memory fileId,
        string memory action,
        string memory ipAddress,
        bool          success,
        bool          anomalyFlag
    ) external {
        uint256 logIndex = accessLogs.length;

        accessLogs.push(AccessLog({
            user:        msg.sender,
            fileId:      fileId,
            action:      action,
            ipAddress:   ipAddress,
            timestamp:   block.timestamp,
            success:     success,
            anomalyFlag: anomalyFlag
        }));

        if (anomalyFlag) {
            anomalyLogIndices.push(logIndex);
            emit AnomalyDetected(fileId, msg.sender, action, logIndex, block.timestamp);
        }

        emit AccessLogged(fileId, msg.sender, action, success, anomalyFlag, block.timestamp);
    }

    // ─── Read Functions ───────────────────────────────────────────────────────

    /**
     * @notice Get all metadata fields for a file.
     */
    function getFileMetadata(string memory fileId)
        external
        view
        returns (
            string  memory retFileId,
            string  memory retFileHash,
            string  memory retFileName,
            uint256        retFileSize,
            address        retOwner,
            uint256        retTimestamp,
            bool           retIsActive
        )
    {
        FileRecord storage rec = files[fileId];
        return (
            rec.fileId,
            rec.fileHash,
            rec.fileName,
            rec.fileSize,
            rec.owner,
            rec.timestamp,
            rec.isActive
        );
    }

    /**
     * @notice Get the ChunkInfo array for a file.
     */
    function getFileChunks(string memory fileId)
        external
        view
        returns (ChunkInfo[] memory)
    {
        return fileChunks[fileId];
    }

    /**
     * @notice Check whether a user holds at least the required permission.
     *         File owners always have FULL access.
     */
    function checkPermission(
        string  memory fileId,
        address        user,
        Permission     required
    ) external view returns (bool) {
        if (files[fileId].owner == user) {
            return true;
        }
        Permission held = permissions[fileId][user];
        return uint8(held) >= uint8(required);
    }

    /**
     * @notice Paginated access logs filtered by fileId.
     * @param fileId   Filter by this file identifier
     * @param page     Zero-based page number
     * @param pageSize Number of entries per page
     */
    function getAccessLogs(
        string memory fileId,
        uint256 page,
        uint256 pageSize
    ) external view returns (AccessLog[] memory) {
        require(pageSize > 0 && pageSize <= 200, "SecureDataManagement: invalid pageSize");

        // First pass: count matching logs
        uint256 total = 0;
        for (uint256 i = 0; i < accessLogs.length; i++) {
            if (_strEq(accessLogs[i].fileId, fileId)) {
                total++;
            }
        }

        uint256 start = page * pageSize;
        if (start >= total) {
            return new AccessLog[](0);
        }

        uint256 end = start + pageSize;
        if (end > total) end = total;
        uint256 resultLen = end - start;

        AccessLog[] memory result = new AccessLog[](resultLen);
        uint256 count = 0;
        uint256 idx = 0;

        for (uint256 i = 0; i < accessLogs.length && idx < resultLen; i++) {
            if (_strEq(accessLogs[i].fileId, fileId)) {
                if (count >= start) {
                    result[idx] = accessLogs[i];
                    idx++;
                }
                count++;
            }
        }
        return result;
    }

    /**
     * @notice Paginated anomaly-flagged access logs.
     * @param page     Zero-based page number
     * @param pageSize Number of entries per page
     */
    function getAnomalyLogs(
        uint256 page,
        uint256 pageSize
    ) external view returns (AccessLog[] memory) {
        require(pageSize > 0 && pageSize <= 200, "SecureDataManagement: invalid pageSize");

        uint256 total = anomalyLogIndices.length;
        uint256 start = page * pageSize;

        if (start >= total) {
            return new AccessLog[](0);
        }

        uint256 end = start + pageSize;
        if (end > total) end = total;
        uint256 resultLen = end - start;

        AccessLog[] memory result = new AccessLog[](resultLen);
        for (uint256 i = 0; i < resultLen; i++) {
            result[i] = accessLogs[anomalyLogIndices[start + i]];
        }
        return result;
    }

    // ─── Internal Helpers ─────────────────────────────────────────────────────

    function _strEq(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }
}
