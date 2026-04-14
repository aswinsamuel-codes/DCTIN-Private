// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title DCTIN - Decentralized Cyber Threat Intelligence Network
 * @notice Smart contract for storing immutable cyber threat intelligence on blockchain
 * @dev Uses role-based access control and prevents duplicate threat submissions
 * 
 * Security Features:
 * - Role-based access control (Admin, Reporter roles)
 * - Duplicate hash prevention via mapping
 * - Events for full audit trail
 * - Gas-optimized storage and operations
 */
contract DCTIN is AccessControl {

    // ============ Roles ============
    bytes32 public constant REPORTER_ROLE = keccak256("REPORTER_ROLE");

    // ============ Enums ============
    enum ThreatType {
        MALWARE,           // 0: Malware hash (MD5, SHA256, etc.)
        PHISHING_URL,      // 1: Phishing website URL
        MALICIOUS_IP,      // 2: Malicious IP address
        C2_SERVER,         // 3: Command & Control server
        BOTNET_NODE,       // 4: Botnet participant
        RANSOMWARE,        // 5: Ransomware signature
        EXPLOIT_PAYLOAD,   // 6: Exploit code/payload
        SUSPICIOUS_DOMAIN  // 7: Suspicious domain
    }

    enum ThreatSeverity {
        LOW,      // 0: Low severity
        MEDIUM,   // 1: Medium severity
        HIGH,     // 2: High severity
        CRITICAL  // 3: Critical severity
    }

    // ============ Structs ============
    /**
     * @notice Stores all threat report data
     * @dev MAXIMUM gas optimization - entire struct fits in TWO storage slots
     * Slot 1: threatHash (32) = 32 bytes
     * Slot 2: reporter (20) + timestamp (8) + threatType (1) + severity (1) + padding (2) = 32 bytes
     */
    struct ThreatReport {
        bytes32 threatHash;        // 32 bytes - Fixed size, no dynamic allocation
        address reporter;          // 20 bytes
        uint64 timestamp;          // 8 bytes
        ThreatType threatType;     // 1 byte
        ThreatSeverity severity;   // 1 byte
                                   // 2 bytes padding
    }

    /**
     * @notice Input struct for batch threat reporting
     * @dev Used as calldata in reportThreatBatch to avoid stack-too-deep
     */
    struct ThreatInput {
        bytes32 threatHash;
        uint256 threatType;
        uint256 severity;
    }

    // ============ State Variables ============
    
    /// @notice Array of all threat reports for iteration
    ThreatReport[] private _threatReports;
    
    /// @notice Mapping from threat hash to report index (0 = not exists, index+1 = actual index)
    /// @dev Uses 1-based indexing to distinguish between "not found" (0) and index 0
    /// @dev O(1) lookup for duplicate prevention
    mapping(bytes32 => uint256) private _hashToIndex;
    
    /// @notice Total number of unique threats reported
    /// @dev Derived from array length to save storage writes
    function totalThreats() external view returns (uint256) {
        return _threatReports.length;
    }

    // ============ Rate Limiting ============
    
    /// @notice Maximum reports per reporter per block (prevents spam)
    uint256 public constant MAX_REPORTS_PER_BLOCK = 10;
    
    /// @notice Maximum threats allowed in a single batch submission
    uint256 public constant MAX_BATCH_SIZE = 50;
    
    /// @notice Tracks reporter submission count per block
    /// @dev Mapping: reporter => blockNumber => count
    mapping(address => mapping(uint256 => uint256)) private _reportsPerBlock;
    
    /// @notice Emitted when reporter exceeds rate limit
    event RateLimitExceeded(address indexed reporter, uint256 blockNumber, uint256 attemptCount);

    // ============ Events ============
    /**
     * @notice Emitted when a new threat is reported
     * @param threatHash The unique identifier of the threat (indexed for filtering)
     * @param threatType Category of the threat (indexed for filtering)
     * @param reporter Address that submitted the report (indexed for filtering)
     * @param timestamp Block timestamp of the report
     * @param reportIndex Index in the _threatReports array
     * @param severity Severity level of the threat
     */
    event ThreatReported(
        bytes32 indexed threatHash,
        ThreatType indexed threatType,
        address indexed reporter,
        uint64 timestamp,
        uint256 reportIndex,
        ThreatSeverity severity
    );

    /**
     * @notice Emitted when a new reporter is granted role
     * @param reporter Address granted reporter role
     * @param granter Address that granted the role
     */
    event ReporterAdded(address indexed reporter, address indexed granter);

    /**
     * @notice Emitted when a reporter role is revoked
     * @param reporter Address that lost reporter role
     * @param revoker Address that revoked the role
     */
    event ReporterRemoved(address indexed reporter, address indexed revoker);

    // ============ Errors ============
    error DCTIN__ThreatAlreadyExists(bytes32 threatHash);
    error DCTIN__InvalidThreatHash();
    error DCTIN__InvalidThreatType();
    error DCTIN__InvalidSeverity();
    error DCTIN__NotAuthorizedReporter();
    error DCTIN__ThreatNotFound(bytes32 threatHash);
    error DCTIN__RateLimitExceeded(address reporter, uint256 blockNumber);
    error DCTIN__InvalidPaginationRange();
    error DCTIN__EmptyBatch();
    error DCTIN__BatchTooLarge(uint256 provided, uint256 maximum);

    // ============ Constructor ============
    /**
     * @notice Initializes the contract with deployer as admin
     * @dev Sets up DEFAULT_ADMIN_ROLE for the deployer
     */
    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        // Deployer also gets reporter role by default
        _grantRole(REPORTER_ROLE, msg.sender);
    }

    // ============ External Functions ============
    
    /**
     * @notice Submit a new cyber threat report
     * @dev Only addresses with REPORTER_ROLE can call this function
     * @dev Rate limited to MAX_REPORTS_PER_BLOCK per block per reporter
     * @param _threatHash The threat identifier as bytes32 (SHA256 truncated or full)
     * @param _threatTypeRaw Category of threat as uint256 (will be validated against ThreatType enum)
     * @param _severityRaw Severity level as uint256 (0=LOW, 1=MEDIUM, 2=HIGH, 3=CRITICAL)
     * 
     * Security:
     * - Rate limiting prevents spam attacks
     * - Zero hash validation prevents empty submissions
     * - Duplicate check ensures data integrity
     * - Access control enforces authorization
     */
    function reportThreat(
        bytes32 _threatHash,
        uint256 _threatTypeRaw,
        uint256 _severityRaw
    ) external onlyRole(REPORTER_ROLE) {
        // Input validation - check for zero hash (saves gas on invalid inputs)
        if (_threatHash == bytes32(0)) revert DCTIN__InvalidThreatHash();
        
        // Validate threat type enum range before casting
        if (_threatTypeRaw > uint256(ThreatType.SUSPICIOUS_DOMAIN)) {
            revert DCTIN__InvalidThreatType();
        }
        ThreatType _threatType = ThreatType(_threatTypeRaw);
        
        // Validate severity enum range before casting
        if (_severityRaw > uint256(ThreatSeverity.CRITICAL)) {
            revert DCTIN__InvalidSeverity();
        }
        ThreatSeverity _severity = ThreatSeverity(_severityRaw);
        
        // Rate limiting check - prevents spam attacks
        uint256 currentBlock = block.number;
        uint256 reportsThisBlock = _reportsPerBlock[msg.sender][currentBlock];
        if (reportsThisBlock >= MAX_REPORTS_PER_BLOCK) {
            emit RateLimitExceeded(msg.sender, currentBlock, reportsThisBlock + 1);
            revert DCTIN__RateLimitExceeded(msg.sender, currentBlock);
        }
        
        // Check for duplicates using mapping - O(1) lookup
        // This also implicitly prevents event re-emission for same hash
        if (_hashToIndex[_threatHash] != 0) {
            revert DCTIN__ThreatAlreadyExists(_threatHash);
        }

        // Create report - fits in single memory chunk, no dynamic allocation
        ThreatReport memory newReport = ThreatReport({
            threatHash: _threatHash,
            reporter: msg.sender,
            timestamp: uint64(block.timestamp),
            threatType: _threatType,
            severity: _severity
        });

        // Add to array and update mappings
        _threatReports.push(newReport);
        uint256 reportIndex = _threatReports.length; // 1-based index for mapping
        _hashToIndex[_threatHash] = reportIndex;
        
        // Increment rate limit counter
        _reportsPerBlock[msg.sender][currentBlock] = reportsThisBlock + 1;

        // Emit event for transparency and off-chain indexing
        // Event emission happens AFTER all state changes (checks-effects-interactions)
        emit ThreatReported(
            _threatHash,
            _threatType,
            msg.sender,
            uint64(block.timestamp),
            reportIndex - 1, // Actual array index (0-based)
            _severity
        );
    }

    /**
     * @notice Submit multiple threat reports in a single transaction
     * @dev Gas-efficient bulk submission; rate limiting applies to the total batch size
     * @dev Only addresses with REPORTER_ROLE can call this function
     * @param _threats Array of ThreatInput structs (max MAX_BATCH_SIZE)
     * 
     * Security:
     * - Empty batch rejected to prevent wasted gas
     * - Batch size capped at MAX_BATCH_SIZE (50)
     * - Rate limiting checks entire batch against remaining quota
     * - Each item validated individually (hash, type, severity, duplicates)
     */
    function reportThreatBatch(
        ThreatInput[] calldata _threats
    ) external onlyRole(REPORTER_ROLE) {
        if (_threats.length == 0) revert DCTIN__EmptyBatch();
        if (_threats.length > MAX_BATCH_SIZE) {
            revert DCTIN__BatchTooLarge(_threats.length, MAX_BATCH_SIZE);
        }

        // Rate limiting: check if entire batch fits within block quota
        uint256 currentBlock = block.number;
        uint256 reportsThisBlock = _reportsPerBlock[msg.sender][currentBlock];
        if (reportsThisBlock + _threats.length > MAX_REPORTS_PER_BLOCK) {
            emit RateLimitExceeded(msg.sender, currentBlock, reportsThisBlock + _threats.length);
            revert DCTIN__RateLimitExceeded(msg.sender, currentBlock);
        }

        uint64 timestamp = uint64(block.timestamp);

        for (uint256 i = 0; i < _threats.length; i++) {
            ThreatInput calldata input = _threats[i];

            // Per-item validation
            if (input.threatHash == bytes32(0)) revert DCTIN__InvalidThreatHash();
            if (input.threatType > uint256(ThreatType.SUSPICIOUS_DOMAIN)) revert DCTIN__InvalidThreatType();
            if (input.severity > uint256(ThreatSeverity.CRITICAL)) revert DCTIN__InvalidSeverity();
            if (_hashToIndex[input.threatHash] != 0) revert DCTIN__ThreatAlreadyExists(input.threatHash);

            ThreatType threatType = ThreatType(input.threatType);
            ThreatSeverity severity = ThreatSeverity(input.severity);

            ThreatReport memory newReport = ThreatReport({
                threatHash: input.threatHash,
                reporter: msg.sender,
                timestamp: timestamp,
                threatType: threatType,
                severity: severity
            });

            _threatReports.push(newReport);
            uint256 reportIndex = _threatReports.length; // 1-based index for mapping
            _hashToIndex[input.threatHash] = reportIndex;

            emit ThreatReported(
                input.threatHash,
                threatType,
                msg.sender,
                timestamp,
                reportIndex - 1,
                severity
            );
        }

        // Update rate limit counter once for the entire batch
        _reportsPerBlock[msg.sender][currentBlock] = reportsThisBlock + _threats.length;
    }

    /**
     * @notice Grant reporter role to a new address
     * @dev Only DEFAULT_ADMIN_ROLE can grant roles
     * @param _reporter Address to grant reporter role to
     */
    function addReporter(address _reporter) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(REPORTER_ROLE, _reporter);
        emit ReporterAdded(_reporter, msg.sender);
    }

    /**
     * @notice Revoke reporter role from an address
     * @dev Only DEFAULT_ADMIN_ROLE can revoke roles
     * @param _reporter Address to revoke reporter role from
     */
    function removeReporter(address _reporter) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(REPORTER_ROLE, _reporter);
        emit ReporterRemoved(_reporter, msg.sender);
    }

    // ============ View Functions ============
    
    /**
     * @notice Get a threat report by its hash
     * @param _threatHash The hash to look up (bytes32)
     * @return ThreatReport struct with all threat data
     * 
     * Gas Consideration: View function, no gas cost for external calls
     * bytes32 parameter is more efficient than string (no length prefix)
     */
    function getThreatByHash(
        bytes32 _threatHash
    ) external view returns (ThreatReport memory) {
        uint256 index = _hashToIndex[_threatHash];
        if (index == 0) revert DCTIN__ThreatNotFound(_threatHash);
        
        return _threatReports[index - 1]; // Convert 1-based to 0-based
    }

    /**
     * @notice Check if a threat hash exists in the system
     * @param _threatHash The hash to check (bytes32)
     * @return bool True if threat exists, false otherwise
     * 
     * Gas: O(1) lookup via mapping, bytes32 comparison is single EVM word comparison
     */
    function threatExists(bytes32 _threatHash) external view returns (bool) {
        return _hashToIndex[_threatHash] != 0;
    }

    /**
     * @notice Get total number of threat reports
     * @return uint256 Total count of threats
     * @dev Returns array length - no separate storage variable needed
     */
    function getTotalThreats() external view returns (uint256) {
        return _threatReports.length;
    }

    /**
     * @notice Get a threat report by its array index
     * @param _index Index in the threats array
     * @return ThreatReport struct with all threat data
     */
    function getThreatByIndex(uint256 _index) external view returns (ThreatReport memory) {
        if (_index >= _threatReports.length) revert DCTIN__ThreatNotFound(bytes32(0));
        return _threatReports[_index];
    }

    /**
     * @notice Get multiple threats with pagination
     * @dev Gas-efficient batch retrieval for UI/API consumption
     * @dev Includes overflow protection for pagination parameters
     * @param _startIndex Starting index in the array
     * @param _count Number of threats to retrieve
     * @return ThreatReport[] Array of threat reports
     */
    function getThreatsPaginated(
        uint256 _startIndex,
        uint256 _count
    ) external view returns (ThreatReport[] memory) {
        // Overflow protection: if _startIndex + _count overflows, endIndex will be < _startIndex
        // Also prevents excessive gas consumption from huge _count values
        if (_count > 1000) revert DCTIN__InvalidPaginationRange();
        
        uint256 arrayLength = _threatReports.length;
        if (_startIndex >= arrayLength) {
            return new ThreatReport[](0); // Return empty array instead of reverting
        }
        
        // Safe calculation of end index
        uint256 endIndex;
        unchecked {
            endIndex = _startIndex + _count;
        }
        
        // Clamp to array length
        if (endIndex > arrayLength || endIndex < _startIndex) { // Second check detects overflow
            endIndex = arrayLength;
        }
        
        uint256 resultCount = endIndex - _startIndex;
        ThreatReport[] memory result = new ThreatReport[](resultCount);
        
        for (uint256 i = 0; i < resultCount; i++) {
            result[i] = _threatReports[_startIndex + i];
        }
        
        return result;
    }

    /**
     * @notice Get all threat hashes reported by a specific address
     * @dev Iterates through all reports - use with caution for large datasets
     * @param _reporter Address to filter by
     * @return bytes32[] Array of threat hashes
     */
    function getThreatsByReporter(
        address _reporter
    ) external view returns (bytes32[] memory) {
        // First count matching reports
        uint256 count = 0;
        for (uint256 i = 0; i < _threatReports.length; i++) {
            if (_threatReports[i].reporter == _reporter) {
                count++;
            }
        }
        
        // Collect matching hashes
        bytes32[] memory result = new bytes32[](count);
        uint256 index = 0;
        for (uint256 i = 0; i < _threatReports.length; i++) {
            if (_threatReports[i].reporter == _reporter) {
                result[index] = _threatReports[i].threatHash;
                index++;
            }
        }
        
        return result;
    }

    /**
     * @notice Check if an address has reporter role
     * @param _account Address to check
     * @return bool True if account is a reporter
     */
    function isReporter(address _account) external view returns (bool) {
        return hasRole(REPORTER_ROLE, _account);
    }

    /**
     * @notice Check if an address has admin role
     * @param _account Address to check
     * @return bool True if account is an admin
     */
    function isAdmin(address _account) external view returns (bool) {
        return hasRole(DEFAULT_ADMIN_ROLE, _account);
    }

    // ============ Internal Functions ============
    
    /**
     * @notice Override supportsInterface for AccessControl
     */
    function supportsInterface(
        bytes4 interfaceId
    ) public view override(AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
