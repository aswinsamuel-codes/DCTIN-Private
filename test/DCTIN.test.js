import { expect } from "chai";
import hardhat from "hardhat";

const { ethers } = hardhat;

describe("DCTIN - Decentralized Cyber Threat Intelligence Network (v2 bytes32)", function () {
  let dctin;
  let owner, admin, reporter1, reporter2, unauthorized;

  // Threat type enum values
  const ThreatType = {
    MALWARE: 0,
    PHISHING_URL: 1,
    MALICIOUS_IP: 2,
    C2_SERVER: 3,
    BOTNET_NODE: 4,
    RANSOMWARE: 5,
    EXPLOIT_PAYLOAD: 6,
    SUSPICIOUS_DOMAIN: 7
  };

  // Sample threat hashes as bytes32
  const sampleThreatHash = ethers.id("malware_sample_1"); // keccak256 hash
  const sampleThreatHash2 = ethers.id("phishing_url_sample_1");
  const sampleThreatHash3 = ethers.id("c2_server_sample_1");

  beforeEach(async function () {
    [owner, admin, reporter1, reporter2, unauthorized] = await ethers.getSigners();
    
    const DCTIN = await ethers.getContractFactory("DCTIN");
    dctin = await DCTIN.deploy();
    await dctin.waitForDeployment();
  });

  describe("Deployment", function () {
    it("Should set deployer as DEFAULT_ADMIN_ROLE", async function () {
      expect(await dctin.isAdmin(owner.address)).to.be.true;
    });

    it("Should set deployer as REPORTER_ROLE", async function () {
      expect(await dctin.isReporter(owner.address)).to.be.true;
    });

    it("Should initialize with zero threats", async function () {
      expect(await dctin.getTotalThreats()).to.equal(0);
    });
  });

  describe("Threat Reporting (bytes32)", function () {
    it("Should allow reporter to submit a threat with bytes32 hash", async function () {
      const tx = await dctin.reportThreat(sampleThreatHash, ThreatType.MALWARE);
      const receipt = await tx.wait();
      
      expect(await dctin.getTotalThreats()).to.equal(1);
      expect(await dctin.threatExists(sampleThreatHash)).to.be.true;
      
      // Verify event was emitted with correct bytes32 hash
      const event = receipt.logs.find(
        log => log.fragment && log.fragment.name === "ThreatReported"
      );
      expect(event).to.not.be.undefined;
    });

    it("Should store correct threat data with bytes32", async function () {
      await dctin.reportThreat(sampleThreatHash, ThreatType.MALWARE);
      
      const threat = await dctin.getThreatByHash(sampleThreatHash);
      expect(threat.threatHash).to.equal(sampleThreatHash);
      expect(threat.threatType).to.equal(ThreatType.MALWARE);
      expect(threat.reporter).to.equal(owner.address);
    });

    it("Should prevent duplicate bytes32 threat hashes", async function () {
      await dctin.reportThreat(sampleThreatHash, ThreatType.MALWARE);
      
      await expect(dctin.reportThreat(sampleThreatHash, ThreatType.RANSOMWARE))
        .to.be.revertedWithCustomError(dctin, "DCTIN__ThreatAlreadyExists")
        .withArgs(sampleThreatHash);
    });

    it("Should prevent zero bytes32 hash", async function () {
      const zeroHash = ethers.ZeroHash; // bytes32(0)
      await expect(dctin.reportThreat(zeroHash, ThreatType.MALWARE))
        .to.be.revertedWithCustomError(dctin, "DCTIN__InvalidThreatHash");
    });

    it("Should prevent invalid threat type", async function () {
      await expect(dctin.reportThreat(sampleThreatHash, 8))
        .to.be.revertedWithCustomError(dctin, "DCTIN__InvalidThreatType");
    });

    it("Should reject unauthorized reporters", async function () {
      await expect(
        dctin.connect(unauthorized).reportThreat(sampleThreatHash, ThreatType.MALWARE)
      ).to.be.reverted;
    });

    it("Should allow multiple unique bytes32 threats from same reporter", async function () {
      await dctin.reportThreat(sampleThreatHash, ThreatType.MALWARE);
      await dctin.reportThreat(sampleThreatHash2, ThreatType.PHISHING_URL);
      
      expect(await dctin.getTotalThreats()).to.equal(2);
      
      // Verify both exist
      expect(await dctin.threatExists(sampleThreatHash)).to.be.true;
      expect(await dctin.threatExists(sampleThreatHash2)).to.be.true;
    });
  });

  describe("Access Control", function () {
    it("Should allow admin to add reporter", async function () {
      await expect(dctin.addReporter(reporter1.address))
        .to.emit(dctin, "ReporterAdded")
        .withArgs(reporter1.address, owner.address);
      
      expect(await dctin.isReporter(reporter1.address)).to.be.true;
    });

    it("Should allow admin to remove reporter", async function () {
      await dctin.addReporter(reporter1.address);
      
      await expect(dctin.removeReporter(reporter1.address))
        .to.emit(dctin, "ReporterRemoved")
        .withArgs(reporter1.address, owner.address);
      
      expect(await dctin.isReporter(reporter1.address)).to.be.false;
    });

    it("Should allow new reporter to submit threats", async function () {
      await dctin.addReporter(reporter1.address);
      
      await expect(
        dctin.connect(reporter1).reportThreat(sampleThreatHash, ThreatType.MALWARE)
      ).to.not.be.reverted;
    });

    it("Should prevent non-admin from adding reporters", async function () {
      await expect(
        dctin.connect(reporter1).addReporter(reporter2.address)
      ).to.be.reverted;
    });

    it("Should prevent removed reporter from submitting", async function () {
      await dctin.addReporter(reporter1.address);
      await dctin.removeReporter(reporter1.address);
      
      await expect(
        dctin.connect(reporter1).reportThreat(sampleThreatHash, ThreatType.MALWARE)
      ).to.be.reverted;
    });
  });

  describe("Rate Limiting Security", function () {
    it("Should enforce MAX_REPORTS_PER_BLOCK limit (10 reports)", async function () {
      // Submit exactly 10 reports (the limit)
      for (let i = 0; i < 10; i++) {
        const hash = ethers.id(`rate_limit_test_${i}`);
        await expect(dctin.reportThreat(hash, ThreatType.MALWARE)).to.not.be.reverted;
      }
      
      // 11th report should fail with rate limit
      const eleventhHash = ethers.id("rate_limit_test_10");
      await expect(dctin.reportThreat(eleventhHash, ThreatType.MALWARE))
        .to.be.revertedWithCustomError(dctin, "DCTIN__RateLimitExceeded")
        .withArgs(owner.address, await ethers.provider.getBlockNumber());
    });

    it("Should reset rate limit in new block", async function () {
      // Submit 10 reports in current block
      for (let i = 0; i < 10; i++) {
        const hash = ethers.id(`block_reset_test_${i}`);
        await dctin.reportThreat(hash, ThreatType.MALWARE);
      }
      
      // Mine a new block
      await ethers.provider.send("evm_mine", []);
      
      // Should be able to submit again in new block
      const newBlockHash = ethers.id("new_block_report");
      await expect(dctin.reportThreat(newBlockHash, ThreatType.MALWARE)).to.not.be.reverted;
    });

    it("Should track rate limits per reporter independently", async function () {
      await dctin.addReporter(reporter1.address);
      
      // Owner submits 5 reports
      for (let i = 0; i < 5; i++) {
        await dctin.reportThreat(ethers.id(`owner_report_${i}`), ThreatType.MALWARE);
      }
      
      // Reporter1 should still have full quota of 10
      for (let i = 0; i < 10; i++) {
        await expect(
          dctin.connect(reporter1).reportThreat(ethers.id(`reporter1_report_${i}`), ThreatType.PHISHING_URL)
        ).to.not.be.reverted;
      }
      
      // Reporter1's 11th should fail
      await expect(
        dctin.connect(reporter1).reportThreat(ethers.id("reporter1_excess"), ThreatType.PHISHING_URL)
      ).to.be.revertedWithCustomError(dctin, "DCTIN__RateLimitExceeded");
    });

    it("Should emit RateLimitExceeded event when limit breached", async function () {
      // Fill up to limit
      for (let i = 0; i < 10; i++) {
        await dctin.reportThreat(ethers.id(`event_test_${i}`), ThreatType.MALWARE);
      }
      
      // Next attempt should emit event then revert
      const tx = dctin.reportThreat(ethers.id("event_test_excess"), ThreatType.MALWARE);
      await expect(tx)
        .to.emit(dctin, "RateLimitExceeded")
        .withArgs(owner.address, await ethers.provider.getBlockNumber(), 11);
      
      await expect(tx).to.be.revertedWithCustomError(dctin, "DCTIN__RateLimitExceeded");
    });
  });

  describe("Query Functions (bytes32)", function () {
    beforeEach(async function () {
      // Seed with 5 threats for query tests
      for (let i = 0; i < 5; i++) {
        await dctin.reportThreat(ethers.id(`query_seed_${i}`), ThreatType.MALWARE);
      }
    });

    it("Should get threat by bytes32 hash correctly", async function () {
      const hash = ethers.id("query_seed_0");
      const threat = await dctin.getThreatByHash(hash);
      expect(threat.threatType).to.equal(ThreatType.MALWARE);
      expect(threat.threatHash).to.equal(hash);
      expect(threat.reporter).to.equal(owner.address);
    });

    it("Should revert for non-existent bytes32 hash", async function () {
      const nonExistentHash = ethers.id("non_existent_threat");
      await expect(dctin.getThreatByHash(nonExistentHash))
        .to.be.revertedWithCustomError(dctin, "DCTIN__ThreatNotFound")
        .withArgs(nonExistentHash);
    });

    it("Should check bytes32 threat existence correctly", async function () {
      expect(await dctin.threatExists(ethers.id("query_seed_0"))).to.be.true;
      expect(await dctin.threatExists(ethers.id("unknown_hash"))).to.be.false;
    });

    it("Should get threat by valid index", async function () {
      const threat = await dctin.getThreatByIndex(0);
      expect(threat.threatHash).to.equal(ethers.id("query_seed_0"));
    });

    it("Should revert for out-of-bounds index", async function () {
      await expect(dctin.getThreatByIndex(999))
        .to.be.revertedWithCustomError(dctin, "DCTIN__ThreatNotFound")
        .withArgs(ethers.ZeroHash);
    });

    it("Should paginate correctly with valid range", async function () {
      const page = await dctin.getThreatsPaginated(0, 3);
      expect(page.length).to.equal(3);
    });

    it("Should return empty array for startIndex beyond array length", async function () {
      const page = await dctin.getThreatsPaginated(1000, 10);
      expect(page.length).to.equal(0);
    });

    it("Should clamp pagination to array length", async function () {
      const page = await dctin.getThreatsPaginated(3, 100); // Only 2 items left (index 3,4)
      expect(page.length).to.equal(2);
    });

    it("Should reject excessive count values in pagination", async function () {
      await expect(dctin.getThreatsPaginated(0, 1001))
        .to.be.revertedWithCustomError(dctin, "DCTIN__InvalidPaginationRange");
    });

    it("Should handle pagination overflow gracefully", async function () {
      // Test with values that could cause overflow: startIndex = max, count = max
      const maxUint = ethers.MaxUint256;
      const page = await dctin.getThreatsPaginated(maxUint, 1000);
      expect(page.length).to.equal(0); // Should return empty, not revert
    });

    it("Should get threats by reporter", async function () {
      const threats = await dctin.getThreatsByReporter(owner.address);
      expect(threats.length).to.equal(5);
    });
  });

  describe("Edge Cases and Boundary Tests", function () {
    it("Should handle all valid threat type enum values", async function () {
      const threatTypes = Object.values(ThreatType).filter(v => typeof v === 'number');
      
      for (let i = 0; i < threatTypes.length; i++) {
        const hash = ethers.id(`edge_case_type_${i}`);
        await expect(dctin.reportThreat(hash, i)).to.not.be.reverted;
      }
      
      expect(await dctin.getTotalThreats()).to.equal(threatTypes.length);
    });

    it("Should revert on invalid threat type (8)", async function () {
      await expect(dctin.reportThreat(ethers.id("invalid_type"), 8))
        .to.be.revertedWithCustomError(dctin, "DCTIN__InvalidThreatType");
    });

    it("Should revert on very large invalid threat type (255)", async function () {
      await expect(dctin.reportThreat(ethers.id("large_invalid_type"), 255))
        .to.be.revertedWithCustomError(dctin, "DCTIN__InvalidThreatType");
    });

    it("Should prevent duplicate submission even with different threat types", async function () {
      const hash = ethers.id("duplicate_across_types");
      
      await dctin.reportThreat(hash, ThreatType.MALWARE);
      
      // Same hash, different type should still fail
      await expect(dctin.reportThreat(hash, ThreatType.PHISHING_URL))
        .to.be.revertedWithCustomError(dctin, "DCTIN__ThreatAlreadyExists")
        .withArgs(hash);
    });

    it("Should maintain totalThreats as view function (no storage)", async function () {
      const totalBefore = await dctin.totalThreats();
      expect(totalBefore).to.equal(0);
      
      await dctin.reportThreat(ethers.id("view_test_1"), ThreatType.MALWARE);
      
      const totalAfter = await dctin.totalThreats();
      expect(totalAfter).to.equal(1);
      
      // Verify it's truly a view function by calling statically
      const staticTotal = await dctin.totalThreats.staticCall();
      expect(staticTotal).to.equal(1);
    });

    it("Should correctly track multiple reporters' submissions", async function () {
      await dctin.addReporter(reporter1.address);
      await dctin.addReporter(reporter2.address);
      
      // Each reporter submits 3 threats
      for (let i = 0; i < 3; i++) {
        await dctin.reportThreat(ethers.id(`owner_multi_${i}`), ThreatType.MALWARE);
        await dctin.connect(reporter1).reportThreat(ethers.id(`r1_multi_${i}`), ThreatType.PHISHING_URL);
        await dctin.connect(reporter2).reportThreat(ethers.id(`r2_multi_${i}`), ThreatType.C2_SERVER);
      }
      
      expect(await dctin.getTotalThreats()).to.equal(9);
    });
  });
});
