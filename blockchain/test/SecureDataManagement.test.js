const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("SecureDataManagement", function () {
  let contract;
  let owner, user1, user2;

  const FILE_ID = "file-test-001";
  const FILE_HASH = "abc123def456";
  const FILE_NAME = "test-document.pdf";
  const FILE_SIZE = 1024 * 1024; // 1 MB
  const CHUNK_IDS = ["file-test-001/chunk_0000"];
  const CHUNK_HASHES = ["chunkhash001"];
  const CHUNK_SIZES = [1024 * 1024];
  const CHUNK_LOCATIONS = ["minio://secure-storage/file-test-001/chunk_0000"];

  const Permission = { NONE: 0, READ: 1, WRITE: 2, FULL: 3 };

  beforeEach(async function () {
    [owner, user1, user2] = await ethers.getSigners();

    const SecureDataManagement = await ethers.getContractFactory("SecureDataManagement");
    contract = await SecureDataManagement.deploy();
    await contract.waitForDeployment();
  });

  describe("registerFile", function () {
    it("should register a file successfully", async function () {
      const tx = await contract.connect(owner).registerFile(
        FILE_ID, FILE_HASH, FILE_NAME, FILE_SIZE,
        CHUNK_IDS, CHUNK_HASHES, CHUNK_SIZES, CHUNK_LOCATIONS
      );
      await tx.wait();

      const [retId, retHash, retName, retSize, retOwner,, retActive] =
        await contract.getFileMetadata(FILE_ID);

      expect(retId).to.equal(FILE_ID);
      expect(retHash).to.equal(FILE_HASH);
      expect(retName).to.equal(FILE_NAME);
      expect(retSize).to.equal(FILE_SIZE);
      expect(retOwner).to.equal(owner.address);
      expect(retActive).to.be.true;
    });

    it("should emit FileRegistered event", async function () {
      const tx = await contract.connect(owner).registerFile(
        FILE_ID, FILE_HASH, FILE_NAME, FILE_SIZE,
        CHUNK_IDS, CHUNK_HASHES, CHUNK_SIZES, CHUNK_LOCATIONS
      );
      const receipt = await tx.wait();
      const block = await ethers.provider.getBlock(receipt.blockNumber);
      await expect(tx)
        .to.emit(contract, "FileRegistered")
        .withArgs(FILE_ID, owner.address, FILE_HASH, FILE_SIZE, block.timestamp);
    });

    it("should revert on duplicate fileId", async function () {
      await contract.connect(owner).registerFile(
        FILE_ID, FILE_HASH, FILE_NAME, FILE_SIZE,
        CHUNK_IDS, CHUNK_HASHES, CHUNK_SIZES, CHUNK_LOCATIONS
      );
      await expect(
        contract.connect(owner).registerFile(
          FILE_ID, FILE_HASH, FILE_NAME, FILE_SIZE,
          CHUNK_IDS, CHUNK_HASHES, CHUNK_SIZES, CHUNK_LOCATIONS
        )
      ).to.be.revertedWith("SecureDataManagement: file already registered");
    });

    it("should revert on empty fileId", async function () {
      await expect(
        contract.connect(owner).registerFile(
          "", FILE_HASH, FILE_NAME, FILE_SIZE,
          CHUNK_IDS, CHUNK_HASHES, CHUNK_SIZES, CHUNK_LOCATIONS
        )
      ).to.be.revertedWith("SecureDataManagement: fileId cannot be empty");
    });

    it("should revert on chunk array length mismatch", async function () {
      await expect(
        contract.connect(owner).registerFile(
          FILE_ID, FILE_HASH, FILE_NAME, FILE_SIZE,
          CHUNK_IDS, CHUNK_HASHES, [1024, 2048], CHUNK_LOCATIONS
        )
      ).to.be.revertedWith("SecureDataManagement: chunk array length mismatch");
    });

    it("should store chunk info correctly", async function () {
      await contract.connect(owner).registerFile(
        FILE_ID, FILE_HASH, FILE_NAME, FILE_SIZE,
        CHUNK_IDS, CHUNK_HASHES, CHUNK_SIZES, CHUNK_LOCATIONS
      );
      const chunks = await contract.getFileChunks(FILE_ID);
      expect(chunks.length).to.equal(1);
      expect(chunks[0].chunkId).to.equal(CHUNK_IDS[0]);
      expect(chunks[0].chunkHash).to.equal(CHUNK_HASHES[0]);
      expect(chunks[0].chunkSize).to.equal(CHUNK_SIZES[0]);
      expect(chunks[0].chunkLocation).to.equal(CHUNK_LOCATIONS[0]);
    });
  });

  describe("grantAccess", function () {
    beforeEach(async function () {
      await contract.connect(owner).registerFile(
        FILE_ID, FILE_HASH, FILE_NAME, FILE_SIZE,
        CHUNK_IDS, CHUNK_HASHES, CHUNK_SIZES, CHUNK_LOCATIONS
      );
    });

    it("should grant READ permission to user1", async function () {
      const tx = await contract.connect(owner).grantAccess(FILE_ID, user1.address, Permission.READ);
      const receipt = await tx.wait();
      const block = await ethers.provider.getBlock(receipt.blockNumber);
      await expect(tx)
        .to.emit(contract, "AccessGranted")
        .withArgs(FILE_ID, user1.address, Permission.READ, block.timestamp);
    });

    it("should grant WRITE permission to user1", async function () {
      await contract.connect(owner).grantAccess(FILE_ID, user1.address, Permission.WRITE);
      const hasRead = await contract.checkPermission(FILE_ID, user1.address, Permission.READ);
      const hasWrite = await contract.checkPermission(FILE_ID, user1.address, Permission.WRITE);
      const hasFull = await contract.checkPermission(FILE_ID, user1.address, Permission.FULL);
      expect(hasRead).to.be.true;
      expect(hasWrite).to.be.true;
      expect(hasFull).to.be.false;
    });

    it("should revert when non-owner tries to grant access", async function () {
      await expect(
        contract.connect(user1).grantAccess(FILE_ID, user2.address, Permission.READ)
      ).to.be.revertedWith("SecureDataManagement: caller is not the file owner");
    });

    it("should revert on zero address", async function () {
      await expect(
        contract.connect(owner).grantAccess(FILE_ID, ethers.ZeroAddress, Permission.READ)
      ).to.be.revertedWith("SecureDataManagement: zero address");
    });
  });

  describe("checkPermission", function () {
    beforeEach(async function () {
      await contract.connect(owner).registerFile(
        FILE_ID, FILE_HASH, FILE_NAME, FILE_SIZE,
        CHUNK_IDS, CHUNK_HASHES, CHUNK_SIZES, CHUNK_LOCATIONS
      );
    });

    it("owner should always have FULL permission", async function () {
      const result = await contract.checkPermission(FILE_ID, owner.address, Permission.FULL);
      expect(result).to.be.true;
    });

    it("user with no permission should be denied", async function () {
      const result = await contract.checkPermission(FILE_ID, user1.address, Permission.READ);
      expect(result).to.be.false;
    });

    it("user with READ should not have WRITE", async function () {
      await contract.connect(owner).grantAccess(FILE_ID, user1.address, Permission.READ);
      const hasRead = await contract.checkPermission(FILE_ID, user1.address, Permission.READ);
      const hasWrite = await contract.checkPermission(FILE_ID, user1.address, Permission.WRITE);
      expect(hasRead).to.be.true;
      expect(hasWrite).to.be.false;
    });

    it("user with FULL should pass all permission checks", async function () {
      await contract.connect(owner).grantAccess(FILE_ID, user1.address, Permission.FULL);
      expect(await contract.checkPermission(FILE_ID, user1.address, Permission.NONE)).to.be.true;
      expect(await contract.checkPermission(FILE_ID, user1.address, Permission.READ)).to.be.true;
      expect(await contract.checkPermission(FILE_ID, user1.address, Permission.WRITE)).to.be.true;
      expect(await contract.checkPermission(FILE_ID, user1.address, Permission.FULL)).to.be.true;
    });
  });

  describe("revokeAccess", function () {
    beforeEach(async function () {
      await contract.connect(owner).registerFile(
        FILE_ID, FILE_HASH, FILE_NAME, FILE_SIZE,
        CHUNK_IDS, CHUNK_HASHES, CHUNK_SIZES, CHUNK_LOCATIONS
      );
      await contract.connect(owner).grantAccess(FILE_ID, user1.address, Permission.WRITE);
    });

    it("should revoke access and emit event", async function () {
      const tx = await contract.connect(owner).revokeAccess(FILE_ID, user1.address);
      const receipt = await tx.wait();
      const block = await ethers.provider.getBlock(receipt.blockNumber);
      await expect(tx)
        .to.emit(contract, "AccessRevoked")
        .withArgs(FILE_ID, user1.address, block.timestamp);

      const hasRead = await contract.checkPermission(FILE_ID, user1.address, Permission.READ);
      expect(hasRead).to.be.false;
    });

    it("should revert when non-owner tries to revoke", async function () {
      await expect(
        contract.connect(user1).revokeAccess(FILE_ID, user2.address)
      ).to.be.revertedWith("SecureDataManagement: caller is not the file owner");
    });

    it("should revert when trying to revoke owner access", async function () {
      await expect(
        contract.connect(owner).revokeAccess(FILE_ID, owner.address)
      ).to.be.revertedWith("SecureDataManagement: cannot revoke owner access");
    });
  });

  describe("logAccess", function () {
    beforeEach(async function () {
      await contract.connect(owner).registerFile(
        FILE_ID, FILE_HASH, FILE_NAME, FILE_SIZE,
        CHUNK_IDS, CHUNK_HASHES, CHUNK_SIZES, CHUNK_LOCATIONS
      );
    });

    it("should log access and emit AccessLogged event", async function () {
      await expect(
        contract.connect(user1).logAccess(FILE_ID, "download", "192.168.1.1", true, false)
      ).to.emit(contract, "AccessLogged");
    });

    it("should emit AnomalyDetected when anomalyFlag is true", async function () {
      await expect(
        contract.connect(user1).logAccess(FILE_ID, "download", "1.2.3.4", true, true)
      )
        .to.emit(contract, "AnomalyDetected")
        .and.to.emit(contract, "AccessLogged");
    });
  });

  describe("getAccessLogs", function () {
    const FILE_ID_2 = "file-test-002";

    beforeEach(async function () {
      await contract.connect(owner).registerFile(
        FILE_ID, FILE_HASH, FILE_NAME, FILE_SIZE,
        CHUNK_IDS, CHUNK_HASHES, CHUNK_SIZES, CHUNK_LOCATIONS
      );
      await contract.connect(user1).logAccess(FILE_ID, "download", "10.0.0.1", true, false);
      await contract.connect(user1).logAccess(FILE_ID, "view", "10.0.0.1", true, false);
      await contract.connect(user2).logAccess(FILE_ID, "download", "10.0.0.2", false, false);
      await contract.connect(owner).logAccess(FILE_ID_2, "upload", "10.0.0.3", true, false);
    });

    it("should return logs filtered by fileId", async function () {
      const logs = await contract.getAccessLogs(FILE_ID, 0, 10);
      expect(logs.length).to.equal(3);
      for (const log of logs) {
        expect(log.fileId).to.equal(FILE_ID);
      }
    });

    it("should paginate correctly", async function () {
      const page0 = await contract.getAccessLogs(FILE_ID, 0, 2);
      const page1 = await contract.getAccessLogs(FILE_ID, 1, 2);
      expect(page0.length).to.equal(2);
      expect(page1.length).to.equal(1);
    });

    it("should return empty array when page is out of range", async function () {
      const logs = await contract.getAccessLogs(FILE_ID, 99, 10);
      expect(logs.length).to.equal(0);
    });
  });

  describe("getAnomalyLogs", function () {
    beforeEach(async function () {
      await contract.connect(owner).registerFile(
        FILE_ID, FILE_HASH, FILE_NAME, FILE_SIZE,
        CHUNK_IDS, CHUNK_HASHES, CHUNK_SIZES, CHUNK_LOCATIONS
      );
      // 2 normal, 2 anomalous
      await contract.connect(user1).logAccess(FILE_ID, "download", "10.0.0.1", true, false);
      await contract.connect(user1).logAccess(FILE_ID, "download", "5.5.5.5", true, true);
      await contract.connect(user2).logAccess(FILE_ID, "upload", "10.0.0.2", true, false);
      await contract.connect(user2).logAccess(FILE_ID, "download", "8.8.8.8", false, true);
    });

    it("should return only anomalous logs", async function () {
      const logs = await contract.getAnomalyLogs(0, 10);
      expect(logs.length).to.equal(2);
      for (const log of logs) {
        expect(log.anomalyFlag).to.be.true;
      }
    });

    it("should paginate anomaly logs correctly", async function () {
      const page0 = await contract.getAnomalyLogs(0, 1);
      const page1 = await contract.getAnomalyLogs(1, 1);
      expect(page0.length).to.equal(1);
      expect(page1.length).to.equal(1);
      expect(page0[0].user).to.not.equal(page1[0].user);
    });

    it("should return empty array when no anomalies", async function () {
      const SDM = await ethers.getContractFactory("SecureDataManagement");
      const fresh = await SDM.deploy();
      await fresh.waitForDeployment();
      const logs = await fresh.getAnomalyLogs(0, 10);
      expect(logs.length).to.equal(0);
    });
  });

  async function getTimestamp() {
    const block = await ethers.provider.getBlock("latest");
    return block.timestamp;
  }
});
