const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  console.log("Deploying SecureDataManagement contract...");

  const [deployer] = await ethers.getSigners();
  console.log(`Deploying with account: ${deployer.address}`);

  const balance = await ethers.provider.getBalance(deployer.address);
  console.log(`Account balance: ${ethers.formatEther(balance)} ETH/MATIC`);

  const SecureDataManagement = await ethers.getContractFactory("SecureDataManagement");
  const contract = await SecureDataManagement.deploy();

  await contract.waitForDeployment();

  const contractAddress = await contract.getAddress();
  console.log(`\nSecureDataManagement deployed to: ${contractAddress}`);

  const artifactPath = path.join(
    __dirname,
    "..",
    "artifacts",
    "contracts",
    "SecureDataManagement.sol",
    "SecureDataManagement.json"
  );

  const abiOutputPath = path.join(
    __dirname,
    "..",
    "..",
    "backend",
    "abi",
    "SecureDataManagement.json"
  );

  if (fs.existsSync(artifactPath)) {
    const artifact  = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
    const network   = await ethers.provider.getNetwork();
    const netName   = network.name === "unknown" ? `chain-${network.chainId}` : network.name;
    const abiOutput = {
      contractName: artifact.contractName,
      abi: artifact.abi,
      address: contractAddress,
      deployedAt: new Date().toISOString(),
      network: netName,
      chainId: Number(network.chainId)
    };

    fs.mkdirSync(path.dirname(abiOutputPath), { recursive: true });

    const networkOutputPath = abiOutputPath.replace(".json", `-${netName}.json`);
    fs.writeFileSync(networkOutputPath, JSON.stringify(abiOutput, null, 2));
    console.log(`\nABI saved to: ${networkOutputPath}`);

    fs.writeFileSync(abiOutputPath, JSON.stringify(abiOutput, null, 2));
    console.log(`ABI saved to: ${abiOutputPath} (default)`);
  } else {
    console.warn(`Artifact not found at ${artifactPath}. Run 'npx hardhat compile' first.`);
  }

  console.log("\n─────────────────────────────────────────────────");
  console.log("Deployment complete!");
  console.log(`Contract address: ${contractAddress}`);
  console.log("─────────────────────────────────────────────────");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Deployment failed:", error);
    process.exit(1);
  });
