import hre from "hardhat";
import fs from "fs";

/**
 * @title DCTIN Deployment Script
 * @notice Deploys the DCTIN smart contract to the configured network
 * @dev Uses Hardhat's runtime environment for deployment
 */

async function main() {
  console.log("🚀 Starting DCTIN Smart Contract Deployment...\n");

  const { ethers, network } = hre;

  // Get the deployer's address
  const [deployer] = await ethers.getSigners();
  console.log("👤 Deploying contracts with account:", deployer.address);
  
  // Check deployer balance
  const balance = await ethers.provider.getBalance(deployer.address);
  console.log("💰 Account balance:", ethers.formatEther(balance), "ETH");

  // Deploy the DCTIN contract
  console.log("\n📄 Deploying DCTIN contract...");
  const DCTIN = await ethers.getContractFactory("DCTIN");
  const dctin = await DCTIN.deploy();
  
  // Wait for deployment to complete
  await dctin.waitForDeployment();
  
  const contractAddress = await dctin.getAddress();
  console.log("✅ DCTIN contract deployed to:", contractAddress);

  // Log deployment details
  console.log("\n📊 Deployment Summary:");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("Contract Address:", contractAddress);
  console.log("Deployer Address:", deployer.address);
  console.log("Network:", network.name);
  console.log("Block Number:", await ethers.provider.getBlockNumber());
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

  // Save deployment info
  const deploymentInfo = {
    contract: "DCTIN",
    address: contractAddress,
    deployer: deployer.address,
    network: network.name,
    timestamp: new Date().toISOString(),
    abi: DCTIN.interface.formatJson()
  };

  console.log("📝 Save this information for future reference!");
  
  // Optional: Verify roles are set correctly
  console.log("\n🔐 Verifying initial setup...");
  const isDeployerAdmin = await dctin.isAdmin(deployer.address);
  const isDeployerReporter = await dctin.isReporter(deployer.address);
  
  console.log("Deployer is Admin:", isDeployerAdmin ? "✅" : "❌");
  console.log("Deployer is Reporter:", isDeployerReporter ? "✅" : "❌");

  if (!isDeployerAdmin || !isDeployerReporter) {
    console.warn("⚠️ Warning: Initial role setup may have issues!");
  } else {
    console.log("✅ All initial roles verified successfully!");
  }

  // Save deployment to file
  const deploymentsDir = "./deployments";
  
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir);
  }
  
  const filename = `${deploymentsDir}/${network.name}-${Date.now()}.json`;
  fs.writeFileSync(filename, JSON.stringify(deploymentInfo, null, 2));
  console.log(`\n💾 Deployment info saved to: ${filename}`);

  console.log("\n🎉 Deployment completed successfully!");
  console.log("\nNext steps:");
  console.log("1. Add authorized reporters using: dctin.addReporter(address)");
  console.log("2. Start submitting threat reports using: dctin.reportThreat(hash, type)");
  console.log("3. Query threats using: dctin.getThreatByHash(hash)");

  return deploymentInfo;
}

// Execute deployment
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("❌ Deployment failed:", error);
    process.exit(1);
  });
