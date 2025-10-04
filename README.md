# 🔒 Remix Plugin for Security Analysis

🛡️ A comprehensive smart contract security analysis plugin for Remix IDE, built with Clarity for the Stacks blockchain.

## 🚀 Overview

This MVP demonstrates how IDE plugins can integrate with blockchain smart contracts to provide real-time security analysis, vulnerability detection, and code quality assessment for smart contracts. Perfect for developers learning about IDE integration and security tooling.

## ✨ Features

### 🔍 Core Security Analysis
- **Contract Security Scoring**: Automated security score calculation based on gas usage, code quality, and vulnerabilities
- **Vulnerability Detection**: Track and categorize security vulnerabilities with confidence ratings
- **Risk Assessment**: Multi-level risk categorization (low, medium, high, critical)
- **Analysis History**: Complete audit trail of all security analyses

### 👥 User Management
- **Analyzer Certification**: Register and manage certified security analyzers
- **User Reputation**: Track user analysis history and reputation scores
- **Credential System**: Verify analyzer credentials and accuracy ratings

### 📊 Advanced Features
- **Security Patterns**: Maintain database of common security patterns and vulnerabilities
- **Batch Processing**: Analyze multiple vulnerabilities in a single transaction
- **Fee Management**: Configurable analysis fees with STX token payments
- **Plugin Controls**: Admin controls for plugin activation/deactivation

### 🎯 Security Bounty System
- **Bounty Creation**: Contract owners can post STX rewards for vulnerability discovery
- **Competitive Analysis**: Multiple security researchers can compete for bounties
- **Performance-Based Rewards**: Dynamic payouts based on vulnerability severity (4x for critical, 2x for high)
- **Reputation Tracking**: Bounty hunter success rates and lifetime earnings
- **Time-Based Expiration**: Automatic bounty expiration with fund recovery

### 🛡️ Security Insurance Pool
- **DeFi Insurance**: Decentralized insurance marketplace for smart contract security risks
- **Liquidity Provision**: Earn yield by providing STX liquidity to insurance pools
- **Risk-Based Premiums**: Premium calculations based on security scores and coverage duration
- **Automated Claims**: Streamlined claim filing and processing system
- **Pool Management**: Real-time pool statistics and utilization tracking

### 🏅 Security Badge NFT System
- **Tokenized Security**: Transform security analysis into tradeable NFT badges
- **Tier-Based Badges**: Platinum (90+), Gold (75+), Silver (60+), Bronze (50+) classifications
- **DeFi Composability**: NFT badges integrate with lending, DEXs, and other protocols
- **NFT Marketplace**: Built-in marketplace for buying/selling security credentials
- **Time-Decay Mechanics**: Badges expire and require renewal for continuous validity

## 🛠️ Installation & Setup

### Prerequisites
- Clarinet installed
- Stacks wallet configured
- Node.js (for testing)

### Quick Start
```bash
# Clone the repository
git clone <your-repo-url>
cd Remix-Plugin-for-Security-Analysis

# Install dependencies
npm install

# Run tests
npm test

# Deploy to testnet
clarinet deploy --testnet
```

## 📋 Usage

### 🔧 Basic Operations

#### Register as Analyzer
```clarity
(contract-call? .remix-plugin-for-security-analysis register-analyzer 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM)
```

#### Perform Security Analysis
```clarity
(contract-call? .remix-plugin-for-security-analysis perform-security-analysis 
  'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM  ;; contract address
  u85                                           ;; gas usage score
  u90)                                          ;; code quality score
```

#### Add Vulnerability
```clarity
(contract-call? .remix-plugin-for-security-analysis add-vulnerability
  u1                                    ;; analysis ID
  u1                                    ;; vulnerability index
  "reentrancy"                         ;; vulnerability type
  "high"                               ;; severity
  "Potential reentrancy attack vector" ;; description
  u42                                  ;; line number
  u95)                                 ;; confidence level
```

### 📊 Query Functions

#### Get Analysis Summary
```clarity
(contract-call? .remix-plugin-for-security-analysis get-analysis-summary u1)
```

#### Check Security Score
```clarity
(contract-call? .remix-plugin-for-security-analysis get-analysis u1)
```

#### View User History
```clarity
(contract-call? .remix-plugin-for-security-analysis get-user-history 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM)
```

### 🎯 Bounty System Operations

#### Create Security Bounty
```clarity
(contract-call? .remix-plugin-for-security-analysis create-security-bounty
  'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM  ;; target contract
  u10000000                                     ;; total reward (10 STX)
  u1000                                         ;; duration (1000 blocks)
  "medium")                                     ;; minimum severity
```

#### Claim Bounty
```clarity
(contract-call? .remix-plugin-for-security-analysis claim-bounty
  u1                                            ;; bounty ID
  u1                                            ;; analysis ID
  u1)                                           ;; vulnerability index
```

#### Check Bounty Status
```clarity
(contract-call? .remix-plugin-for-security-analysis get-bounty u1)
```

#### View Bounty Hunter Stats
```clarity
(contract-call? .remix-plugin-for-security-analysis get-bounty-hunter-stats 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM)
```

### 🛡️ Insurance System Operations

#### Provide Liquidity
```clarity
(contract-call? .remix-plugin-for-security-analysis provide-liquidity u5000000) ;; 5 STX
```

#### Purchase Insurance
```clarity
(contract-call? .remix-plugin-for-security-analysis purchase-insurance
  'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM  ;; contract to insure
  u2000000                                     ;; coverage amount (2 STX)
  u2000                                        ;; duration (2000 blocks)
  u85)                                         ;; security score
```

#### File Insurance Claim
```clarity
(contract-call? .remix-plugin-for-security-analysis file-insurance-claim
  u1                                           ;; policy ID
  u1000000                                     ;; claim amount (1 STX)
  u1)                                          ;; vulnerability evidence ID
```

#### Check Policy Status
```clarity
(contract-call? .remix-plugin-for-security-analysis get-insurance-policy u1)
```

#### View Pool Statistics
```clarity
(contract-call? .remix-plugin-for-security-analysis get-pool-stats u0)
```

### 🏅 NFT Badge Operations

#### Mint Security Badge
```clarity
(contract-call? .remix-plugin-for-security-analysis mint-security-badge
  u1                                               ;; analysis ID
  u10000)                                          ;; validity (blocks)
```

#### Transfer Badge
```clarity
(contract-call? .remix-plugin-for-security-analysis transfer-security-badge
  u1                                               ;; badge ID
  'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM)      ;; recipient
```

#### List Badge for Sale
```clarity
(contract-call? .remix-plugin-for-security-analysis list-badge-for-sale
  u1                                               ;; badge ID
  u5000000)                                        ;; price (5 STX)
```

#### Buy Badge from Marketplace
```clarity
(contract-call? .remix-plugin-for-security-analysis buy-badge-from-marketplace u1)
```

#### Check Badge Details
```clarity
(contract-call? .remix-plugin-for-security-analysis get-security-badge u1)
```

#### View Badge Statistics
```clarity
(contract-call? .remix-plugin-for-security-analysis get-badge-statistics u0)
```

## 🏗️ Architecture

### 📁 Contract Structure
- **Security Analyses**: Core analysis data storage
- **Vulnerability Tracking**: Detailed vulnerability information
- **User Management**: Analyzer credentials and user history
- **Security Patterns**: Common vulnerability pattern database
- **Bounty System**: Security bounty tracking and reward distribution
- **Reputation System**: Bounty hunter performance and reward history
- **Insurance Pool**: DeFi-style insurance marketplace with liquidity provision
- **Claims Management**: Automated insurance claim processing and payouts
- **NFT Badge System**: Tokenized security credentials with marketplace
- **Badge Ownership**: Track and transfer security NFTs across users

### 🔄 Workflow
1. **Register Analyzer** → Gain certification to perform analyses
2. **Initiate Analysis** → Pay fee and create analysis record
3. **Add Vulnerabilities** → Document found security issues
4. **Complete Analysis** → Finalize and publish results
5. **View Results** → Access comprehensive security reports

## 🧪 Testing

```bash
# Run all tests
npm test

# Run specific test file
npm test tests/remix-plugin-test.ts

# Check contract syntax
clarinet check
```

## 📖 API Reference

### Public Functions
- `perform-security-analysis`: Start new security analysis
- `add-vulnerability`: Add vulnerability to existing analysis
- `complete-analysis`: Mark analysis as completed
- `register-analyzer`: Register new security analyzer
- `add-security-pattern`: Add new security pattern
- `create-security-bounty`: Post bounty for vulnerability discovery
- `claim-bounty`: Claim reward for finding vulnerabilities
- `expire-bounty`: Expire bounty and recover remaining funds
- `provide-liquidity`: Add STX to insurance pool for yield
- `purchase-insurance`: Buy insurance coverage for contracts
- `file-insurance-claim`: File claim for security incident
- `process-insurance-claim`: Process and approve/reject claims
- `mint-security-badge`: Create NFT badge from completed analysis
- `transfer-security-badge`: Transfer badge ownership
- `list-badge-for-sale`: List badge on marketplace
- `buy-badge-from-marketplace`: Purchase listed badges

### Read-Only Functions
- `get-analysis`: Retrieve analysis by ID
- `get-vulnerability`: Get specific vulnerability details
- `get-user-history`: View user's analysis history
- `calculate-overall-security-score`: Calculate composite security score
- `get-bounty`: Retrieve bounty details and status
- `get-bounty-hunter-stats`: View bounty hunter performance metrics
- `calculate-bounty-reward`: Calculate reward based on vulnerability severity
- `get-insurance-policy`: View policy details and coverage
- `get-liquidity-provider`: Check liquidity provider statistics
- `calculate-insurance-premium`: Calculate premium for coverage
- `get-total-insurance-pool`: View total pool liquidity
- `get-security-badge`: View NFT badge details and metadata
- `get-badge-ownership`: List all badges owned by address
- `calculate-badge-tier`: Determine badge tier from security score
- `is-badge-active`: Check if badge is currently valid

## 🔐 Security Considerations

- All analyses require STX payment to prevent spam
- Only registered analyzers can perform security analyses
- Contract owner controls analyzer registration
- Fee adjustments are owner-only operations

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🎯 Learning Objectives

This project teaches:
- **IDE Plugin Architecture**: How security tools integrate with development environments
- **Smart Contract Security**: Common vulnerabilities and detection methods
- **Blockchain Integration**: Connecting traditional tools with blockchain data
- **User Experience**: Building developer-friendly security tooling

## 🌟 Next Steps

- Integrate with actual Remix IDE
- Add real-time vulnerability detection
- Implement machine learning for pattern recognition
- Build web interface for analysis results
- Add support for multiple blockchain platforms

---

Made with ❤️ for the Stacks community | 🔒 Security First | 🚀 Built for Developers
