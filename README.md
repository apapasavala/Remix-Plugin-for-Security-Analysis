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

## 🏗️ Architecture

### 📁 Contract Structure
- **Security Analyses**: Core analysis data storage
- **Vulnerability Tracking**: Detailed vulnerability information
- **User Management**: Analyzer credentials and user history
- **Security Patterns**: Common vulnerability pattern database

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

### Read-Only Functions
- `get-analysis`: Retrieve analysis by ID
- `get-vulnerability`: Get specific vulnerability details
- `get-user-history`: View user's analysis history
- `calculate-overall-security-score`: Calculate composite security score

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
