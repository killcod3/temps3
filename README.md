# TempS3: Temporary File Storage on S3

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://github.com/killcod3/temps3/releases)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20-lightgrey.svg)](https://github.com/killcod3/temps3/releases)

A secure CLI application for temporary file storage using AWS S3 with automatic expiration, intelligent chunking, and local history tracking.


## 🌟 Key Features

### 🔒 **Security First**
- **AES-256-GCM Encryption**: All credentials encrypted using military-grade encryption
- **System Keyring Integration**: Secure credential storage with encrypted file fallback
- **Presigned URLs**: Temporary, secure access links with configurable expiration
- **No Plain Text Storage**: Zero credentials stored in plain text anywhere

### ⚡ **Performance Optimized**
- **Intelligent Multipart Uploads**: Automatic switching for files >5MB with concurrent chunk processing
- **Async I/O Throughout**: Non-blocking operations for maximum efficiency  
- **Progress Tracking**: Real-time upload progress with detailed statistics
- **Retry Logic**: Exponential backoff with configurable retry limits
- **Connection Pooling**: Optimized database connections and HTTP clients

### 🕐 **Smart File Lifecycle**
- **Automatic Expiration**: Files deleted automatically after 1, 3, or 5 days using S3 Lifecycle Policies
- **Flexible TTL Options**: Choose retention period based on your needs
- **Zero Maintenance**: No manual cleanup required, S3 handles expiration
- **Cost Optimization**: Automatic deletion reduces storage costs

### 📊 **Comprehensive Tracking**
- **Local SQLite Database**: Complete upload history with metadata
- **Search & Filter**: Find uploads by name, date, size, or status
- **Detailed Listings**: File size, upload date, expiration, and access URLs
- **Export Capabilities**: Full data export for backup or analysis

### 🌍 **Cross-Platform Ready**
- **Windows**: Native x64 binary with PowerShell installer
- **Linux**: GNU and musl (static) binaries for all distributions
- **macOS**: Build-from-source support with comprehensive documentation
- **Docker**: Static binary perfect for containerized environments

## 📦 Installation

### 🚀 **Quick Install (Recommended)**

#### Linux/Unix (One-liner)
```bash
curl -fsSL https://raw.githubusercontent.com/killcod3/temps3/main/install.sh | bash
```

#### Windows (PowerShell)
```powershell
iwr -useb https://raw.githubusercontent.com/killcod3/temps3/main/install.ps1 | iex
```

### 📥 **Manual Installation**

#### Download Pre-built Binaries
Download the latest release for your platform from [GitHub Releases](https://github.com/killcod3/temps3/releases):

| Platform | File | Notes |
|----------|------|-------|
| **Windows x64** | `temps3-v0.1.0-x86_64-pc-windows-gnu.zip` | Windows 7+ compatible |
| **Linux x64** | `temps3-v0.1.0-x86_64-unknown-linux-gnu.tar.gz` | Most Linux distributions |
| **Linux Static** | `temps3-v0.1.0-x86_64-unknown-linux-musl.tar.gz` | Alpine, Docker, embedded |

#### Verify Download Integrity
```bash
# Download checksums
curl -fsSL https://github.com/killcod3/temps3/releases/download/v0.1.0/checksums.sha256

# Verify (Linux/macOS)
sha256sum -c checksums.sha256

# Verify (Windows PowerShell)
Get-FileHash -Algorithm SHA256 temps3-v0.1.0-x86_64-pc-windows-gnu.zip
```

### 🌐 **Global Access Setup**

After installation, TempS3 should be available globally. If not:

#### Linux/macOS
```bash
# Add to your shell profile (~/.bashrc, ~/.zshrc, etc.)
export PATH="$HOME/.local/bin:$PATH"

# Reload shell
source ~/.bashrc
```

#### Windows
```powershell
# Automatic via installer, or manually add to PATH:
$env:PATH = "$env:USERPROFILE\.local\bin;$env:PATH"

# Permanent (run as administrator)
[Environment]::SetEnvironmentVariable("PATH", "$env:USERPROFILE\.local\bin;$env:PATH", "Machine")
```

## 🚀 Getting Started

### 1. **Initial Configuration**
Set up AWS credentials and create your private S3 bucket:
```bash
temps3 init
```

**Interactive Setup Process:**
1. **AWS Credentials**: Enter your Access Key ID and Secret Access Key
2. **Region Selection**: Choose your preferred AWS region (default: us-east-1)
3. **Bucket Creation**: Automatically creates a unique bucket (e.g., `temps3-e648efb2`)
4. **Permission Validation**: Verifies S3 read/write permissions
5. **Credential Storage**: Encrypts and stores credentials securely

### 2. **Upload Your First File**
```bash
# Upload with default 1-day expiration
temps3 upload document.pdf

# Upload with custom expiration
temps3 upload presentation.pptx --ttl 5d

# Upload with verbose output
temps3 upload archive.zip --ttl 3d --verbose
```

### 3. **Manage Your Uploads**
```bash
# List all uploads
temps3 list

# List with filters
temps3 list --status active --limit 20 --sort size

# Search uploads
temps3 list --search "document" --ttl 1d
```

### Basic Commands
- `temps3 config`: Initialize your configuration and AWS credentials
- `temps3 upload <file>`: Upload a file with automatic expiration
- `temps3 list`: List your upload history with filtering options
- `temps3 credentials <action>`: Manage your stored AWS credentials
- `temps3 manage <action>`: Administrative tasks (clear history, reset config)

### TTL Options
- `--ttl 1d`: 1 day expiration (24 hours) - **default**
- `--ttl 3d`: 3 days expiration (72 hours)
- `--ttl 5d`: 5 days expiration (120 hours)


For comprehensive usage examples, advanced features, troubleshooting, and AWS setup instructions, see the [**Complete Documentation**](./DOCS.md).


## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue.

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

---

TempS3 - Making temporary file storage simple, secure, and intelligent

Built with ❤️ in Rust.
