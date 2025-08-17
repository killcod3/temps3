# TempS3 Complete Documentation

## Table of Contents

1. [Overview](#overview)
2. [Installation Guide](#installation-guide)
3. [Configuration](#configuration)
4. [Command Reference](#command-reference)
5. [Advanced Usage Patterns](#advanced-usage-patterns)
6. [AWS Setup & IAM Policies](#aws-setup--iam-policies)
7. [Troubleshooting](#troubleshooting)

---

## Overview

### What is TempS3?

TempS3 is a command-line tool for secure temporary file storage using AWS S3. It's designed for developers, system administrators, and organizations that need reliable, secure, and automated temporary file storage with automatic cleanup.

### Key Capabilities

- **Secure Storage**: Military-grade AES-256-GCM encryption for credentials
- **Automatic Expiration**: S3 Lifecycle Policies for automatic file deletion
- **Intelligent Uploads**: Multipart uploads with concurrent processing for large files
- **Comprehensive Tracking**: SQLite database with full upload history and metadata
- **Cross-Platform**: Native binaries for Windows, Linux, and macOS
- **Production Ready**: Robust error handling, retry logic, and logging

### Use Cases

- **DevOps**: Temporary storage for build artifacts, deployment packages
- **Data Transfer**: Secure file sharing between teams or systems  
- **Backup Solutions**: Short-term backup storage with automatic cleanup
- **CI/CD Pipelines**: Artifact storage during build and deployment processes
- **Development**: Temporary storage for large files during development cycles

---

## Installation Guide

### System Requirements

| Component | Requirement |
|-----------|-------------|
| **Operating System** | Windows 7+, Linux (glibc 2.17+), macOS 10.12+ |
| **Memory** | 100MB RAM (500MB during large uploads) |
| **Disk Space** | 50MB free space |
| **Network** | Internet connection for AWS S3 access |
| **Architecture** | x86_64 (64-bit) |

### AWS Requirements
- Valid AWS account with billing enabled
- S3 service access in your chosen region
- IAM permissions for S3 bucket operations (see [AWS Setup](#aws-setup--iam-policies))

### Installation Methods

#### Method 1: Automated Installer (Recommended)

##### Linux/Unix Systems
```bash
# Download and run installer
curl -fsSL https://raw.githubusercontent.com/killcod3/temps3/main/install.sh | bash

# Verify installation
temps3 --version
```

##### Windows Systems
```powershell
# Run in PowerShell (as user, not admin)
iwr -useb https://raw.githubusercontent.com/killcod3/temps3/main/install.ps1 | iex

# Verify installation
temps3 --version
```

#### Method 2: Manual Download

Download the latest release for your platform from [GitHub Releases](https://github.com/killcod3/temps3/releases):

| Platform | File |
|----------|------|
| **Windows x64** | `temps3-v0.1.0-x86_64-pc-windows-gnu.zip` |
| **Linux x64** | `temps3-v0.1.0-x86_64-unknown-linux-gnu.tar.gz` |
| **Linux Static** | `temps3-v0.1.0-x86_64-unknown-linux-musl.tar.gz` |

#### Method 3: Build from Source

```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Clone and build
git clone https://github.com/killcod3/temps3.git
cd temps3
cargo build --release

# Install globally (optional)
sudo cp target/release/temps3 /usr/local/bin/
```

---

## Configuration

### Initial Setup

#### Step 1: Initialize TempS3
```bash
temps3 init
```

This interactive command will:
1. **Collect AWS Credentials**: Access Key ID, Secret Access Key, Region
2. **Validate Credentials**: Test S3 access permissions
3. **Create S3 Bucket**: Generate unique bucket name (e.g., `temps3-e648efb2`)
4. **Setup Lifecycle Rules**: Configure automatic file expiration
5. **Store Credentials Securely**: Encrypt and store using system keyring
6. **Initialize Database**: Create local SQLite database for tracking

#### Step 2: Verify Configuration
```bash
# Check credentials and permissions
temps3 config --check-credentials

# Test with a small upload
echo "test" > test.txt
temps3 upload test.txt --ttl 1d
temps3 list
```

### Configuration Files

#### Primary Config File
**Location:** `~/.config/temps3/config.yml` (Linux/macOS) or `%APPDATA%\temps3\config.yml` (Windows)

```yaml
# AWS Configuration
aws_region: "us-east-1"                    # AWS region for S3 operations
bucket_name: "temps3-e648efb2"             # Your unique S3 bucket name

# URL Configuration  
presigned_url_expiry_days: 7               # Max URL validity (AWS limit: 7 days)

# Upload Configuration
chunk_size_mb: 5                           # Multipart upload chunk size
max_concurrent_uploads: 10                 # Concurrent chunks for multipart uploads
max_retries: 3                             # Retry attempts for failed operations
base_retry_delay_ms: 1000                  # Base delay between retries (exponential backoff)

# Storage Configuration
database_path: "/home/user/.config/temps3/temps3.db"  # Local SQLite database

# Logging
log_level: "warn"                          # Log level: error, warn, info, debug, trace
```

#### Other Configuration Files
- `credentials.enc`: Encrypted AWS credentials
- `encryption.key`: Encryption key for credentials (44 bytes)
- `state.yml`: Application state information
- `temps3.db`: SQLite database with upload history
- `config.yml.backup`: Automatic backup of configuration

---

## Command Reference

### Global Options
```bash
-h, --help       Show help information
-V, --version    Show version information
```

### Core Commands

#### `temps3 init`
Initialize credentials and bucket configuration (interactive setup).

```bash
temps3 init
```

#### `temps3 upload`
Upload files to S3 with automatic expiration.

```bash
temps3 upload [OPTIONS] <FILE_PATH>
```

**Arguments:**
- `<FILE_PATH>`: Path to the file to upload

**Options:**
- `--ttl <TTL>`: Time-to-live (1d, 3d, 5d) [default: 1d]
- `-v, --verbose`: Enable verbose output with detailed progress and timing

**Examples:**
```bash
# Basic upload (1-day expiration)
temps3 upload document.pdf

# Upload with 3-day expiration
temps3 upload presentation.pptx --ttl 3d

# Upload large file with verbose output
temps3 upload backup.tar.gz --ttl 5d --verbose
```

**Output Example:**
```
📁 File: document.pdf
⏱️  TTL: 3d
🔑 S3 Key: temps3/2025/08/17/132931/d3045036-707a-473f-aacf-84d628f72ea3-document.pdf
⬆️  Uploading file...
########################################       1/1       Upload complete

✅ Upload successful!

📊 File size: 2.4 MB
🏷️  TTL: 3d (expires in 3 days)
🔗 Download URL: https://temps3-bucket.s3.amazonaws.com/...
⏰ URL expires: 2025-08-24 13:29:32 UTC
🆔 Upload ID: d37e6a7f-f6d2-4440-aba8-9793c8185a87
🔐 Checksum: a1fff0ffefb9eace7230c24e50731f0a91c62f9cefdfe77121c2f607125dffae
```

#### `temps3 list`
Display and filter uploaded files with comprehensive options.

```bash
temps3 list [OPTIONS]
```

**Options:**
- `--ttl <TTL>`: Filter by TTL duration (1d, 3d, 5d)
- `--status <STATUS>`: Filter by status (active, expired, all) [default: all]
- `--limit <LIMIT>`: Number of results per page [default: 10]
- `--page <PAGE>`: Page number (starting from 1) [default: 1]
- `--sort <SORT>`: Sort by (date, size, name, expiry) [default: date]
- `--order <ORDER>`: Sort order (asc, desc) [default: desc]
- `--search <SEARCH>`: Search pattern in file names
- `-v, --verbose`: Show detailed information for each upload

**Examples:**
```bash
# List recent uploads (default: 10 most recent)
temps3 list

# List active files only
temps3 list --status active

# Search for specific files
temps3 list --search "backup"

# Pagination and sorting
temps3 list --page 2 --limit 20 --sort size --order asc

# Complex query
temps3 list --search "document" --status active --sort name --order asc --limit 10
```

#### `temps3 config`
Manage configuration settings.

```bash
temps3 config [OPTIONS]
```

**Options:**
- `--check-credentials`: Check credential validity and S3 permissions

#### `temps3 credentials`
Credential management operations.

```bash
temps3 credentials <SUBCOMMAND>
```

**Subcommands:**
- `update [--skip-validation]`: Update stored AWS credentials
- `test`: Test current credentials and show detailed status
- `remove`: Remove stored credentials (with confirmation prompt)

#### `temps3 manage`
Database and bucket management operations.

```bash
temps3 manage <SUBCOMMAND>
```

**Subcommands:**
- `purge-database`: Purge all entries from the local SQLite database
- `empty-bucket`: Empty the S3 bucket and mark all local entries as expired

---

## Advanced Usage Patterns

### Automation & Scripting

```bash
#!/bin/bash
# Backup script example

# Create timestamped backup
backup_file="backup-$(date +%Y%m%d-%H%M%S).tar.gz"
tar -czf "$backup_file" /important/data

# Upload with 5-day retention and capture output
upload_output=$(temps3 upload "$backup_file" --ttl 5d)

# Extract download URL from output
download_url=$(echo "$upload_output" | grep "🔗 Download URL:" | awk '{print $4}')

# Log the URL for recovery
echo "$(date): Backup available at: $download_url" >> backup-recovery-log.txt

# Clean local backup file
rm "$backup_file"

echo "Backup completed and uploaded to S3"
```

### Batch Operations

```bash
# Upload multiple files with same TTL
for file in *.pdf; do
    echo "Uploading: $file"
    temps3 upload "$file" --ttl 3d
done

# Upload entire directory as archive
tar -czf "project-$(date +%Y%m%d).tar.gz" /path/to/project
temps3 upload "project-$(date +%Y%m%d).tar.gz" --ttl 5d --verbose

# Conditional uploads with error handling
for file in *.backup; do
    if [[ -f "$file" && -s "$file" ]]; then
        if temps3 upload "$file" --ttl 5d; then
            echo "✅ Uploaded: $file"
            rm "$file"  # Remove local file after successful upload
        else
            echo "❌ Failed to upload: $file"
        fi
    fi
done
```

### Integration Examples

#### CI/CD Pipeline (GitHub Actions)
```yaml
name: Deploy and Upload Artifacts
jobs:
  build:
    steps:
      - name: Build application
        run: cargo build --release
        
      - name: Upload build artifacts to TempS3
        run: |
          temps3 upload target/release/myapp --ttl 5d --verbose
          echo "Build artifact uploaded for 5 days"
          
      - name: List recent uploads
        run: temps3 list --limit 1 --verbose
```

#### Database Backup Script
```bash
#!/bin/bash
# PostgreSQL backup to TempS3

DB_NAME="production_db"
BACKUP_FILE="$DB_NAME-$(date +%Y%m%d_%H%M%S).sql.gz"

# Create compressed backup
pg_dump "$DB_NAME" | gzip > "$BACKUP_FILE"

# Upload with 5-day retention
if temps3 upload "$BACKUP_FILE" --ttl 5d --verbose; then
    echo "✅ Database backup uploaded successfully"
    rm "$BACKUP_FILE"  # Clean local file
else
    echo "❌ Backup upload failed - keeping local file"
fi
```

---

## AWS Setup & IAM Policies

### Required AWS Permissions

#### Minimum IAM Policy
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "TempS3BucketAccess",
            "Effect": "Allow",
            "Action": [
                "s3:CreateBucket",
                "s3:DeleteBucket",
                "s3:GetBucketLocation",
                "s3:GetBucketVersioning",
                "s3:ListBucket",
                "s3:GetBucketLifecycle",
                "s3:PutBucketLifecycle",
                "s3:DeleteBucketLifecycle"
            ],
            "Resource": "arn:aws:s3:::temps3-*"
        },
        {
            "Sid": "TempS3ObjectAccess",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:GetObjectVersion",
                "s3:ListMultipartUploadParts",
                "s3:AbortMultipartUpload",
                "s3:CreateMultipartUpload",
                "s3:CompleteMultipartUpload"
            ],
            "Resource": "arn:aws:s3:::temps3-*/*"
        }
    ]
}
```

### IAM User Creation

#### Step 1: Create IAM User
1. **AWS Console**: Navigate to IAM → Users → Create User
2. **Username**: Choose a descriptive name (e.g., `temps3-cli-user`)
3. **Access Type**: Select "Programmatic access"
4. **Permissions**: Attach the TempS3 policy created above or select s3 permissions from menu

#### Step 2: Generate Access Keys
1. **After user creation**, go to Security Credentials tab
2. **Create Access Key** → Choose "CLI, SDK, & API access"
3. **Download CSV** or copy the Access Key ID and Secret Access Key
4. **Store Securely**: Never commit these to version control

#### Step 3: Test Permissions
```bash
# Test with TempS3
temps3 init
# Enter the credentials when prompted
temps3 config --check-credentials
```

### Bucket Configuration

TempS3 automatically creates and configures buckets with:
- **Unique naming**: `temps3-{8-character-uuid}`
- **Public access blocking**: All public access blocked by default
- **Lifecycle policies**: Automatic expiration rules for each TTL
- **Versioning**: Disabled (not needed for temporary storage)

### Security Best Practices

1. **Rotate Keys Regularly**: Change access keys every 90 days
2. **Use IAM Roles**: When running on EC2, use IAM roles instead of keys
3. **Monitor Usage**: Enable CloudTrail logging for S3 operations
4. **Least Privilege**: Use the minimum required permissions

---

## Troubleshooting

### Common Issues

#### Initialization Problems
```bash
# If temps3 init fails
temps3 credentials test

# Check if configuration directory exists
ls -la ~/.config/temps3/

# Re-initialize if needed
rm -rf ~/.config/temps3/
temps3 init
```

#### Upload Failures
```bash
# Test with verbose mode for detailed error information
temps3 upload problem-file.txt --verbose

# Check available disk space and file permissions
ls -la problem-file.txt
df -h

# Verify credentials and S3 access
temps3 config --check-credentials
```

#### List Command Issues
```bash
# If list shows no results but you have uploads
temps3 list --status all --limit 50

# Check database directly
ls -la ~/.config/temps3/temps3.db

# Verify specific upload by search
temps3 list --search "filename" --verbose
```

### Debug Mode
```bash
# Enable debug logging for detailed troubleshooting
RUST_LOG=debug temps3 upload file.txt

# Maximum verbosity for development
RUST_LOG=trace temps3 config --check-credentials

# Check log level in configuration
cat ~/.config/temps3/config.yml | grep log_level
```

### Getting Help
- **GitHub Issues**: [Report bugs or request features](https://github.com/killcod3/temps3/issues)
- **Documentation**: [Comprehensive docs](https://github.com/killcod3/temps3#readme)

---

*This documentation is maintained alongside the TempS3 codebase. For the latest updates, see the [GitHub repository](https://github.com/killcod3/temps3).*
