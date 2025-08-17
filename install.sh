#!/bin/bash
# TempS3 Installer Script for Linux/macOS
# Usage: curl -fsSL https://raw.githubusercontent.com/yourusername/temps3/main/install.sh | bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO="killcod3/temps3"
VERSION="v0.1.0"
INSTALL_DIR="$HOME/.local/bin"

# Detect platform
detect_platform() {
    local platform
    case "$(uname -s)" in
        Linux*)
            case "$(uname -m)" in
                x86_64) platform="x86_64-unknown-linux-gnu" ;;
                *) echo -e "${RED}Unsupported architecture: $(uname -m)${NC}" >&2; exit 1 ;;
            esac
            ;;
        Darwin*)
            echo -e "${YELLOW}macOS detected. Pre-built binaries are not available.${NC}"
            echo -e "${BLUE}Please build from source using: cargo install --git https://github.com/$REPO${NC}"
            exit 1
            ;;
        *)
            echo -e "${RED}Unsupported platform: $(uname -s)${NC}" >&2
            exit 1
            ;;
    esac
    echo $platform
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Download and install
install_temps3() {
    local platform=$(detect_platform)
    local archive="temps3-$VERSION-$platform.tar.gz"
    local url="https://github.com/$REPO/releases/download/$VERSION/$archive"
    
    echo -e "${BLUE}🚀 Installing TempS3 $VERSION for $platform${NC}"
    
    # Create install directory
    mkdir -p "$INSTALL_DIR"
    
    # Create temporary directory
    local tmp_dir=$(mktemp -d)
    cd "$tmp_dir"
    
    echo -e "${BLUE}📥 Downloading $archive${NC}"
    if command_exists curl; then
        curl -fsSL "$url" -o "$archive"
    elif command_exists wget; then
        wget -q "$url" -O "$archive"
    else
        echo -e "${RED}❌ Neither curl nor wget found. Please install one of them.${NC}" >&2
        exit 1
    fi
    
    echo -e "${BLUE}📦 Extracting archive${NC}"
    tar -xzf "$archive"
    
    echo -e "${BLUE}📂 Installing to $INSTALL_DIR${NC}"
    cp temps3 "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/temps3"
    
    # Cleanup
    cd - >/dev/null
    rm -rf "$tmp_dir"
    
    echo -e "${GREEN}✅ TempS3 installed successfully!${NC}"
    
    # Check if install directory is in PATH
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        echo -e "${YELLOW}⚠️  $INSTALL_DIR is not in your PATH${NC}"
        echo -e "${BLUE}Add this line to your shell profile (~/.bashrc, ~/.zshrc, etc.):${NC}"
        echo -e "${GREEN}export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
        echo
        echo -e "${BLUE}Then restart your terminal or run: source ~/.bashrc${NC}"
    fi
    
    echo
    echo -e "${GREEN}🎉 Installation complete!${NC}"
    echo -e "${BLUE}Run 'temps3 config' to get started.${NC}"
}

# Main execution
main() {
    echo -e "${BLUE}TempS3 Installer${NC}"
    echo
    
    # Check for dependencies
    if ! command_exists tar; then
        echo -e "${RED}❌ tar is required but not installed${NC}" >&2
        exit 1
    fi
    
    # Confirm installation
    read -p "Install TempS3 to $INSTALL_DIR? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Installation cancelled${NC}"
        exit 0
    fi
    
    install_temps3
}

# Run main function
main "$@"
