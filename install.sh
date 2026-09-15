#!/bin/sh
# Installation script for bnmap
# Usage: curl -sSL https://raw.githubusercontent.com/apirrone/better_nmap/main/install.sh | sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Repository information
REPO="apirrone/better_nmap"
BINARY_NAME="bnmap"

# Print colored output
print_info() {
    printf "${GREEN}[INFO]${NC} %s\n" "$1"
}

print_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1"
}

print_warning() {
    printf "${YELLOW}[WARNING]${NC} %s\n" "$1"
}

# Detect platform
detect_platform() {
    local os
    local arch
    local platform

    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux*)
            case "$arch" in
                x86_64)
                    platform="linux-x86_64"
                    ;;
                aarch64|arm64)
                    platform="linux-aarch64"
                    ;;
                armv7l|armv7*)
                    platform="linux-armv7"
                    ;;
                *)
                    print_error "Unsupported architecture: $arch"
                    exit 1
                    ;;
            esac
            ;;
        Darwin*)
            case "$arch" in
                arm64|aarch64)
                    platform="macos-aarch64"
                    ;;
                x86_64)
                    platform="macos-x86_64"
                    ;;
                *)
                    print_error "Unsupported architecture: $arch"
                    exit 1
                    ;;
            esac
            ;;
        *)
            print_error "Unsupported operating system: $os"
            exit 1
            ;;
    esac

    echo "$platform"
}

# Get the latest release version
get_latest_version() {
    curl -sSL "https://api.github.com/repos/$REPO/releases/latest" | \
        grep '"tag_name":' | \
        sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
}

# Download and install
install_bnmap() {
    local platform
    local version
    local download_url
    local install_dir
    local temp_dir

    print_info "Detecting platform..."
    platform=$(detect_platform)
    print_info "Detected platform: $platform"

    print_info "Fetching latest release..."
    version=$(get_latest_version)

    if [ -z "$version" ]; then
        print_error "Failed to fetch latest version"
        exit 1
    fi

    print_info "Latest version: $version"

    # Construct download URL
    download_url="https://github.com/$REPO/releases/download/$version/$BINARY_NAME-$platform.tar.gz"

    # Create temporary directory
    temp_dir=$(mktemp -d)
    trap "rm -rf $temp_dir" EXIT

    print_info "Downloading $BINARY_NAME $version for $platform..."
    if ! curl -sSL "$download_url" -o "$temp_dir/$BINARY_NAME.tar.gz"; then
        print_error "Failed to download $BINARY_NAME"
        print_error "URL: $download_url"
        exit 1
    fi

    print_info "Extracting archive..."
    tar xzf "$temp_dir/$BINARY_NAME.tar.gz" -C "$temp_dir"

    # Determine installation directory
    if [ -w "/usr/local/bin" ]; then
        install_dir="/usr/local/bin"
    elif [ -d "$HOME/.local/bin" ]; then
        install_dir="$HOME/.local/bin"
        mkdir -p "$install_dir"
    else
        install_dir="$HOME/.local/bin"
        mkdir -p "$install_dir"
    fi

    print_info "Installing to $install_dir/$BINARY_NAME..."

    # Check if we need sudo
    if [ -w "$install_dir" ]; then
        mv "$temp_dir/$BINARY_NAME-$platform" "$install_dir/$BINARY_NAME"
        chmod +x "$install_dir/$BINARY_NAME"
    else
        print_warning "Need elevated privileges to install to $install_dir"
        sudo mv "$temp_dir/$BINARY_NAME-$platform" "$install_dir/$BINARY_NAME"
        sudo chmod +x "$install_dir/$BINARY_NAME"
    fi

    print_info "Installation complete!"

    # Check if install_dir is in PATH
    case ":$PATH:" in
        *":$install_dir:"*)
            ;;
        *)
            print_warning "$install_dir is not in your PATH"
            print_warning "Add it to your PATH by adding this line to your shell profile:"
            print_warning "  export PATH=\"\$PATH:$install_dir\""
            ;;
    esac

    # Verify installation
    if command -v "$BINARY_NAME" >/dev/null 2>&1; then
        print_info "Verification successful: $($BINARY_NAME --version 2>/dev/null || echo 'bnmap installed')"
        print_info ""
        print_info "Run '$BINARY_NAME --help' to get started!"
    else
        print_warning "Installation succeeded but $BINARY_NAME is not in PATH"
        print_info "You can run it directly: $install_dir/$BINARY_NAME"
    fi
}

# Main
main() {
    print_info "Installing $BINARY_NAME..."
    echo ""

    # Check for required commands
    for cmd in curl tar; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            print_error "Required command not found: $cmd"
            exit 1
        fi
    done

    install_bnmap
}

main
