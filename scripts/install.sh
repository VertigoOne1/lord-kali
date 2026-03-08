#!/usr/bin/env bash
set -euo pipefail

REPO="https://github.com/insidewhy/lord-kali.git"
PREFIX="${HOME}/.local/bin"

install_rustc() {
  if command -v rustc &>/dev/null; then
    return 0
  fi

  echo "rustc is not installed."

  if [[ "$(uname)" == "Darwin" ]]; then
    if command -v brew &>/dev/null; then
      read -rp "Install rust via brew? [Y/n] " answer
      if [[ "${answer,,}" != "n" ]]; then
        brew install rust
        return 0
      fi
    fi
  elif [[ -f /etc/os-release ]]; then
    . /etc/os-release
    case "${ID:-}" in
      arch|manjaro|endeavouros|garuda)
        read -rp "Install rust via pacman? [Y/n] " answer
        if [[ "${answer,,}" != "n" ]]; then
          sudo pacman -S --needed rust
          return 0
        fi
        ;;
      ubuntu|debian|linuxmint|pop)
        read -rp "Install rust via rustup (recommended for Debian-based)? [Y/n] " answer
        if [[ "${answer,,}" != "n" ]]; then
          curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
          source "${HOME}/.cargo/env"
          return 0
        fi
        ;;
      fedora)
        read -rp "Install rust via dnf? [Y/n] " answer
        if [[ "${answer,,}" != "n" ]]; then
          sudo dnf install rust cargo
          return 0
        fi
        ;;
      opensuse*|sles)
        read -rp "Install rust via zypper? [Y/n] " answer
        if [[ "${answer,,}" != "n" ]]; then
          sudo zypper install rust cargo
          return 0
        fi
        ;;
      alpine)
        read -rp "Install rust via apk? [Y/n] " answer
        if [[ "${answer,,}" != "n" ]]; then
          sudo apk add rust cargo
          return 0
        fi
        ;;
      void)
        read -rp "Install rust via xbps? [Y/n] " answer
        if [[ "${answer,,}" != "n" ]]; then
          sudo xbps-install -S rust cargo
          return 0
        fi
        ;;
    esac
  fi

  echo "Please install rustc and cargo, then re-run this script."
  echo "Visit https://rustup.rs for installation instructions."
  exit 1
}

install_rustc

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "Cloning lord-kali..."
git clone --depth 1 "$REPO" "$TMPDIR/lord-kali"

echo "Building..."
cd "$TMPDIR/lord-kali"
cargo build --release

echo "Installing to ${PREFIX}..."
mkdir -p "$PREFIX"
cp target/release/lord-kali "$PREFIX/lord-kali"

echo ""
echo "Installed lord-kali to ${PREFIX}/lord-kali"

if [[ ":$PATH:" != *":${PREFIX}:"* ]]; then
  echo "Warning: ${PREFIX} is not in your PATH. Add it to your shell profile."
fi
