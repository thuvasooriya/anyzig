#!/bin/sh
# anyzig installer
# Usage: curl -LsSf https://raw.githubusercontent.com/thuvasooriya/anyzig/main/install.sh | sh
set -eu

REPO="thuvasooriya/anyzig"
BINARY_NAME="zig"
DEFAULT_INSTALL_DIR="${HOME}/.local/bin"

# flags
VERBOSE=0
QUIET=0
NO_MODIFY_PATH=0
FORCE=0
VERSION=""
INSTALL_DIR=""

# color support
if [ -t 1 ]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  CYAN='\033[0;36m'
  BOLD='\033[1m'
  RESET='\033[0m'
else
  RED='' GREEN='' YELLOW='' CYAN='' BOLD='' RESET=''
fi

# ---- output helpers ----

info() {
  [ "$QUIET" -eq 0 ] && printf '%s\n' "$1"
}

verbose() {
  [ "$VERBOSE" -eq 1 ] && printf '  %s\n' "$1"
}

warn() {
  printf '%b[warn]%b %s\n' "$YELLOW" "$RESET" "$1" >&2
}

err() {
  printf '%b[error]%b %s\n' "$RED" "$RESET" "$1" >&2
  exit 1
}

ok() {
  [ "$QUIET" -eq 0 ] && printf '%b[ok]%b %s\n' "$GREEN" "$RESET" "$1"
}

banner() {
  [ "$QUIET" -eq 1 ] && return
  printf '\n%b  anyzig installer%b\n' "$BOLD$CYAN" "$RESET"
  printf '  https://github.com/%s\n\n' "$REPO"
}

# ---- platform detection ----

detect_os() {
  case "$(uname -s)" in
    Linux)  printf 'linux' ;;
    Darwin) printf 'macos' ;;
    *)      err "unsupported OS: $(uname -s)" ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64 | amd64)   printf 'x86_64' ;;
    aarch64 | arm64)  printf 'aarch64' ;;
    armv7* | armv6*)  printf 'arm' ;;
    arm*)             printf 'arm' ;;
    *)                err "unsupported arch: $(uname -m)" ;;
  esac
}

# ---- dependency checks ----

need_cmd() {
  if ! command -v "$1" > /dev/null 2>&1; then
    err "required command not found: $1"
  fi
}

# returns the download tool name
detect_downloader() {
  if command -v curl > /dev/null 2>&1; then
    printf 'curl'
  elif command -v wget > /dev/null 2>&1; then
    printf 'wget'
  else
    err "neither curl nor wget found; install one and retry"
  fi
}

# ---- network ----

download() {
  local url="$1"
  local dest="$2"
  local downloader
  downloader="$(detect_downloader)"
  verbose "downloading: $url"
  if [ "$downloader" = "curl" ]; then
    if [ "$QUIET" -eq 1 ]; then
      curl -LsSf -o "$dest" "$url"
    else
      curl -LSf --progress-bar -o "$dest" "$url"
    fi
  else
    if [ "$QUIET" -eq 1 ]; then
      wget -q -O "$dest" "$url"
    else
      wget -O "$dest" "$url"
    fi
  fi
}

# fetch raw text (for API/redirect)
fetch_text() {
  local url="$1"
  local downloader
  downloader="$(detect_downloader)"
  if [ "$downloader" = "curl" ]; then
    curl -LsSf "$url"
  else
    wget -qO- "$url"
  fi
}

resolve_version() {
  if [ -n "$VERSION" ]; then
    printf '%s' "$VERSION"
    return
  fi
  verbose "querying GitHub API for latest release"
  local api_url="https://api.github.com/repos/${REPO}/releases/latest"
  local tag
  tag="$(fetch_text "$api_url" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
  if [ -z "$tag" ]; then
    err "could not determine latest release tag from GitHub API"
  fi
  printf '%s' "$tag"
}

# ---- install ----

install_anyzig() {
  local os arch tag archive_name download_url tmpdir archive dest

  os="$(detect_os)"
  arch="$(detect_arch)"
  tag="$(resolve_version)"

  info "installing anyzig ${BOLD}${tag}${RESET} for ${arch}-${os}"

  archive_name="anyzig-${arch}-${os}.tar.gz"
  download_url="https://github.com/${REPO}/releases/download/${tag}/${archive_name}"

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT INT TERM

  archive="${tmpdir}/${archive_name}"
  info "downloading ${archive_name} ..."
  download "$download_url" "$archive"

  verbose "extracting archive"
  tar -xzf "$archive" -C "$tmpdir"

  # find the zig binary (may be at root or in a subdirectory)
  local extracted_bin
  extracted_bin="$(find "$tmpdir" -maxdepth 2 -name "$BINARY_NAME" -not -name "*.tar.gz" | head -1)"
  if [ -z "$extracted_bin" ]; then
    err "could not find '$BINARY_NAME' binary in extracted archive"
  fi

  local install_dir="${INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"
  dest="${install_dir}/${BINARY_NAME}"

  verbose "install dir: $install_dir"
  mkdir -p "$install_dir"

  if [ -f "$dest" ] && [ "$FORCE" -eq 0 ]; then
    verbose "backing up existing binary to ${dest}.bak"
    cp "$dest" "${dest}.bak"
  fi

  cp "$extracted_bin" "$dest"
  chmod +x "$dest"

  ok "installed to ${dest}"
}

# ---- PATH management ----

in_path() {
  local dir="$1"
  case ":${PATH}:" in
    *":${dir}:"*) return 0 ;;
    *)            return 1 ;;
  esac
}

detect_shell() {
  local shell_name
  shell_name="$(basename "${SHELL:-sh}")"
  printf '%s' "$shell_name"
}

shell_profile() {
  local sh="$1"
  local home="${HOME}"
  case "$sh" in
    zsh)  printf '%s/.zshrc' "$home" ;;
    bash) printf '%s/.bashrc' "$home" ;;
    fish) printf '%s/.config/fish/config.fish' "$home" ;;
    *)    printf '%s/.profile' "$home" ;;
  esac
}

path_export_line() {
  local dir="$1"
  local sh="$2"
  case "$sh" in
    fish) printf 'fish_add_path "%s"\n' "$dir" ;;
    *)    printf 'export PATH="%s:$PATH"\n' "$dir" ;;
  esac
}

manage_path() {
  local install_dir="${INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"

  if in_path "$install_dir"; then
    verbose "$install_dir already in PATH"
    return
  fi

  if [ "$NO_MODIFY_PATH" -eq 1 ]; then
    warn "$install_dir is not in PATH"
    info "add it manually:"
    info "  export PATH=\"${install_dir}:\$PATH\""
    return
  fi

  local sh profile export_line
  sh="$(detect_shell)"
  profile="$(shell_profile "$sh")"
  export_line="$(path_export_line "$install_dir" "$sh")"

  # write to profile
  if [ -f "$profile" ] || [ "$sh" = "fish" ]; then
    printf '\n# added by anyzig installer\n%s\n' "$export_line" >> "$profile"
    ok "added $install_dir to PATH in $profile"
    info "restart your shell or run:  source $profile"
  else
    warn "could not determine shell profile; add manually:"
    info "  $export_line"
  fi
}

# ---- verify ----

verify_install() {
  local dest="${INSTALL_DIR:-$DEFAULT_INSTALL_DIR}/${BINARY_NAME}"
  if ! "$dest" any version > /dev/null 2>&1; then
    warn "verification failed: '$dest any version' did not succeed"
    return
  fi
  local ver
  ver="$("$dest" any version 2>/dev/null | head -1)"
  ok "verified: $ver"
}

# ---- usage ----

usage() {
  cat <<EOF
anyzig installer

USAGE:
  install.sh [OPTIONS]

OPTIONS:
  -h, --help              show this help
  -v, --verbose           detailed output
  -q, --quiet             minimal output
  --version VERSION       install specific release tag (e.g. v0.1.0)
  --install-dir DIR       install directory (default: \$HOME/.local/bin)
  --no-modify-path        skip shell profile PATH modification
  --force                 reinstall even if already present

ENVIRONMENT:
  ANYZIG_VERSION          install specific version (same as --version)
  ANYZIG_INSTALL_DIR      install directory (same as --install-dir)

EXAMPLES:
  curl -LsSf https://raw.githubusercontent.com/thuvasooriya/anyzig/main/install.sh | sh
  curl -LsSf .../install.sh | sh -s -- --version v0.2.0
  ANYZIG_INSTALL_DIR=/usr/local/bin sh install.sh
EOF
}

# ---- arg parsing ----

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -h|--help)           usage; exit 0 ;;
      -v|--verbose)        VERBOSE=1 ;;
      -q|--quiet)          QUIET=1 ;;
      --version)           shift; VERSION="${1:-}" ;;
      --install-dir)       shift; INSTALL_DIR="${1:-}" ;;
      --no-modify-path)    NO_MODIFY_PATH=1 ;;
      --force)             FORCE=1 ;;
      *)                   err "unknown option: $1" ;;
    esac
    shift
  done

  # env var overrides (lower precedence than flags if already set)
  : "${VERSION:=${ANYZIG_VERSION:-}}"
  : "${INSTALL_DIR:=${ANYZIG_INSTALL_DIR:-}}"
}

# ---- main ----

main() {
  parse_args "$@"

  banner

  need_cmd uname
  need_cmd tar
  need_cmd mktemp
  need_cmd chmod
  need_cmd mkdir
  need_cmd cp
  detect_downloader > /dev/null  # early check

  install_anyzig
  manage_path
  verify_install

  info ""
  info "run '${BOLD}zig any help${RESET}' to get started"
}

main "$@"
