#!/usr/bin/env bash
set -euo pipefail

# Detect if script is run via curl|bash
# When run via pipe, BASH_SOURCE[0] is usually /dev/fd/XX or empty
if [[ -n "${BASH_SOURCE[0]:-}" ]] && [[ -f "${BASH_SOURCE[0]}" ]] && [[ "${BASH_SOURCE[0]}" != *"/dev/fd/"* ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  RUN_VIA_CURL=0
else
  SCRIPT_DIR="/tmp"
  RUN_VIA_CURL=1
fi

# GitHub repository (can be overridden via env)
GITHUB_REPO="${GITHUB_REPO:-cleverg0d/PublicGuard}"
GITHUB_BRANCH="${GITHUB_BRANCH:-main}"
LIST_URL="${SCANNER_LIST_URL:-https://raw.githubusercontent.com/${GITHUB_REPO}/${GITHUB_BRANCH}/scanners_list.txt}"
LIST_FILE="${LIST_FILE:-${SCRIPT_DIR}/scanners_list.txt}"
LOGTAG="${LOGTAG:-SCANNER_BLOCK}"
IPSET_V4="${IPSET_V4:-scanner_block_v4}"
IPSET_V6="${IPSET_V6:-scanner_block_v6}"
CHAIN_V4="${CHAIN_V4:-SCANNER_BLOCK_V4}"
CHAIN_V6="${CHAIN_V6:-SCANNER_BLOCK_V6}"
RATE_LIMIT="${RATE_LIMIT:-10/minute}"
FLUSH_SETS=0
SYNC_LIST=0
DRY_RUN=0

usage() {
  cat <<USAGE
Usage: ${0##*/} [options]

Options:
  --sync           Download latest list from SCANNER_LIST_URL before applying
  --flush          Flush ipset contents before loading new entries
  --dry-run        Parse list and print actions without touching firewall
  --list <path>    Use alternate list file (default: ${LIST_FILE})
  -h, --help       Show this help

Environment variables:
  GITHUB_REPO        GitHub repo (user/repo, default: cleverg0d/PublicGuard)
  GITHUB_BRANCH      Branch name (default: main)
  SCANNER_LIST_URL   Override list URL (default: auto from GitHub)
  LOGTAG             Prefix used in syslog when packets are logged
  IPSET_V4/V6        ipset names for IPv4/IPv6 networks
  CHAIN_V4/V6        iptables chains injected into INPUT
  RATE_LIMIT         Log rate limit (default: 10/minute)
USAGE
}

ensure_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "[!] This script must run as root (sudo)." >&2
    exit 1
  fi
}

detect_pkg_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    PKG_MANAGER="apt-get"
    PKG_INSTALL="apt-get install -y"
  elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"
    PKG_INSTALL="yum install -y"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"
    PKG_INSTALL="dnf install -y"
  elif command -v pacman >/dev/null 2>&1; then
    PKG_MANAGER="pacman"
    PKG_INSTALL="pacman -S --noconfirm"
  elif command -v zypper >/dev/null 2>&1; then
    PKG_MANAGER="zypper"
    PKG_INSTALL="zypper install -y"
  else
    PKG_MANAGER="unknown"
    PKG_INSTALL=""
  fi
}

install_package() {
  local pkg="$1"
  if [[ "$PKG_MANAGER" == "unknown" ]]; then
    echo "[!] Cannot determine package manager. Please install $pkg manually." >&2
    return 1
  fi
  
  echo "[+] Installing $pkg..."
  if $PKG_INSTALL "$pkg" >/dev/null 2>&1; then
    echo "[+] Successfully installed $pkg"
    return 0
  else
    echo "[!] Failed to install $pkg" >&2
    return 1
  fi
}

require_cmd() {
  local cmd="$1"
  local pkg="${2:-$cmd}"
  
  if command -v "$cmd" >/dev/null 2>&1; then
    return 0
  fi
  
  echo "[!] Command '$cmd' not found. Attempting to install '$pkg'..."
  
  if [[ $EUID -ne 0 ]]; then
    echo "[!] Need root privileges to install packages. Please run with sudo." >&2
    exit 1
  fi
  
  detect_pkg_manager
  
  # Map command names to package names
  case "$pkg" in
    fail2ban-server|fail2ban)
      if ! install_package "fail2ban"; then
        return 1
      fi
      ;;
    *)
      if ! install_package "$pkg"; then
        return 1
      fi
      ;;
  esac
  
  # Verify installation
  if command -v "$cmd" >/dev/null 2>&1; then
    return 0
  fi
  
  # For fail2ban, check alternative command names
  if [[ "$pkg" == "fail2ban" ]]; then
    if command -v fail2ban-server >/dev/null 2>&1 || command -v fail2ban >/dev/null 2>&1; then
      return 0
    fi
  fi
  
  echo "[!] Failed to install $pkg. Please install it manually." >&2
  return 1
}

ensure_ipset() {
  local name="$1"; shift
  local family="$1"
  if ! ipset list "$name" >/dev/null 2>&1; then
    ipset create "$name" hash:net family "$family"
  fi
}

flush_ipset() {
  local name="$1"
  ipset flush "$name"
}

ensure_chain() {
  local table_bin="$1" chain="$2" set_name="$3" limit="$4" logtag="$5"

  if ! $table_bin -nL "$chain" >/dev/null 2>&1; then
    $table_bin -N "$chain"
  fi

  if ! $table_bin -C INPUT -j "$chain" >/dev/null 2>&1; then
    $table_bin -I INPUT 1 -j "$chain"
  fi

  if ! $table_bin -C "$chain" -m set --match-set "$set_name" src \
       -m limit --limit "$limit" -j LOG --log-prefix "$logtag " >/dev/null 2>&1; then
    $table_bin -A "$chain" -m set --match-set "$set_name" src \
      -m limit --limit "$limit" -j LOG --log-prefix "$logtag "
  fi

  if ! $table_bin -C "$chain" -m set --match-set "$set_name" src -j DROP >/dev/null 2>&1; then
    $table_bin -A "$chain" -m set --match-set "$set_name" src -j DROP
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --sync)
        SYNC_LIST=1
        shift
        ;;
      --flush)
        FLUSH_SETS=1
        shift
        ;;
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      --list)
        LIST_FILE="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "Unknown option: $1" >&2
        usage
        exit 1
        ;;
    esac
  done
}

sync_list() {
  if [[ -z "$LIST_URL" ]]; then
    echo "[!] --sync requested but SCANNER_LIST_URL not set" >&2
    exit 1
  fi
  require_cmd curl
  echo "[+] Downloading blocklist from $LIST_URL"
  curl -fsSL "$LIST_URL" -o "${LIST_FILE}.tmp"
  mv "${LIST_FILE}.tmp" "$LIST_FILE"
}

load_entries() {
  local v4_count=0
  local v6_count=0

  while IFS= read -r raw || [[ -n "$raw" ]]; do
    local line="${raw%%#*}"
    line="${line%%$'\r'}"
    # trim leading/trailing whitespace without touching internal symbols
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    if [[ -z "$line" ]]; then
      continue
    fi

    if [[ "$line" == *:* ]]; then
      ((DRY_RUN)) && echo "[dry-run] ipv6 -> $line" && { ((v6_count++)); continue; }
      ipset add "$IPSET_V6" "$line" -exist
      ((v6_count++))
    else
      ((DRY_RUN)) && echo "[dry-run] ipv4 -> $line" && { ((v4_count++)); continue; }
      ipset add "$IPSET_V4" "$line" -exist
      ((v4_count++))
    fi
  done < "$LIST_FILE"

  echo "[+] Loaded $v4_count IPv4 networks and $v6_count IPv6 networks"
}

main() {
  parse_args "$@"

  # Auto-sync if running via curl or --sync flag
  if [[ $RUN_VIA_CURL -eq 1 ]] || [[ $SYNC_LIST -eq 1 ]]; then
    if [[ -z "$LIST_URL" ]]; then
      echo "[!] Cannot determine list URL. Set SCANNER_LIST_URL or GITHUB_REPO" >&2
      exit 1
    fi
    sync_list
  fi

  if [[ ! -f "$LIST_FILE" ]]; then
    echo "[!] Blocklist file not found: $LIST_FILE" >&2
    exit 1
  fi

  if [[ $DRY_RUN -eq 1 ]]; then
    load_entries
    exit 0
  fi

  ensure_root
  
  echo "[+] Checking dependencies..."
  require_cmd iptables
  require_cmd ip6tables
  require_cmd ipset
  require_cmd curl
  
  # Check fail2ban (optional but recommended)
  if ! command -v fail2ban-server >/dev/null 2>&1 && ! command -v fail2ban >/dev/null 2>&1; then
    echo "[+] fail2ban not found. Installing fail2ban (recommended for additional protection)..."
    detect_pkg_manager
    if [[ "$PKG_MANAGER" != "unknown" ]]; then
      if install_package "fail2ban"; then
        echo "[+] fail2ban installed successfully"
      else
        echo "[!] Could not install fail2ban, continuing without it..."
      fi
    else
      echo "[!] Could not determine package manager for fail2ban, skipping..."
    fi
  else
    echo "[+] fail2ban is already installed"
  fi

  ensure_ipset "$IPSET_V4" inet
  ensure_ipset "$IPSET_V6" inet6

  if [[ $FLUSH_SETS -eq 1 ]]; then
    echo "[+] Flushing existing ipset entries"
    flush_ipset "$IPSET_V4"
    flush_ipset "$IPSET_V6"
  fi

  load_entries

  ensure_chain iptables "$CHAIN_V4" "$IPSET_V4" "$RATE_LIMIT" "$LOGTAG"
  ensure_chain ip6tables "$CHAIN_V6" "$IPSET_V6" "$RATE_LIMIT" "$LOGTAG"

  echo "[+] Rules active. Verify with: iptables -L $CHAIN_V4 -n && ip6tables -L $CHAIN_V6 -n"
}

main "$@"
