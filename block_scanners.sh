#!/usr/bin/env bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Detect if script is run via curl|bash
# When run via pipe, BASH_SOURCE[0] is usually /dev/fd/XX or empty
if [[ -n "${BASH_SOURCE[0]:-}" ]] && [[ -f "${BASH_SOURCE[0]}" ]] && [[ "${BASH_SOURCE[0]}" != *"/dev/fd/"* ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  RUN_VIA_CURL=0
else
  # Use persistent directory instead of /tmp
  SCRIPT_DIR="/var/lib/publicguard"
  RUN_VIA_CURL=1
  # Create directory if it doesn't exist
  mkdir -p "$SCRIPT_DIR" 2>/dev/null || SCRIPT_DIR="/tmp"
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

find_command() {
  local cmd="$1"
  # Try multiple methods and paths
  if command -v "$cmd" >/dev/null 2>&1; then
    command -v "$cmd"
    return 0
  fi
  
  # Check common system paths
  for path in /usr/local/sbin /usr/sbin /sbin /usr/local/bin /usr/bin /bin; do
    if [[ -x "$path/$cmd" ]]; then
      echo "$path/$cmd"
      return 0
    fi
  done
  
  return 1
}

require_cmd() {
  local cmd="$1"
  local pkg="${2:-$cmd}"
  
  # Try to find command first
  local cmd_path
  if cmd_path=$(find_command "$cmd"); then
    # Add directory to PATH if not already there
    local cmd_dir=$(dirname "$cmd_path")
    if [[ ":$PATH:" != *":$cmd_dir:"* ]]; then
      export PATH="$cmd_dir:$PATH"
    fi
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
  
  # After installation, try to find command again
  if cmd_path=$(find_command "$cmd"); then
    local cmd_dir=$(dirname "$cmd_path")
    if [[ ":$PATH:" != *":$cmd_dir:"* ]]; then
      export PATH="$cmd_dir:$PATH"
    fi
    echo "[+] Found $cmd at $cmd_path"
    return 0
  fi
  
  # For fail2ban, check alternative command names
  if [[ "$pkg" == "fail2ban" ]]; then
    if cmd_path=$(find_command "fail2ban-server") || cmd_path=$(find_command "fail2ban"); then
      local cmd_dir=$(dirname "$cmd_path")
      if [[ ":$PATH:" != *":$cmd_dir:"* ]]; then
        export PATH="$cmd_dir:$PATH"
      fi
      return 0
    fi
  fi
  
  echo "[!] Failed to find $cmd after installation. It may be installed but not in PATH." >&2
  echo "[!] Please ensure $pkg is properly installed and accessible." >&2
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

check_ssh_security() {
  echo ""
  echo "[+] Checking SSH security configuration..."
  
  local sshd_config="/etc/ssh/sshd_config"
  local issues_found=0
  
  if [[ ! -f "$sshd_config" ]]; then
    echo -e "${YELLOW}[!] SSH config file not found: $sshd_config${NC}"
    return 0
  fi
  
  # Check PermitRootLogin
  if grep -qE "^[^#]*PermitRootLogin\s+yes" "$sshd_config" 2>/dev/null; then
    echo -e "${RED}[!] SECURITY ISSUE: Root login via SSH is ENABLED${NC}"
    echo -e "${RED}    Recommendation: Set 'PermitRootLogin no' in $sshd_config${NC}"
    ((issues_found++))
  elif grep -qE "^[^#]*PermitRootLogin\s+no" "$sshd_config" 2>/dev/null; then
    echo -e "${GREEN}[+] Root login via SSH is DISABLED (secure)${NC}"
  else
    echo -e "${YELLOW}[!] PermitRootLogin not explicitly set (default may allow root login)${NC}"
    echo -e "${YELLOW}    Recommendation: Add 'PermitRootLogin no' to $sshd_config${NC}"
  fi
  
  # Check PasswordAuthentication
  if grep -qE "^[^#]*PasswordAuthentication\s+yes" "$sshd_config" 2>/dev/null; then
    echo -e "${RED}[!] SECURITY ISSUE: Password authentication is ENABLED${NC}"
    echo -e "${RED}    Recommendation: Set 'PasswordAuthentication no' and use SSH keys${NC}"
    ((issues_found++))
  elif grep -qE "^[^#]*PasswordAuthentication\s+no" "$sshd_config" 2>/dev/null; then
    echo -e "${GREEN}[+] Password authentication is DISABLED (secure, using SSH keys)${NC}"
  else
    echo -e "${YELLOW}[!] PasswordAuthentication not explicitly set (default is yes)${NC}"
    echo -e "${YELLOW}    Recommendation: Set 'PasswordAuthentication no' to $sshd_config${NC}"
  fi
  
  # Check PubkeyAuthentication
  if grep -qE "^[^#]*PubkeyAuthentication\s+no" "$sshd_config" 2>/dev/null; then
    echo -e "${RED}[!] SECURITY ISSUE: Public key authentication is DISABLED${NC}"
    echo -e "${RED}    Recommendation: Enable 'PubkeyAuthentication yes'${NC}"
    ((issues_found++))
  elif grep -qE "^[^#]*PubkeyAuthentication\s+yes" "$sshd_config" 2>/dev/null; then
    echo -e "${GREEN}[+] Public key authentication is ENABLED (secure)${NC}"
  fi
  
  if [[ $issues_found -eq 0 ]]; then
    echo -e "${GREEN}[+] SSH configuration looks secure${NC}"
  else
    echo ""
    echo -e "${RED}[!] Found $issues_found security issue(s) in SSH configuration${NC}"
    echo -e "${YELLOW}[!] After fixing, restart SSH: systemctl restart sshd${NC}"
  fi
  echo ""
}

ensure_chain() {
  local table_bin="$1" chain="$2" set_name="$3" limit="$4" logtag="$5"
  local created=0

  if ! $table_bin -nL "$chain" >/dev/null 2>&1; then
    $table_bin -N "$chain" || {
      echo "[!] Failed to create chain $chain" >&2
      return 1
    }
    created=1
  fi

  if ! $table_bin -C INPUT -j "$chain" >/dev/null 2>&1; then
    $table_bin -I INPUT 1 -j "$chain" || {
      echo "[!] Failed to add $chain to INPUT" >&2
      return 1
    }
    created=1
  fi

  if ! $table_bin -C "$chain" -m set --match-set "$set_name" src \
       -m limit --limit "$limit" -j LOG --log-prefix "$logtag " >/dev/null 2>&1; then
    $table_bin -A "$chain" -m set --match-set "$set_name" src \
      -m limit --limit "$limit" -j LOG --log-prefix "$logtag " || {
      echo "[!] Failed to add LOG rule to $chain" >&2
      return 1
    }
    created=1
  fi

  if ! $table_bin -C "$chain" -m set --match-set "$set_name" src -j DROP >/dev/null 2>&1; then
    $table_bin -A "$chain" -m set --match-set "$set_name" src -j DROP || {
      echo "[!] Failed to add DROP rule to $chain" >&2
      return 1
    }
    created=1
  fi

  if [[ $created -eq 1 ]]; then
    echo "[+] $chain configured"
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
  
  # Ensure directory exists
  mkdir -p "$(dirname "$LIST_FILE")" 2>/dev/null || true
  
  # Download to temp file first, then atomic move
  curl -fsSL "$LIST_URL" -o "${LIST_FILE}.tmp"
  if [[ -f "${LIST_FILE}.tmp" ]]; then
    mv "${LIST_FILE}.tmp" "$LIST_FILE"
  else
    echo "[!] Failed to download blocklist" >&2
    exit 1
  fi
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
      set +e
      # -exist flag prevents duplicates - silently skips if IP already exists
      ipset add "$IPSET_V6" "$line" -exist 2>/dev/null
      ipset_result=$?
      set -e
      # Count all processed entries (including existing ones - -exist doesn't error)
      ((v6_count++))
    else
      ((DRY_RUN)) && echo "[dry-run] ipv4 -> $line" && { ((v4_count++)); continue; }
      set +e
      # -exist flag prevents duplicates - silently skips if IP already exists
      ipset add "$IPSET_V4" "$line" -exist 2>/dev/null
      ipset_result=$?
      set -e
      # Count all processed entries (including existing ones - -exist doesn't error)
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
  
  # Ensure system paths are in PATH for iptables/ip6tables
  export PATH="/usr/local/sbin:/usr/sbin:/sbin:$PATH"
  
  # Find iptables location and add to PATH if needed
  for ipt_path in /sbin/iptables /usr/sbin/iptables /usr/local/sbin/iptables /bin/iptables /usr/bin/iptables; do
    if [[ -x "$ipt_path" ]]; then
      ipt_dir=$(dirname "$ipt_path")
      if [[ ":$PATH:" != *":$ipt_dir:"* ]]; then
        export PATH="$ipt_dir:$PATH"
      fi
      break
    fi
  done
  
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
  fi

  ensure_ipset "$IPSET_V4" inet
  ensure_ipset "$IPSET_V6" inet6

  if [[ $FLUSH_SETS -eq 1 ]]; then
    echo "[!] WARNING: Flushing existing ipset entries (this will remove ALL entries including custom ones)"
    echo "[!] Press Ctrl+C within 5 seconds to cancel..."
    sleep 5
    echo "[+] Flushing existing ipset entries"
    flush_ipset "$IPSET_V4"
    flush_ipset "$IPSET_V6"
  fi

  echo "[+] Loading IP addresses into ipset..."
  if ! load_entries; then
    echo "[!] Failed to load entries into ipset" >&2
    exit 1
  fi

  # Check if xt_set module is loaded (required for ipset with iptables)
  if ! lsmod | grep -q "^xt_set"; then
    echo "[+] Loading xt_set module..."
    set +e
    modprobe xt_set 2>/dev/null
    modprobe_result=$?
    set -e
    if [[ $modprobe_result -ne 0 ]]; then
      echo "[!] Warning: Could not load xt_set module. Rules may not work properly."
    fi
  fi

  set +e
  ensure_chain iptables "$CHAIN_V4" "$IPSET_V4" "$RATE_LIMIT" "$LOGTAG"
  ipv4_result=$?
  ensure_chain ip6tables "$CHAIN_V6" "$IPSET_V6" "$RATE_LIMIT" "$LOGTAG"
  ipv6_result=$?
  set -e

  if [[ $ipv4_result -eq 0 ]] && [[ $ipv6_result -eq 0 ]]; then
    echo "[+] Blocking rules active"
  else
    echo "[!] Some rules failed to apply. Check errors above."
    exit 1
  fi
  
  # Check SSH security configuration
  check_ssh_security
}

main "$@"
