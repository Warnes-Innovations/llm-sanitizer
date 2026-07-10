#!/usr/bin/env bash
# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# install-deps.sh — install every system and Python dependency required for
# llm-sanitizer's archive and document extraction features, on macOS and Linux.
#
# Installs:
#   System : libarchive        — shared library backing libarchive-c (RAR 3/4/5)
#   Python : filetype         — magic-byte type detection for all files (Tier 1)
#            pypdf             — PDF structural validation (Tier 2)
#            py7zr             — 7z archives (pure Python)
#            libarchive-c      — RAR 3/4/5 via libarchive (BSD-licensed binding)
#            olefile           — legacy OLE2 .doc/.ppt/.xls text fallback
#            markitdown        — primary document→text engine
#            mammoth           — .docx
#            python-pptx       — .pptx
#            openpyxl          — .xlsx
#            xlrd              — legacy .xls
#            pdfminer.six      — .pdf
#            striprtf          — .rtf (optional but tiny)
#   Audit  : semgrep           — static code auditor for agent-tool scripts
#                                (Flow-Guard supply-chain "surface B"; LGPL-2.1)
#   Dev    : mypy              — strict static type checking (skip with --no-dev)
#
# Stdlib archive formats (ZIP, TAR, TAR.GZ, TAR.BZ2, TAR.XZ) need NO install.
#
# Usage:
#   bash scripts/install-deps.sh [options]
#
# Options:
#   --python PATH    Python interpreter to install into (default: python3)
#   --no-system      Skip the system-library (libarchive) step
#   --no-python      Skip the Python-package step
#   --no-dev         Skip dev/type-check tooling (mypy)
#   --editable       Also `pip install -e .` the repo (editable/develop install)
#   --install        Also `pip install .` the repo (non-editable install);
#                    mutually exclusive with --editable
#   --yes            Assume "yes" for the pre-install confirmation prompt
#   -h, --help       Show this help and exit
#
# Notes:
#   * Run this inside the virtualenv you want the packages in (or let `uv`
#     discover the project's .venv). Without a venv, pip installs with --user.
#   * The system-library step may prompt for sudo.
#   * RUN this script — do not `source` it. Sourcing runs it in your current
#     shell (leaking `set -euo pipefail`) and breaks path detection under zsh.
#         bash scripts/install-deps.sh      # correct
#         . ./scripts/install-deps.sh       # WRONG (sourced)

# Refuse sourcing (bash + zsh) before `set -u` can error on an interactive shell.
if [ -n "${ZSH_VERSION:-}" ]; then
  case "${ZSH_EVAL_CONTEXT:-}" in (*:file*) _fg_sourced=1 ;; (*) _fg_sourced=0 ;; esac
elif [ -n "${BASH_VERSION:-}" ]; then
  if [ "${BASH_SOURCE[0]:-}" != "${0}" ]; then _fg_sourced=1; else _fg_sourced=0; fi
else
  _fg_sourced=0
fi
if [ "${_fg_sourced}" = 1 ]; then
  printf 'install-deps.sh must be run, not sourced. Use:\n    bash scripts/install-deps.sh\n' >&2
  # shellcheck disable=SC2317  # `exit` is reached when executed; `return` only succeeds when sourced
  return 1 2>/dev/null || exit 1
fi

set -euo pipefail

# ---------------------------------------------------------------------------
# Output helpers (color only when stdout is a TTY)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'
else
  C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""
fi
info()  { printf '%s==>%s %s\n' "$C_BLUE"   "$C_RESET" "$*"; }
ok()    { printf '%s  ✓%s %s\n' "$C_GREEN"  "$C_RESET" "$*"; }
warn()  { printf '%s  !%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()   { printf '%s  ✗%s %s\n' "$C_RED"    "$C_RESET" "$*" >&2; }
die()   { err "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
PYTHON="python3"
DO_SYSTEM=1
DO_PYTHON=1
DO_DEV=1
DO_EDITABLE=0
DO_INSTALL=0
ASSUME_YES=0

# Help text lives here (not scraped from the header comment) so that editing
# the comment block can never shift or truncate `--help`. Quoted heredoc: the
# backticks below are literal, not command substitution.
usage() {
  cat <<'EOF'
install-deps.sh — install the system and Python dependencies for llm-sanitizer's
archive and document extraction features, on macOS and Linux.

Usage:
  bash scripts/install-deps.sh [options]

Options:
  --python PATH    Python interpreter to install into (default: python3)
  --no-system      Skip the system-library (libarchive) step
  --no-python      Skip the Python-package step
  --no-dev         Skip dev/type-check tooling (mypy)
  --editable       Also `pip install -e .` the repo (editable/develop install)
  --install        Also `pip install .` the repo (non-editable install);
                   mutually exclusive with --editable
  --yes, -y        Assume "yes" for the pre-install confirmation prompt
  -h, --help       Show this help and exit

Notes:
  * Run this inside the virtualenv you want the packages in (or let `uv`
    discover the project's .venv). Without a venv, pip installs with --user.
  * The system-library step may prompt for sudo.
  * RUN this script — do not `source` it.
EOF
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --python)    PYTHON="${2:?--python needs a value}"; shift 2 ;;
    --python=*)  PYTHON="${1#*=}"; shift ;;
    --no-system) DO_SYSTEM=0; shift ;;
    --no-python) DO_PYTHON=0; shift ;;
    --no-dev)    DO_DEV=0; shift ;;
    --editable)  DO_EDITABLE=1; shift ;;
    --install)   DO_INSTALL=1; shift ;;
    --yes|-y)    ASSUME_YES=1; shift ;;
    -h|--help)   usage ;;
    *)           die "Unknown option: $1 (use --help)" ;;
  esac
done

if [ "$DO_EDITABLE" = 1 ] && [ "$DO_INSTALL" = 1 ]; then
  die "--editable and --install are mutually exclusive (pick one)."
fi

# $0 is the script path for any EXECUTED shell (bash/zsh/sh). Sourcing — where
# $0 would be unreliable — is refused above, so BASH_SOURCE isn't needed.
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# ---------------------------------------------------------------------------
# Preamble
# ---------------------------------------------------------------------------
OS="$(uname -s)"
info "${C_BOLD}llm-sanitizer dependency installer${C_RESET}"
printf '    OS            : %s\n' "$OS"
printf '    Repo root     : %s\n' "$REPO_ROOT"
printf '    Python        : %s\n' "$PYTHON"
printf '    System step   : %s\n' "$([ "$DO_SYSTEM" = 1 ] && echo enabled || echo skipped)"
printf '    Python step   : %s\n' "$([ "$DO_PYTHON" = 1 ] && echo enabled || echo skipped)"
printf '    Dev tooling   : %s\n' "$([ "$DO_DEV" = 1 ] && echo enabled || echo skipped)"
if   [ "$DO_EDITABLE" = 1 ]; then _pkg_mode='editable install'
elif [ "$DO_INSTALL"  = 1 ]; then _pkg_mode='non-editable install'
else                              _pkg_mode='skipped'
fi
printf '    Package       : %s\n' "$_pkg_mode"
echo

if [ "$ASSUME_YES" != 1 ]; then
  printf 'Proceed with installation? [y/N] '
  read -r reply
  case "$reply" in
    y|Y|yes|YES) ;;
    *) info "Aborted."; exit 0 ;;
  esac
fi

# ---------------------------------------------------------------------------
# sudo helper (Linux system packages)
# ---------------------------------------------------------------------------
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi
fi

# ---------------------------------------------------------------------------
# Step 1 — system library: libarchive
# ---------------------------------------------------------------------------
install_system_deps() {
  info "Installing system library: libarchive"
  case "$OS" in
    Darwin)
      if ! command -v brew >/dev/null 2>&1; then
        err "Homebrew not found."
        err "Install it from https://brew.sh, then re-run — or use --no-system"
        err "if libarchive is already present (e.g. via MacPorts)."
        return 1
      fi
      brew install libarchive
      # Homebrew keeps libarchive keg-only; expose its lib dir so the ctypes
      # binding (libarchive-c) can find libarchive.dylib at runtime.
      local prefix
      prefix="$(brew --prefix libarchive 2>/dev/null || true)"
      if [ -n "$prefix" ] && [ -d "$prefix/lib" ]; then
        ok "libarchive installed at $prefix"
        warn "If Python can't load libarchive, add to your shell profile:"
        # shellcheck disable=SC2016  # literal profile line for the user; must NOT expand here
        printf '      export DYLD_LIBRARY_PATH="%s/lib:${DYLD_LIBRARY_PATH:-}"\n' "$prefix"
      fi
      ;;
    Linux)
      if   command -v apt-get >/dev/null 2>&1; then
        $SUDO apt-get update
        $SUDO apt-get install -y libarchive-dev libarchive-tools
      elif command -v dnf >/dev/null 2>&1; then
        $SUDO dnf install -y libarchive libarchive-devel
      elif command -v yum >/dev/null 2>&1; then
        $SUDO yum install -y libarchive libarchive-devel
      elif command -v pacman >/dev/null 2>&1; then
        $SUDO pacman -S --needed --noconfirm libarchive
      elif command -v zypper >/dev/null 2>&1; then
        $SUDO zypper install -y libarchive libarchive-devel
      elif command -v apk >/dev/null 2>&1; then
        $SUDO apk add libarchive libarchive-tools
      else
        err "No supported package manager found (apt/dnf/yum/pacman/zypper/apk)."
        err "Install the 'libarchive' shared library manually, then --no-system."
        return 1
      fi
      ok "libarchive installed"
      ;;
    *)
      err "Unsupported OS: $OS (this script supports macOS and Linux)."
      return 1
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Step 2 — Python packages
# ---------------------------------------------------------------------------
PY_PKGS=(
  filetype
  pypdf
  py7zr
  libarchive-c
  olefile
  markitdown
  mammoth
  python-pptx
  openpyxl
  xlrd
  "pdfminer.six"
  striprtf
  semgrep            # static code auditor for agent-tool scripts (Flow-Guard surface B)
)

install_python_deps() {
  command -v "$PYTHON" >/dev/null 2>&1 || die "Python interpreter not found: $PYTHON"
  info "Python: $("$PYTHON" --version 2>&1)"

  # Prefer uv when available (fast, and discovers the project .venv); otherwise
  # fall back to pip. Honor an active virtualenv; without one, pip uses --user.
  local installer
  if command -v uv >/dev/null 2>&1; then
    installer="uv"
    info "Using uv for Python package installation"
  else
    installer="pip"
    info "Using $PYTHON -m pip for Python package installation"
  fi

  py_install() {
    if [ "$installer" = "uv" ]; then
      uv pip install --python "$PYTHON" "$@"
    elif [ -n "${VIRTUAL_ENV:-}" ]; then
      "$PYTHON" -m pip install "$@"
    else
      "$PYTHON" -m pip install --user "$@"
    fi
  }

  info "Installing Python packages: ${PY_PKGS[*]}"
  py_install --upgrade pip >/dev/null 2>&1 || true
  py_install "${PY_PKGS[@]}"
  ok "Python packages installed"

  if [ "$DO_DEV" = 1 ]; then
    info "Installing dev/type-check tooling: mypy"
    py_install mypy
    ok "dev tooling installed"
  fi

  if [ "$DO_EDITABLE" = 1 ] || [ "$DO_INSTALL" = 1 ]; then
    local _mode _flag
    if [ "$DO_EDITABLE" = 1 ]; then _mode="editable"; _flag="-e"; else _mode="non-editable"; _flag=""; fi
    if [ -f "$REPO_ROOT/pyproject.toml" ]; then
      info "Installing llm-sanitizer ($_mode) from $REPO_ROOT"
      # shellcheck disable=SC2086  # $_flag is intentionally unquoted (empty = word-split away)
      ( cd "$REPO_ROOT" && py_install $_flag . )
      ok "llm-sanitizer installed ($_mode)"
    else
      warn "--$( [ "$DO_EDITABLE" = 1 ] && echo editable || echo install ) given but no pyproject.toml at $REPO_ROOT; skipping."
    fi
  fi
}

# ---------------------------------------------------------------------------
# Step 3 — verification
# ---------------------------------------------------------------------------
verify() {
  info "Verifying imports"
  # module_name:pip_name pairs — module name differs from pip name for some.
  local checks=(
    "filetype:filetype"
    "pypdf:pypdf"
    "py7zr:py7zr"
    "libarchive:libarchive-c"
    "olefile:olefile"
    "markitdown:markitdown"
    "mammoth:mammoth"
    "pptx:python-pptx"
    "openpyxl:openpyxl"
    "xlrd:xlrd"
    "pdfminer:pdfminer.six"
    "striprtf:striprtf"
  )
  local failed=0
  local entry mod pip
  for entry in "${checks[@]}"; do
    mod="${entry%%:*}"; pip="${entry##*:}"
    if "$PYTHON" -c "import $mod" >/dev/null 2>&1; then
      ok "$pip (import $mod)"
    else
      err "$pip — 'import $mod' failed"
      failed=1
    fi
  done
  # CLI-only tooling (verified by presence on PATH, not by import). If installed
  # via pip --user, ensure ~/.local/bin (Linux) or the user base bin is on PATH.
  if command -v semgrep >/dev/null 2>&1; then
    ok "semgrep ($(semgrep --version 2>/dev/null | head -1))"
  else
    err "semgrep — not found on PATH (if pip-installed --user, add its bin dir to PATH)"
    failed=1
  fi
  if [ "$DO_DEV" = 1 ]; then
    if command -v mypy >/dev/null 2>&1; then
      ok "mypy ($(mypy --version 2>/dev/null))"
    else
      err "mypy — not found on PATH (if pip-installed --user, add its bin dir to PATH)"
      failed=1
    fi
  fi
  return $failed
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
rc=0
if [ "$DO_SYSTEM" = 1 ]; then
  install_system_deps || rc=1
else
  info "Skipping system-library step (--no-system)"
fi

if [ "$DO_PYTHON" = 1 ]; then
  install_python_deps || rc=1
else
  info "Skipping Python-package step (--no-python)"
fi

echo
if [ "$DO_PYTHON" = 1 ]; then
  if verify; then
    ok "${C_BOLD}All dependencies present.${C_RESET}"
  else
    rc=1
    warn "Some imports failed. If libarchive-c failed on macOS, set"
    warn "DYLD_LIBRARY_PATH as noted above and re-run verification."
  fi
fi

echo
if [ "$rc" = 0 ]; then
  info "${C_GREEN}${C_BOLD}Done.${C_RESET} Archive + document extraction dependencies are ready."
else
  die "Finished with errors (see above)."
fi
