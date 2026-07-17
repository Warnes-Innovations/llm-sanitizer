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
#   * If a virtualenv is active, packages install into it. Otherwise the script
#     creates and uses a repo-local .venv (REPO_ROOT/.venv) so the install and
#     the post-install verification share one interpreter. It prints the venv
#     path and how to activate it when done.
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
  * If a virtualenv is active, packages install into it. Otherwise the script
    creates and uses a repo-local .venv so install and verification share one
    interpreter; it prints the path and how to activate it when done.
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
# Resolve the target Python environment (install target MUST equal verify
# target). Policy: honor an active virtualenv; otherwise install into a
# repo-local .venv, created on demand. This keeps every install step and the
# post-install verification pointed at ONE interpreter, so we never install
# into one environment and then check imports in another.
# ---------------------------------------------------------------------------
BASE_PY=""       # interpreter the user asked for (used to build the venv)
TARGET_PY=""     # interpreter we install into AND verify against
VENV_DIR=""      # non-empty only when we own a repo-local venv
ENV_DESC="skipped (--no-python)"
if [ "$DO_PYTHON" = 1 ]; then
  BASE_PY="$(command -v "$PYTHON" 2>/dev/null || true)"
  [ -n "$BASE_PY" ] || die "Python interpreter not found: $PYTHON"
  if [ -n "${VIRTUAL_ENV:-}" ]; then
    TARGET_PY="$VIRTUAL_ENV/bin/python"
    ENV_DESC="active venv: $VIRTUAL_ENV"
  else
    VENV_DIR="$REPO_ROOT/.venv"
    TARGET_PY="$VENV_DIR/bin/python"
    if [ -x "$TARGET_PY" ]; then
      ENV_DESC="repo venv (existing): $VENV_DIR"
    else
      ENV_DESC="repo venv (will create): $VENV_DIR"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Preamble
# ---------------------------------------------------------------------------
OS="$(uname -s)"
info "${C_BOLD}llm-sanitizer dependency installer${C_RESET}"
printf '    OS            : %s\n' "$OS"
printf '    Repo root     : %s\n' "$REPO_ROOT"
printf '    Python        : %s\n' "$PYTHON${BASE_PY:+ ($BASE_PY)}"
printf '    Target env    : %s\n' "$ENV_DESC"
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
  # Create the repo-local venv on demand (only when no venv is active; see the
  # target-resolution block above, which sets VENV_DIR in that case). die() on
  # failure is deliberate: without a target interpreter nothing else can run,
  # and die's explicit exit works even though `set -e` is disabled in here.
  if [ -n "$VENV_DIR" ] && [ ! -x "$TARGET_PY" ]; then
    info "No active virtualenv — creating one at $VENV_DIR"
    if command -v uv >/dev/null 2>&1; then
      uv venv --python "$BASE_PY" "$VENV_DIR" || die "Failed to create venv at $VENV_DIR"
    else
      "$BASE_PY" -m venv "$VENV_DIR" || die "Failed to create venv at $VENV_DIR"
    fi
    ok "Created venv at $VENV_DIR"
  fi
  [ -x "$TARGET_PY" ] || die "Target interpreter not found: $TARGET_PY"
  info "Target interpreter: $("$TARGET_PY" --version 2>&1) ($TARGET_PY)"

  # Prefer uv when available (fast); fall back to pip. Either way we install
  # into $TARGET_PY — an absolute interpreter path, never a bare name — so the
  # install target is unambiguous and matches what verify() checks.
  local installer
  if command -v uv >/dev/null 2>&1; then
    installer="uv"
    info "Using uv for Python package installation"
  else
    installer="pip"
    info "Using $TARGET_PY -m pip for Python package installation"
  fi

  py_install() {
    if [ "$installer" = "uv" ]; then
      uv pip install --python "$TARGET_PY" "$@"
    else
      "$TARGET_PY" -m pip install "$@"
    fi
  }

  # NOTE: this function is invoked as `install_python_deps || rc=1`, which
  # disables `set -e` inside it. Every install step must therefore check its
  # own exit status explicitly and `return 1` on failure — otherwise a failed
  # install would fall through to a misleading `ok` success message.
  info "Installing Python packages: ${PY_PKGS[*]}"
  py_install --upgrade pip >/dev/null 2>&1 || true
  if ! py_install "${PY_PKGS[@]}"; then
    err "Python package installation failed (see error above)"
    return 1
  fi
  ok "Python packages installed"

  if [ "$DO_DEV" = 1 ]; then
    info "Installing dev/type-check tooling: mypy"
    if ! py_install mypy; then
      err "mypy installation failed (see error above)"
      return 1
    fi
    ok "dev tooling installed"
  fi

  if [ "$DO_EDITABLE" = 1 ] || [ "$DO_INSTALL" = 1 ]; then
    local _mode _flag
    if [ "$DO_EDITABLE" = 1 ]; then _mode="editable"; _flag="-e"; else _mode="non-editable"; _flag=""; fi
    if [ -f "$REPO_ROOT/pyproject.toml" ]; then
      info "Installing llm-sanitizer ($_mode) from $REPO_ROOT"
      # shellcheck disable=SC2086  # $_flag is intentionally unquoted (empty = word-split away)
      if ! ( cd "$REPO_ROOT" && py_install $_flag . ); then
        err "llm-sanitizer ($_mode) installation failed (see error above)"
        return 1
      fi
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
  info "Verifying imports in $TARGET_PY"
  # Resolve the target env's bin dir so CLI tools are checked in the SAME
  # environment we installed into — not via global PATH, which may shadow the
  # venv (or miss it entirely if the venv isn't activated).
  local venv_bin
  venv_bin="$(dirname "$TARGET_PY")"
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
    if "$TARGET_PY" -c "import $mod" >/dev/null 2>&1; then
      ok "$pip (import $mod)"
    else
      err "$pip — 'import $mod' failed"
      failed=1
    fi
  done
  # CLI-only tooling — checked at the target env's bin dir, not global PATH.
  if [ -x "$venv_bin/semgrep" ]; then
    ok "semgrep ($("$venv_bin/semgrep" --version 2>/dev/null | head -1))"
  else
    err "semgrep — not found in $venv_bin"
    failed=1
  fi
  if [ "$DO_DEV" = 1 ]; then
    if [ -x "$venv_bin/mypy" ]; then
      ok "mypy ($("$venv_bin/mypy" --version 2>/dev/null))"
    else
      err "mypy — not found in $venv_bin"
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
  if [ -n "$VENV_DIR" ]; then
    info "Installed into repo-local venv (no active venv was detected):"
    info "    $VENV_DIR"
    info "To use these tools, activate it first:"
    info "    source \"$VENV_DIR/bin/activate\""
    info "or invoke them by path, e.g. \"$VENV_DIR/bin/llm-sanitizer\"."
  elif [ -n "$TARGET_PY" ]; then
    info "Installed into the active virtualenv: ${VIRTUAL_ENV:-$TARGET_PY}"
  fi
else
  die "Finished with errors (see above)."
fi
