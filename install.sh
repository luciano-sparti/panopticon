#!/usr/bin/env bash
# ==============================================================================
# Panopticon Installer Script
# Works both as a remote one-liner (curl | bash) and as a local installer.
# ==============================================================================
set -euo pipefail

REPO="luciano-sparti/panopticon"
PKG_NAME="panopticon"

# Check for Python 3.9+
check_python() {
    local py=""
    for cmd in python3 python; do
        if command -v "$cmd" >/dev/null 2>&1; then
            if "$cmd" -c "import sys; exit(0 if sys.version_info >= (3, 9) else 1)" 2>/dev/null; then
                py="$cmd"
                break
            fi
        fi
    done

    if [ -z "$py" ]; then
        echo "❌ Error: Python 3.9 or higher is required to install Panopticon." >&2
        echo "   Please install Python 3.9+ and try again." >&2
        exit 1
    fi
    echo "$py"
}

# Determine target directories
if [ "$(id -u)" -eq 0 ]; then
    INSTALL_PREFIX="/usr/local"
    SHARE_DIR="/usr/local/share/panopticon"
else
    INSTALL_PREFIX="${HOME}/.local"
    SHARE_DIR="${HOME}/.local/share/panopticon"
fi

BIN_DIR="${INSTALL_PREFIX}/bin"
VENV_DIR="${SHARE_DIR}/venv"

# Check if running inside local source repository
is_local_repo() {
    [ -f "./pyproject.toml" ] && [ -d "./panopticon" ]
}

main() {
    local py
    py="$(check_python)"

    echo "==> Installing Panopticon..."
    echo "    Python binary:  $($py -c 'import sys; print(sys.executable)') ($($py --version))"
    echo "    Install prefix: ${INSTALL_PREFIX}"
    echo "    Isolated venv:  ${VENV_DIR}"

    mkdir -p "$BIN_DIR" "$SHARE_DIR"

    # Create / update isolated virtualenv
    if [ ! -d "$VENV_DIR" ]; then
        echo "==> Creating virtual environment..."
        "$py" -m venv "$VENV_DIR"
    fi

    echo "==> Installing Panopticon package into venv..."
    "$VENV_DIR/bin/python" -m pip install --quiet --upgrade pip

    if is_local_repo; then
        echo "    (Installing from local source repository)"
        "$VENV_DIR/bin/python" -m pip install --quiet .
    else
        echo "    (Installing latest release from GitHub)"
        "$VENV_DIR/bin/python" -m pip install --quiet "git+https://github.com/${REPO}.git"
    fi

    # Create launcher script
    echo "==> Creating executable launcher in ${BIN_DIR}/panopticon..."
    cat << LAUNCHER > "${BIN_DIR}/panopticon"
#!/usr/bin/env bash
exec "${VENV_DIR}/bin/panopticon" "\$@"
LAUNCHER
    chmod 755 "${BIN_DIR}/panopticon"

    # Linux capability recommendation / setup
    if [ "$(uname -s)" = "Linux" ] && command -v setcap >/dev/null 2>&1; then
        local real_py
        real_py="$(readlink -f "${VENV_DIR}/bin/python" 2>/dev/null || echo "${VENV_DIR}/bin/python")"
        if [ "$(id -u)" -eq 0 ]; then
            setcap cap_net_raw,cap_net_admin=eip "$real_py" 2>/dev/null || true
            echo "✅ Granted CAP_NET_RAW capabilities to ${real_py} (run without sudo)."
        fi
    fi

    echo ""
    echo "🎉 Panopticon installed successfully!"
    echo "   Binary location: ${BIN_DIR}/panopticon"
    echo ""

    if ! echo "$PATH" | tr ':' '\n' | grep -qx "${BIN_DIR}"; then
        echo "⚠️  Note: ${BIN_DIR} is not in your PATH."
        echo "   Add this to your shell profile (~/.bashrc or ~/.zshrc):"
        echo "   export PATH=\"${BIN_DIR}:\$PATH\""
        echo ""
    fi

    if [ "$(uname -s)" = "Linux" ] && [ "$(id -u)" -ne 0 ]; then
        echo "💡 Tip (Linux): Grant packet sniffing permissions once to run without sudo:"
        echo "   sudo setcap cap_net_raw,cap_net_admin=eip \"\$(readlink -f ${VENV_DIR}/bin/python)\""
        echo ""
    fi
}

main "$@"
