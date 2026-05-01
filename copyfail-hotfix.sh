#!/usr/bin/env bash
set -Eeuo pipefail

# Emergency mitigation for CVE-2026-31431 / Copy Fail.
# This script does not patch the kernel.
# It blocks the algif_aead module until the system boots a fixed vendor kernel.

CVE_ID="CVE-2026-31431"
MODULE_NAME="algif_aead"
CONF_FILE="/etc/modprobe.d/disable-${MODULE_NAME}-${CVE_ID}.conf"
LOG_FILE="/var/log/copyfail-hotfix.log"

UPDATE_INITRAMFS="yes"

usage() {
    cat <<EOF
copyfail-hotfix.sh - Emergency mitigation for ${CVE_ID} / Copy Fail

Usage:
  sudo ./copyfail-hotfix.sh apply
  sudo ./copyfail-hotfix.sh status
  sudo ./copyfail-hotfix.sh check
  sudo ./copyfail-hotfix.sh undo

Optional flags:
  --no-initramfs    Do not rebuild initramfs after apply/undo.

Commands:
  apply   Install the mitigation, unload ${MODULE_NAME} if possible, and run checks.
  status  Show current module, modprobe, and mitigation status.
  check   Run a safe AF_ALG AEAD bind check. This does not exploit the system.
  undo    Remove this script's mitigation file and rebuild initramfs if possible.

Important:
  This is a mitigation, not the real kernel fix.
  The real fix is a vendor kernel update that includes the upstream kernel fix.
EOF
}

log() {
    local msg="$*"
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    printf '[%s] %s\n' "$(date -Is)" "$msg" | tee -a "$LOG_FILE"
}

warn() {
    local msg="$*"
    printf '[WARNING] %s\n' "$msg" >&2
    printf '[%s] WARNING: %s\n' "$(date -Is)" "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

die() {
    local msg="$*"
    printf '[ERROR] %s\n' "$msg" >&2
    exit 1
}

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        die "Run this command as root, for example: sudo $0 apply"
    fi
}

is_module_loaded() {
    grep -qE "^${MODULE_NAME} " /proc/modules
}

module_info() {
    if ! command -v modinfo >/dev/null 2>&1; then
        echo "modinfo: not installed"
        return 0
    fi

    local filename
    filename="$(modinfo -F filename "$MODULE_NAME" 2>/dev/null || true)"

    if [[ -z "$filename" ]]; then
        echo "${MODULE_NAME}: not found by modinfo"
    elif [[ "$filename" == "(builtin)" ]]; then
        echo "${MODULE_NAME}: built into the kernel"
        echo "WARNING: If this code is built-in, modprobe blocking may not be enough."
    else
        echo "${MODULE_NAME}: $filename"
    fi
}

write_mitigation_file() {
    mkdir -p /etc/modprobe.d

    if [[ -f "$CONF_FILE" ]]; then
        cp -a "$CONF_FILE" "${CONF_FILE}.bak.$(date +%Y%m%d-%H%M%S)"
        log "Existing mitigation file backed up."
    fi

    cat > "$CONF_FILE" <<EOF
# Emergency mitigation for CVE-2026-31431 / Copy Fail.
# This blocks loading the vulnerable algif_aead module through modprobe.
# This is not a kernel patch.
# Install and boot a fixed vendor kernel as soon as possible.

install ${MODULE_NAME} /bin/false
blacklist ${MODULE_NAME}
EOF

    chmod 0644 "$CONF_FILE"
    log "Wrote $CONF_FILE"
}

unload_module_if_loaded() {
    if ! is_module_loaded; then
        log "${MODULE_NAME} is not currently loaded."
        return 0
    fi

    log "${MODULE_NAME} is currently loaded. Trying to unload it now."

    if modprobe -r "$MODULE_NAME" 2>/tmp/copyfail-modprobe-r.err; then
        log "${MODULE_NAME} unloaded successfully with modprobe -r."
        rm -f /tmp/copyfail-modprobe-r.err
        return 0
    fi

    warn "modprobe -r failed: $(cat /tmp/copyfail-modprobe-r.err 2>/dev/null || true)"
    rm -f /tmp/copyfail-modprobe-r.err

    if rmmod "$MODULE_NAME" 2>/tmp/copyfail-rmmod.err; then
        log "${MODULE_NAME} unloaded successfully with rmmod."
        rm -f /tmp/copyfail-rmmod.err
        return 0
    fi

    warn "rmmod failed: $(cat /tmp/copyfail-rmmod.err 2>/dev/null || true)"
    rm -f /tmp/copyfail-rmmod.err

    warn "${MODULE_NAME} is still loaded. Reboot is required."
    return 1
}

rebuild_initramfs_if_possible() {
    if [[ "$UPDATE_INITRAMFS" != "yes" ]]; then
        log "Skipping initramfs rebuild because --no-initramfs was used."
        return 0
    fi

    if command -v update-initramfs >/dev/null 2>&1; then
        log "Rebuilding initramfs with update-initramfs -u."
        update-initramfs -u
        return 0
    fi

    if command -v dracut >/dev/null 2>&1; then
        log "Rebuilding initramfs with dracut -f."
        dracut -f
        return 0
    fi

    warn "No supported initramfs rebuild tool found. This may still be fine on many systems."
    return 0
}

safe_afalg_check() {
    python3 - <<'PY'
import socket
import sys

try:
    s = socket.socket(38, 5, 0)  # AF_ALG, SOCK_SEQPACKET
    s.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    print("WARNING: AF_ALG AEAD bind works. Mitigation may NOT be active.")
    sys.exit(1)
except FileNotFoundError:
    print("OK: AF_ALG AEAD algorithm is unavailable. Mitigation appears active.")
    sys.exit(0)
except PermissionError:
    print("OK: AF_ALG access is blocked by permissions/seccomp/LSM policy.")
    sys.exit(0)
except OSError as e:
    print(f"OK/INFO: AF_ALG AEAD bind failed: {e}")
    sys.exit(0)
PY
}

show_status() {
    echo "Copy Fail / ${CVE_ID} status"
    echo "-----------------------------------"
    echo "Kernel: $(uname -r)"
    echo

    module_info
    echo

    if [[ -f "$CONF_FILE" ]]; then
        echo "Mitigation file: present - $CONF_FILE"
    else
        echo "Mitigation file: missing - $CONF_FILE"
    fi

    if is_module_loaded; then
        echo "Runtime module state: LOADED"
        echo "Result: reboot or manual unload is still required."
    else
        echo "Runtime module state: not loaded"
        echo "Result: module is not currently loaded. Final decision depends on modprobe and AF_ALG check below."
    fi

    echo
    echo "modprobe dry-run:"
    modprobe -n -v "$MODULE_NAME" 2>&1 || true

    echo
    echo "Safe AF_ALG check:"
    safe_afalg_check || true

    echo
    echo "Possible AF_ALG users:"
    if command -v lsof >/dev/null 2>&1; then
        lsof -nP 2>/dev/null | grep -i 'AF_ALG' || echo "No AF_ALG users found by lsof."
    else
        echo "lsof is not installed."
    fi

    if command -v ss >/dev/null 2>&1; then
        ss -xa 2>/dev/null | grep -i 'alg' || true
    fi
}

apply_hotfix() {
    require_root
    log "Applying emergency mitigation for ${CVE_ID}."

    write_mitigation_file
    unload_module_if_loaded || true
    rebuild_initramfs_if_possible

    echo
    show_status

    echo
    if is_module_loaded; then
        warn "Mitigation file is installed, but ${MODULE_NAME} is still loaded."
        warn "Reboot is required to complete the mitigation."
        exit 2
    fi

    if safe_afalg_check >/tmp/copyfail-safe-check.out 2>&1; then
        cat /tmp/copyfail-safe-check.out
        rm -f /tmp/copyfail-safe-check.out
        log "Mitigation applied successfully."
        log "Still install the official kernel update as soon as available."
        exit 0
    else
        cat /tmp/copyfail-safe-check.out
        rm -f /tmp/copyfail-safe-check.out
        warn "AF_ALG AEAD still appears available. The mitigation may not be active."
        warn "Reboot and test again. If it still works, the vulnerable code may be built into the kernel."
        exit 3
    fi
}

undo_hotfix() {
    require_root
    log "Removing emergency mitigation for ${CVE_ID}."

    if [[ -f "$CONF_FILE" ]]; then
        mv "$CONF_FILE" "${CONF_FILE}.removed.$(date +%Y%m%d-%H%M%S)"
        log "Mitigation file removed by renaming it."
    else
        warn "No mitigation file found at $CONF_FILE."
    fi

    rebuild_initramfs_if_possible
    warn "Reboot may be required before the system fully returns to normal behavior."
}

parse_flags() {
    local arg
    for arg in "$@"; do
        case "$arg" in
            --no-initramfs)
                UPDATE_INITRAMFS="no"
                ;;
            *)
                die "Unknown option: $arg"
                ;;
        esac
    done
}

main() {
    local cmd="${1:-help}"

    if [[ $# -gt 0 ]]; then
        shift || true
    fi

    parse_flags "$@"

    case "$cmd" in
        apply)
            apply_hotfix
            ;;
        status)
            show_status
            ;;
        check)
            safe_afalg_check
            ;;
        undo)
            undo_hotfix
            ;;
        help|-h|--help|"")
            usage
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
