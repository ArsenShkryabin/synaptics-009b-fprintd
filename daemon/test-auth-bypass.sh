#!/usr/bin/env bash
# Authorization regression test for syna-fprintd.
#
# Run as a NORMAL user (not root) against a running patched daemon:
#     ./daemon/test-auth-bypass.sh
#
# It only calls Claim / ListEnrolledFingers / Release. It never enrolls,
# verifies, or deletes anything, so it is safe to run on a working machine.
#
# On the pre-fix daemon the "Claim another user" case SUCCEEDS (that is the
# auth-bypass bug). On the fixed daemon it must fail with PermissionDenied.
set -euo pipefail

DEST="net.reactivated.Fprint"
DEVICE="/net/reactivated/Fprint/Device/0"
IFACE="net.reactivated.Fprint.Device"

if [ "$(id -u)" -eq 0 ]; then
    echo "Run this as your normal desktop user, not root." >&2
    exit 2
fi

ME="$(id -un)"
command -v gdbus >/dev/null || { echo "gdbus not found (install glib2)" >&2; exit 2; }

call() {
    gdbus call --system \
        --dest "$DEST" \
        --object-path "$DEVICE" \
        --method "${IFACE}.$1" "${@:2}" 2>&1
}

cleanup() {
    call Release >/dev/null 2>&1 || true
}
trap cleanup EXIT

expect_ok() {
    local out
    if ! out="$(call "$@")"; then
        echo "FAIL: expected success: $*" >&2
        echo "$out" >&2
        exit 1
    fi
}

expect_denied() {
    local out
    if out="$(call "$@")"; then
        echo "FAIL: expected PermissionDenied, but the call succeeded: $*" >&2
        echo "$out" >&2
        exit 1
    fi
    if ! grep -q "PermissionDenied" <<<"$out"; then
        echo "FAIL: expected PermissionDenied, got a different error: $*" >&2
        echo "$out" >&2
        exit 1
    fi
}

echo "== positive: claim self =="
if ! out="$(call Claim "$ME")"; then
    if grep -q "AlreadyInUse" <<<"$out"; then
        echo "SKIP: device is already claimed by another process." >&2
        echo "      Close fprintd-enroll/verify/lock-screen dialogs and retry." >&2
        exit 2
    fi
    echo "FAIL: could not claim own account:" >&2
    echo "$out" >&2
    exit 1
fi

echo "== positive: list own prints =="
expect_ok ListEnrolledFingers "$ME"

echo "== negative: claim root =="
expect_denied Claim "root"

echo "== negative: list root's prints =="
expect_denied ListEnrolledFingers "root"

echo "== positive: release =="
expect_ok Release

echo "OK: caller authorization is enforced."
