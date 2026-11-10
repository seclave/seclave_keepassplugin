#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright 2026 Seclave AB
#
# Installs the udev rule that lets KeePass use the Seclave's serial port in
# its Usb slave mode on Linux. Windows and macOS need nothing: there the port
# works as it is.
#
#     sudo sh install-udev-rule.sh            install the rule, or update it
#     sudo sh install-udev-rule.sh --remove   remove it
#     sh install-udev-rule.sh --check         show whether it is in place
#     sh install-udev-rule.sh --print         print the rule, change nothing
#
# It writes one file, /etc/udev/rules.d/60-seclave-keepass.rules, and has
# udev read its rules again. The Seclave Companion's Linux packages install
# the same rule as /usr/lib/udev/rules.d/60-seclave.rules; with both in
# place they do the same, and either can stay.
set -eu

RULES=/etc/udev/rules.d/60-seclave-keepass.rules
# The same rule from the Seclave Companion: its packages, or a copy by hand
COMPANION="/usr/lib/udev/rules.d/60-seclave.rules /etc/udev/rules.d/60-seclave.rules"

rule() {
    cat <<'EOF'
# The Seclave in Usb slave mode: a CDC-ACM serial port, USB id 20a0:41e3.
# Installed by install-udev-rule.sh of the Seclave KeePass plugin.
#
# - ID_MM_DEVICE_IGNORE keeps ModemManager off the port, which it would
#   otherwise probe with AT commands, spoiling the first exchange.
# - TAG+="uaccess" gives the port to the user logged in at the computer,
#   through systemd-logind, with no group membership needed. MODE and GROUP
#   keep it closed to every other account but members of the dialout group.
# - SYMLINK+="seclave" names the port /dev/seclave, which the plugin lists
#   first.
#
# Numbered 60 so that the uaccess tag is set before systemd's seat rules run.

SUBSYSTEM=="usb", ATTRS{idVendor}=="20a0", ATTRS{idProduct}=="41e3", ENV{ID_MM_DEVICE_IGNORE}="1"
SUBSYSTEM=="tty", ATTRS{idVendor}=="20a0", ATTRS{idProduct}=="41e3", ENV{ID_MM_DEVICE_IGNORE}="1", MODE="0660", GROUP="dialout", TAG+="uaccess", SYMLINK+="seclave"
EOF
}

usage() {
    cat <<EOF
Usage: sudo sh $0            install the Seclave's udev rule, or update it
       sudo sh $0 --remove   remove it
       sh $0 --check         show whether it is in place
       sh $0 --print         print the rule, change nothing
EOF
}

say() { printf '%s\n' "$*"; }

as_root() {
    if [ "$(id -u)" != 0 ]; then
        say "This changes udev's rules, so it needs root: sudo sh $0${1:+ $1}" >&2
        exit 1
    fi
}

# The Seclave's serial ports plugged in now, by their ttyACM names
seclave_ttys() {
    for tty in /sys/class/tty/ttyACM*; do
        usb=$(readlink -f "$tty/device/.." 2>/dev/null) || continue
        if [ "$(cat "$usb/idVendor" 2>/dev/null)" = 20a0 ] &&
           [ "$(cat "$usb/idProduct" 2>/dev/null)" = 41e3 ]; then
            say "${tty##*/}"
        fi
    done
}

# Has udev read its rules again, and apply them to a Seclave plugged in now
reload() {
    if command -v udevadm >/dev/null 2>&1 && udevadm control --reload-rules 2>/dev/null; then
        for tty in $(seclave_ttys); do
            udevadm trigger --action=change --subsystem-match=tty --sysname-match="$tty" 2>/dev/null || true
        done
        udevadm settle --timeout=10 2>/dev/null || true
    else
        say "udev is not running here, so the rule applies once it runs."
    fi
}

companion_note() {
    for f in $COMPANION; do
        if [ -f "$f" ]; then say "The Seclave Companion's rule is installed as well: $f"; fi
    done
}

install_rule() {
    if [ -e /etc/NIXOS ]; then
        say "On NixOS udev takes its rules from the system configuration. Add this to"
        say "configuration.nix and rebuild:"
        say ""
        say "  services.udev.extraRules = ''"
        rule | sed -n 's/^SUBSYSTEM/    SUBSYSTEM/p'
        say "  '';"
        exit 1
    fi
    as_root
    mkdir -p "${RULES%/*}"
    if [ -f "$RULES" ] && [ "$(rule)" = "$(cat "$RULES")" ]; then
        say "The rule is in place already: $RULES"
    else
        # Written next to the rule and renamed into place, so that udev never
        # reads half a file, and the file takes the directory's SELinux label.
        # udev reads only names ending in .rules.
        rule > "$RULES.new"
        chmod 0644 "$RULES.new"
        mv -f "$RULES.new" "$RULES"
        say "Installed $RULES"
    fi
    reload
    if [ ! -d /run/systemd/seats ]; then
        say "This computer runs no systemd-logind, so the rule cannot give the port to"
        say "the user logged in. Be in the dialout group instead:"
        say "    sudo usermod -aG dialout ${SUDO_USER:-<user>}"
        say "and log out and in again."
    fi
    if [ -e /dev/seclave ]; then
        say "The Seclave is plugged in, at /dev/seclave."
    elif [ -n "$(seclave_ttys)" ]; then
        say "The Seclave is plugged in, but the rule has not reached it yet: choose Usb"
        say "slave on the Seclave again."
    else
        say "Choose Usb slave on the Seclave and plug it in: KeePass finds it as"
        say "/dev/seclave."
    fi
}

remove_rule() {
    as_root --remove
    if [ -e "$RULES" ]; then
        rm -f "$RULES"
        say "Removed $RULES; it no longer applies from the next time the Seclave is"
        say "plugged in."
        reload
    else
        say "Nothing to remove: there is no $RULES"
    fi
    companion_note
}

check() {
    found=1
    if [ ! -f "$RULES" ]; then
        say "The rule is not installed: no $RULES"
    elif [ "$(rule)" = "$(cat "$RULES")" ]; then
        say "The rule is installed: $RULES"
        found=0
    else
        say "The rule is installed, but differs from this script's: $RULES"
        say "(sudo sh $0 replaces it)"
        found=0
    fi
    for f in $COMPANION; do
        if [ -f "$f" ]; then
            say "The Seclave Companion's rule is installed: $f"
            found=0
        fi
    done
    tty=$(seclave_ttys | head -n 1)
    if [ -e /dev/seclave ]; then
        if [ -r /dev/seclave ] && [ -w /dev/seclave ]; then
            say "The Seclave is plugged in, at /dev/seclave, and you can use it."
        else
            say "The Seclave is plugged in, at /dev/seclave, but you cannot use it: the rule"
            say "gives it to the user logged in at the computer, and to the dialout group."
        fi
    elif [ -n "$tty" ]; then
        say "The Seclave is plugged in, as /dev/$tty, without the rule applied."
    else
        say "No Seclave is plugged in in Usb slave mode."
    fi
    return $found
}

case "${1:-}" in
    "") action=install ;;
    --remove) action=remove ;;
    --check) action=check ;;
    --print) action=print ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac
if [ $# -gt 1 ]; then usage >&2; exit 2; fi

if [ "$action" = print ]; then
    rule
    exit 0
fi
if [ "$(uname -s)" != Linux ]; then
    say "Only Linux needs this: on $(uname -s) the Seclave's port works as it is."
    exit 0
fi
case $action in
    install) install_rule ;;
    remove) remove_rule ;;
    check) check ;;
esac
