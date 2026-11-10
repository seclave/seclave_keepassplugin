# Security policy

Report vulnerabilities to **security@seclave.se**, or privately on GitHub
with **Report a vulnerability** on this repository's Security tab. Please do
not open a public issue for a security problem.

This is a host-side plugin: it runs inside KeePass and handles the
database's secrets in two ways.

The sync over the USB slave port is the recommended way to put entries on a
Seclave, and the export is the fallback, for a first bulk load into an
empty Seclave or when the serial port is not available. The sync writes no
file: the entries go over the serial port straight into the device, which
in its Normal security mode asks on its own screen before every change and
goes ahead only on a press of its joystick, and the sync sends only what
changed, after the user has reviewed the plan. The export writes every
exported username, password and note unencrypted to a file on a USB volume,
which any volume that passes the checks below would receive, and it needs
the Seclave in import mode, where the Seclave is a drive to the whole
computer and takes the file in as one bulk load.

**Export to the import volume.** The plugin writes the exported entries,
usernames, passwords and notes included, unencrypted to `seclave.imp` on the
drive the Seclave shows in import mode. It looks only at drives that the
operating system's list of drives, which asks no drive anything, shows to be
local removable disks (on Linux a FAT drive on a removable USB disk, on
Windows a removable drive, on USB where Windows tells, on macOS a local FAT
disk), and never asks a network drive or any other drive anything. Of
those, it recognises the Seclave's as a FAT volume labelled SECLAVE that
holds `SCIMPORT.STE` and is no larger than 2 MB, writes only when exactly
one such drive is present, and names it before writing. The plugin does not
protect the file once it is written: the volume, and the file with it,
exists only in the Seclave's memory while the Seclave is in import mode.
The user is told to check that the Seclave shows Import OK and then to
unplug it, which ends the file.

**Sync over the USB slave port.** The plugin parses what the device sends
over its serial protocol, writes device values back into KeePass entries
(after a history backup of each), and keeps its state in each
entry's custom data: `Seclave.Label`, the entry's label on the Seclave;
`Seclave.Uuid`, the entry the label belongs to; and `Seclave.Baseline`, an
HMAC-SHA256 of the label, group, username, password and notes as last known
on the Seclave. The HMAC key is 32 random bytes, kept as a protected
attachment on an entry of its own, "Seclave sync key", in the database root:
KeePass protects it in memory as it protects passwords, and saves it
encrypted with the database. KeePass protects neither custom data in memory
nor the copies of it in an entry's history, so the hashes, older ones in
history entries included, can be read from a memory dump of an unlocked
KeePass or from an XML export of the database; recovering a password from
one needs the key, which is as protected as the passwords themselves. The
key entry is never exported or synced.

**The backup key.** Only Import Seclave backup asks for the Seclave's backup
key. The plugin decrypts the backup with it, read from the device or from a
backup file, clears it from memory after the read, and never stores it. The
key never changes, and with it any backup of the Seclave, past or future,
opens with every password in it: typing it on a computer exposes every
backup of that Seclave to whatever on that computer can see it. The import
dialog says so next to the key field, before the key is typed.

**The udev rule on Linux.** `install-udev-rule.sh` runs as root and writes
one file, `/etc/udev/rules.d/60-seclave-keepass.rules`; `--print` shows the
rule beforehand and `--remove` takes it out. It comes with each release,
under the same checksums and attestation as the plugin. The rule applies
only to a device with the Seclave's USB ids, 20a0:41e3. It gives that
device's serial port to the user of the session at the computer's own
screen and keyboard (systemd-logind's uaccess), and keeps it closed to every
other account except members of the `dialout` group, as Linux keeps serial
ports anyway; it never opens the port to everyone. Every program that user
runs can open the port, as the plugin does, so what stands between such a
program and the entries is the confirmation the Seclave asks for on its own
screen in its Normal security mode.

**The Seclave's confirmation is its security boundary.** In the Normal
security mode the Seclave shows on its own screen each read and each change
the sync asks for, and goes ahead only on a press of its joystick, which no
program on the computer can give. Keeping it a mirror of KeePass
realistically needs Admin > Slave security > Allow all for the duration of a
sync, and while that is set the boundary is lifted: any computer connected
over USB can read every label, group, username, password and note, and
change entries, without a confirmation on the Seclave. Use Allow all only on
a computer you trust, and set Slave security back to Normal after the sync.
The plugin cannot change that setting and never asks the Seclave to; it
only notices, from how long the Seclave takes to answer, whether it asks
for confirmations, and says so.
