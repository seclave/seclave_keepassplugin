// SPDX-License-Identifier: MIT
// Copyright 2026 Seclave AB
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePass.UI;
using KeePass.Util.Spr;
using KeePassLib;
using KeePassLib.Native;
using KeePassLib.Security;
using KeePassLib.Utility;
using Microsoft.Win32.SafeHandles;

namespace SeclavePlugin
{
    // The plugin's dialogs and message boxes, shown the way KeePass shows its
    // own: while one is open KeePass knows it, and holds off locking the
    // workspace or exiting until it is closed.
    internal static class Dialogs
    {
        public static DialogResult Message(string text, string title, MessageBoxButtons buttons, MessageBoxIcon icon)
        {
            MessageService.ExternalIncrementMessageCount();
            try { return MessageBox.Show(text, title, buttons, icon); }
            finally { MessageService.ExternalDecrementMessageCount(); }
        }

        public static DialogResult ShowDialog(Form form, IWin32Window owner)
        {
            form.Load += delegate { GlobalWindowManager.AddWindow(form); };
            try { return form.ShowDialog(owner); }
            finally { GlobalWindowManager.RemoveWindow(form); }
        }

        // Runs a menu command; anything it did not expect is reported rather
        // than left to end the KeePass process
        public static void Guard(Action command)
        {
            try { command(); }
            catch (Exception ex)
            {
                MessageService.ShowWarning("The Seclave plugin stopped with an error it did not expect:", ex.Message);
            }
        }
    }

    // One entry as the export writes it. The label and group are made once,
    // then checked and written unchanged.
    public sealed class ExportRecord
    {
        public PwEntry Entry;
        public string Label;    // sanitized, not yet cut to 16
        public string Group;    // sanitized, not yet cut to 8
    }

    // What the export checks found. Collisions and errors block the export;
    // warnings ask.
    public sealed class ExportCheck
    {
        public readonly List<string> Collisions = new List<string>();
        public readonly List<string> Errors = new List<string>();
        public readonly List<string> Warnings = new List<string>();
    }

    internal sealed class ImportVolume
    {
        public string Path;
        public string Label;
        public long Size;
    }

    // One search for the Seclave's import volume, and what it found. A drive
    // is looked at only when the system's own list of drives, which asks no
    // drive anything, shows it to be a local removable disk: on Linux a FAT
    // mount of a removable disk on USB, on Windows a removable drive (on USB
    // where Windows can tell), on macOS a local FAT mount of a disk. Any other
    // drive, a network or virtual one above all, may never answer and is not
    // asked anything; and when the list cannot be read, no drive is.
    internal sealed class VolumeSearch
    {
        // The device's import volume is about 256 KB; a matching volume larger
        // than this is some other disk and is never written to
        public const long MaxImportVolume = 2 * 1024 * 1024;

        // A search started with Start that has not ended in this time is left
        // to end on its own, and nothing it finds is used
        public const int TimeLimitMs = 10000;

        public readonly List<ImportVolume> Found = new List<ImportVolume>();
        // Matches too large to be the device
        public readonly List<string> TooLarge = new List<string>();
        // Why the list of drives could not be read, or null
        public string Unreadable;
        // The drive being asked about itself, while that runs
        public volatile string Asking;
        // What stopped a search started with Start, or null
        public Exception Error;

        private readonly Stopwatch m_clock = new Stopwatch();
        private volatile bool m_done;

        // Runs the search on a worker thread of its own, so that a drive that
        // does not answer cannot hold up the caller
        public void Start()
        {
            var worker = new Thread(Work);
            worker.IsBackground = true;
            m_clock.Start();
            worker.Start();
        }

        public bool Done { get { return m_done; } }

        public bool OutOfTime { get { return !m_done && m_clock.ElapsedMilliseconds >= TimeLimitMs; } }

        private void Work()
        {
            try { Run(); }
            catch (Exception ex) { Error = ex; }
            m_done = true;
        }

        // Every volume that looks like a Seclave in import mode: a small FAT
        // volume whose label ends in SECLAVE (on Linux and macOS, its mount
        // point), holding SCIMPORT.STE
        public void Run()
        {
            List<ImportVolume> candidates;
            if (!NativeLib.IsUnix()) candidates = WindowsCandidates();
            else if (NativeLib.GetPlatformID() == PlatformID.MacOSX) candidates = MacCandidates();
            else candidates = LinuxCandidates();
            if (candidates == null) return;
            foreach (ImportVolume v in candidates)
            {
                Asking = v.Path;
                if (!File.Exists(Path.Combine(v.Path, "SCIMPORT.STE"))) continue;
                if (v.Size > MaxImportVolume) TooLarge.Add(v.Path);
                else Found.Add(v);
            }
            Asking = null;
        }

        // Linux: the kernel's list of the mounts this process sees. A
        // candidate is a FAT mount of a SCSI disk node whose disk sysfs calls
        // removable and places on USB.
        private static readonly Regex s_scsiDisk = new Regex(@"^/dev/sd[a-z]+[0-9]*$");

        private List<ImportVolume> LinuxCandidates()
        {
            string[] mounts;
            try { mounts = File.ReadAllLines("/proc/self/mountinfo"); }
            catch (IOException ex) { Unreadable = ex.Message; return null; }
            catch (UnauthorizedAccessException ex) { Unreadable = ex.Message; return null; }
            var candidates = new List<ImportVolume>();
            foreach (string line in mounts)
            {
                // ID, parent, device number, root, mount point, options,
                // optional fields, "-", file system type, source, options
                string[] f = line.Split(' ');
                int dash = Array.IndexOf(f, "-", 6);
                if (dash < 0 || dash + 2 >= f.Length) continue;
                if (f[dash + 1] != "vfat" && f[dash + 1] != "msdos") continue;
                string mountPoint = MountPath(f[4]);
                if (!mountPoint.EndsWith("SECLAVE", StringComparison.OrdinalIgnoreCase)) continue;
                if (!s_scsiDisk.IsMatch(f[dash + 2])) continue;
                // The device's sysfs directory with its links followed shows
                // where it sits (/sys/devices/.../usb2/.../block/sdb/sdb1):
                // below a USB host, but not below the virtual one through which
                // USB/IP attaches a device of another computer
                string device = UnixPath.Real("/sys/class/block/" + f[dash + 2].Substring("/dev/".Length));
                if (device == null || !device.Contains("/usb") || device.Contains("/vhci_hcd")) continue;
                // A partition's directory is in its disk's
                string disk = File.Exists(device + "/partition") ? Path.GetDirectoryName(device) : device;
                long sectors;
                if (SysfsValue(disk + "/removable") != "1" || !long.TryParse(SysfsValue(device + "/size"), out sectors)) continue;
                var v = new ImportVolume();
                v.Path = mountPoint;
                v.Label = mountPoint;
                v.Size = sectors * 512;
                candidates.Add(v);
            }
            return candidates;
        }

        // mountinfo writes a space, tab, newline or backslash in a path as a
        // backslash and three octal digits
        internal static string MountPath(string field)
        {
            return Regex.Replace(field, @"\\([0-7]{3})", delegate(Match m)
            {
                return ((char)Convert.ToInt32(m.Groups[1].Value, 8)).ToString();
            });
        }

        private static string SysfsValue(string path)
        {
            try { return File.ReadAllText(path).Trim(); }
            catch (IOException) { return null; }
            catch (UnauthorizedAccessException) { return null; }
        }

        // macOS: the kernel's list of mounts, read with MNT_NOWAIT, which asks
        // no file system for new figures. A candidate is a local FAT mount of
        // a disk.
        private const int MntNoWait = 2;
        private const uint MntLocal = 0x1000;
        // struct statfs with 64-bit inodes, the layout since macOS 10.6 and
        // the only one on Apple silicon: its size, and the offsets of
        // f_bsize, f_blocks, f_flags, f_fstypename, f_mntonname and
        // f_mntfromname
        private const int StatfsSize = 2168;
        private const int FBsize = 0, FBlocks = 8, FFlags = 64, FTypeName = 72, FOnName = 88, FFromName = 1112;

        // On an Intel Mac that layout's getfsstat has a name of its own, and
        // plain getfsstat has the old layout; Apple silicon has only the one
        [DllImport("libc", EntryPoint = "getfsstat$INODE64")]
        private static extern int GetFsStatIntel([Out] byte[] buffer, int size, int flags);
        [DllImport("libc", EntryPoint = "getfsstat")]
        private static extern int GetFsStat([Out] byte[] buffer, int size, int flags);

        private static int FsStat(byte[] buffer)
        {
            int size = buffer == null ? 0 : buffer.Length;
            try { return GetFsStatIntel(buffer, size, MntNoWait); }
            catch (EntryPointNotFoundException) { return GetFsStat(buffer, size, MntNoWait); }
        }

        private List<ImportVolume> MacCandidates()
        {
            if (IntPtr.Size != 8)
            {
                Unreadable = "on macOS, only a 64-bit KeePass reads it";
                return null;
            }
            int count = FsStat(null);
            byte[] mounts = new byte[(Math.Max(count, 0) + 8) * StatfsSize];
            if (count >= 0) count = FsStat(mounts);
            if (count < 0)
            {
                Unreadable = "getfsstat failed";
                return null;
            }
            var candidates = new List<ImportVolume>();
            int paths = 0;
            bool root = false;
            for (int i = 0; i < count; i++)
            {
                int at = i * StatfsSize;
                string on = CString(mounts, at + FOnName, 1024);
                if (on.StartsWith("/")) paths++;
                if (on == "/") root = true;
                if ((BitConverter.ToUInt32(mounts, at + FFlags) & MntLocal) == 0 || CString(mounts, at + FTypeName, 16) != "msdos" ||
                    !CString(mounts, at + FFromName, 1024).StartsWith("/dev/disk") ||
                    !on.EndsWith("SECLAVE", StringComparison.OrdinalIgnoreCase)) continue;
                var v = new ImportVolume();
                v.Path = on;
                v.Label = on;
                v.Size = BitConverter.ToUInt32(mounts, at + FBsize) * (long)BitConverter.ToUInt64(mounts, at + FBlocks);
                candidates.Add(v);
            }
            // Every mount point is a path, and one is the root; otherwise the
            // layout is not the one above
            if (paths < count || !root)
            {
                Unreadable = "getfsstat gave a layout this plugin does not know";
                return null;
            }
            return candidates;
        }

        private static string CString(byte[] buffer, int offset, int size)
        {
            int end = Array.IndexOf(buffer, (byte)0, offset, size);
            return Encoding.UTF8.GetString(buffer, offset, (end < 0 ? offset + size : end) - offset);
        }

        // Windows: the drive letters and the type Windows gives each drive,
        // which asks no drive. A candidate is a removable drive other than the
        // floppy drives A: and B:, on USB unless Windows cannot tell its bus.
        private List<ImportVolume> WindowsCandidates()
        {
            DriveInfo[] drives;
            try { drives = DriveInfo.GetDrives(); }
            catch (IOException ex) { Unreadable = ex.Message; return null; }
            catch (UnauthorizedAccessException ex) { Unreadable = ex.Message; return null; }
            var candidates = new List<ImportVolume>();
            foreach (DriveInfo drive in drives)
            {
                string letter = drive.Name.Substring(0, 1).ToUpperInvariant();
                if (letter == "A" || letter == "B") continue;
                try
                {
                    if (drive.DriveType != DriveType.Removable) continue;
                    // From here on the drive itself is asked
                    Asking = drive.Name;
                    int bus = WindowsBus(drive.Name);
                    if (bus >= 0 && bus != BusTypeUsb) continue;
                    if (!drive.IsReady || !IsSeclaveFileSystem(drive.DriveFormat) ||
                        !drive.VolumeLabel.EndsWith("SECLAVE", StringComparison.OrdinalIgnoreCase)) continue;
                    var v = new ImportVolume();
                    v.Path = drive.RootDirectory.ToString();
                    v.Label = drive.VolumeLabel;
                    v.Size = drive.TotalSize;
                    candidates.Add(v);
                }
                // A disconnected or inaccessible drive must not prevent checking other drives
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
                catch (SecurityException) { }
            }
            return candidates;
        }

        private static bool IsSeclaveFileSystem(string format)
        {
            return string.Equals(format, "msdos", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(format, "vfat", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(format, "FAT", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(format, "FAT32", StringComparison.OrdinalIgnoreCase);
        }

        private const uint FileShareReadWrite = 3;
        private const uint OpenExisting = 3;
        private const uint IoctlStorageQueryProperty = 0x2d1400;
        private const int BusTypeUsb = 7;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security,
            uint creation, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(SafeFileHandle device, uint code, byte[] input, int inputSize,
            [Out] byte[] output, int outputSize, out int returned, IntPtr overlapped);

        // The bus of a drive's disk as Windows reports it, asked of the volume
        // opened for no access, which reads nothing from the medium; -1 if
        // Windows does not tell
        private static int WindowsBus(string root)
        {
            try
            {
                using (SafeFileHandle volume = CreateFile(@"\\.\" + root.TrimEnd('\\'), 0, FileShareReadWrite, IntPtr.Zero,
                    OpenExisting, 0, IntPtr.Zero))
                {
                    if (volume.IsInvalid) return -1;
                    // STORAGE_PROPERTY_QUERY: StorageDeviceProperty, PropertyStandardQuery
                    var query = new byte[12];
                    var descriptor = new byte[1024];
                    int returned;
                    if (!DeviceIoControl(volume, IoctlStorageQueryProperty, query, query.Length, descriptor, descriptor.Length,
                            out returned, IntPtr.Zero) || returned < 32) return -1;
                    // STORAGE_DEVICE_DESCRIPTOR.BusType
                    return BitConverter.ToInt32(descriptor, 28);
                }
            }
            catch (DllNotFoundException) { return -1; }
            catch (EntryPointNotFoundException) { return -1; }
        }
    }

    // The dialog in front of a VolumeSearch while it runs, with Cancel. It
    // closes when the search ends, when it runs out of time, and on Cancel,
    // at once in each case, whatever the drive being asked is doing.
    internal sealed class VolumeSearchForm : Form
    {
        public readonly VolumeSearch Search = new VolumeSearch();
        public bool TimedOut;

        private readonly System.Windows.Forms.Timer m_timer = new System.Windows.Forms.Timer();

        public VolumeSearchForm()
        {
            Text = "Looking for the Seclave";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(400, 90);
            var status = new Label();
            status.Text = "Looking for the Seclave's drive in import mode...";
            status.SetBounds(12, 12, 376, 30);
            Controls.Add(status);
            var cancel = new Button();
            cancel.Text = "Cancel";
            cancel.DialogResult = DialogResult.Cancel;
            cancel.SetBounds(303, 52, 85, 28);
            Controls.Add(cancel);
            CancelButton = cancel;

            m_timer.Interval = 100;
            m_timer.Tick += delegate
            {
                if (Search.Done)
                {
                    DialogResult = DialogResult.OK;
                }
                else if (Search.OutOfTime)
                {
                    TimedOut = true;
                    DialogResult = DialogResult.Abort;
                }
            };
            Shown += delegate
            {
                Search.Start();
                m_timer.Start();
            };
            FormClosed += delegate { m_timer.Dispose(); };
        }
    }

    public sealed class SeclavePluginExt : Plugin
    {
        private const int m_labelMaxLength = 16;
        private const int m_groupMaxLength = 8;
        private const int m_usernameMaxLength = 50;
        private const int m_passwordMaxLength = 50;
        private const int m_notesMaxLength = 83;
        private const int m_maxEntries = 500;

        private const string m_toolTitle = "Seclave Plugin";

        private IPluginHost m_Host;
        private ToolStripSeparator m_Separator;
        private ToolStripMenuItem m_ToolsMenu;
        private ToolStripMenuItem m_GroupMenu;
        private ToolStripMenuItem m_EntryMenu;
        private ToolStripSeparator m_ToolbarSeparator;
        private ToolStripButton m_SyncButton;

        // A menu item that runs a command, reporting what it throws
        private static ToolStripMenuItem Item(string text, Action command)
        {
            var item = new ToolStripMenuItem(text);
            item.Click += delegate { Dialogs.Guard(command); };
            return item;
        }

        private static ToolStripMenuItem Submenu(params ToolStripItem[] items)
        {
            var submenu = new ToolStripMenuItem("Seclave");
            submenu.DropDownItems.AddRange(items);
            // A drop-down made here has the default font, not the one KeePass
            // gives its menus: use the font of the menu it opens from
            submenu.DropDownOpening += delegate
            {
                if (submenu.Owner != null) submenu.DropDown.Font = submenu.Owner.Font;
            };
            return submenu;
        }

        public override bool Initialize(IPluginHost host)
        {
            m_Host = host;

            // A Seclave submenu in the Tools menu, for the whole database, and
            // in the right-click menus of a group and of entries, for those
            // entries only. The sync first: it is the preferred way onto the
            // device, and the export to the import file is the fallback.
            ToolStripItemCollection menu = host.MainWindow.ToolsMenu.DropDownItems;
            m_Separator = new ToolStripSeparator();
            menu.Add(m_Separator);
            m_ToolsMenu = Submenu(
                Item("Sync with Seclave...", delegate { SyncCommand.SyncAll(m_Host); }),
                Item("Push to Seclave...", delegate { SyncCommand.PushAll(m_Host); }),
                Item("Pull from Seclave...", delegate { SyncCommand.PullAll(m_Host); }),
                new ToolStripSeparator(),
                Item("Import Seclave backup...", delegate { SyncCommand.ImportBackup(m_Host); }),
                Item("Export to Seclave import file...", OnSeclaveExport),
                new ToolStripSeparator(),
                Item("Seclave settings...", OnSeclaveSettings));
            menu.Add(m_ToolsMenu);

            m_GroupMenu = Submenu(
                Item("Sync with Seclave...", delegate { SyncCommand.SyncGroup(m_Host); }),
                Item("Push to Seclave...", delegate { SyncCommand.PushGroup(m_Host); }),
                Item("Pull from Seclave...", delegate { SyncCommand.PullGroup(m_Host); }),
                new ToolStripSeparator(),
                Item("Export this group to Seclave import file...", OnSeclaveGroupExport));
            host.MainWindow.GroupContextMenu.Items.Add(m_GroupMenu);

            m_EntryMenu = Submenu(
                Item("Sync with Seclave...", delegate { SyncCommand.SyncSelected(m_Host); }),
                Item("Push to Seclave...", delegate { SyncCommand.PushSelected(m_Host); }),
                Item("Pull from Seclave...", delegate { SyncCommand.PullSelected(m_Host); }),
                new ToolStripSeparator(),
                Item("Reset Seclave label...", OnResetLabels));
            host.MainWindow.EntryContextMenu.Items.Add(m_EntryMenu);

            // The sync also as a button at the end of KeePass's toolbar, where
            // KeePass puts buttons of its own that a user adds. KeePass gives
            // plugins no access to its toolbar, so it is found by the name of
            // its control; a KeePass without one gets no button.
            Control[] found = host.MainWindow.Controls.Find("m_toolMain", true);
            ToolStrip toolbar = found.Length > 0 ? found[0] as ToolStrip : null;
            if (toolbar != null)
            {
                m_ToolbarSeparator = new ToolStripSeparator();
                toolbar.Items.Add(m_ToolbarSeparator);
                m_SyncButton = new ToolStripButton();
                m_SyncButton.DisplayStyle = ToolStripItemDisplayStyle.Image;
                m_SyncButton.Image = ToolbarIcon(toolbar.ImageScalingSize);
                m_SyncButton.ToolTipText = "Sync with Seclave";
                m_SyncButton.Click += delegate { Dialogs.Guard(delegate { SyncCommand.SyncAll(m_Host); }); };
                toolbar.Items.Add(m_SyncButton);
                host.MainWindow.UIStateUpdated += OnUIStateUpdated;
                OnUIStateUpdated(null, EventArgs.Empty);
            }

            return true;
        }

        public override void Terminate()
        {
            ToolStripItemCollection menu = m_Host.MainWindow.ToolsMenu.DropDownItems;
            menu.Remove(m_Separator);
            menu.Remove(m_ToolsMenu);
            m_Host.MainWindow.GroupContextMenu.Items.Remove(m_GroupMenu);
            m_Host.MainWindow.EntryContextMenu.Items.Remove(m_EntryMenu);

            ToolStrip toolbar = m_SyncButton != null ? m_SyncButton.Owner : null;
            if (toolbar != null)
            {
                m_Host.MainWindow.UIStateUpdated -= OnUIStateUpdated;
                toolbar.Items.Remove(m_ToolbarSeparator);
                toolbar.Items.Remove(m_SyncButton);
            }
        }

        // As KeePass's own buttons for a database, the sync button is enabled
        // only while one is open
        private void OnUIStateUpdated(object sender, EventArgs e)
        {
            m_SyncButton.Enabled = m_Host.Database != null && m_Host.Database.IsOpen;
        }

        // The toolbar picture, the key of the Seclave mark: one of the PNGs
        // embedded in the plugin, 16 pixels, or 32 for a toolbar scaled up
        // for the display, made the toolbar's image size. KeePass names an
        // embedded file after the project's assembly, as Visual Studio does.
        internal static Image ToolbarIcon(Size size)
        {
            string name = size.Height > 16 ? "SeclavePlugin.SyncButton32.png" : "SeclavePlugin.SyncButton16.png";
            using (Stream png = typeof(SeclavePluginExt).Assembly.GetManifestResourceStream(name))
            {
                if (png == null) return null;
                using (var picture = new Bitmap(png))
                    return new Bitmap(picture, size);
            }
        }

        private static void writeTruncatedOrPadded(BinaryWriter writer, string s, int length)
        {
            int l = Math.Min(length, s.Length);
            writer.Write(s.Substring(0, l).ToCharArray());
            for (int i = l; i < length; i++)
            {
                writer.Write((byte)0);
            }
        }

        // ReadString() would leave the plaintext cached in the entry's field
        // for the rest of the session; ReadUtf8() hands out a copy
        internal static string getProtectedString(ProtectedString ps)
        {
            if (ps == null) return "";
            byte[] utf8 = ps.ReadUtf8();
            try { return StrUtil.Utf8.GetString(utf8); }
            finally { MemUtil.ZeroByteArray(utf8); }
        }

        private static void writeNullEntry(BinaryWriter writer)
        {
            /* Null Entry Cookie */
            writer.Write((byte)0x08);
            writer.Write((byte)0xf3);
            writer.Write((byte)0x25);
            writer.Write((byte)0x00);

            /* All ignored */
            for (int i = 0; i < 220+32; i++)
            {
                writer.Write((byte)0);
            }
        }

        private static void writeEntry(BinaryWriter writer, PwDatabase db, ExportRecord record)
        {
            PwEntry entry = record.Entry;

            /* Entry Cookie */
            writer.Write((byte)0x08);
            writer.Write((byte)0xf3);
            writer.Write((byte)0x24);
            writer.Write((byte)0x00);

            writeTruncatedOrPadded(writer, record.Label, m_labelMaxLength);

            /* Status */
            writer.Write((byte)0);

            writeTruncatedOrPadded(writer, record.Group, m_groupMaxLength);
            writeTruncatedOrPadded(writer, FieldValue(db, entry, "UserName"), m_usernameMaxLength);
            writeTruncatedOrPadded(writer, FieldValue(db, entry, "Password"), m_passwordMaxLength);
            writeTruncatedOrPadded(writer, FieldValue(db, entry, "Notes"), m_notesMaxLength);

            /* Zero Padding */
            for (int i = 0; i < 12+32; i++)
            {
                writer.Write((byte)0);
            }
        }

        // Entries in the Recycle bin, or in any group below it, are neither
        // exported nor synced
        internal static bool IsInRecycleBin(PwDatabase db, PwEntry entry)
        {
            for (PwGroup group = entry.ParentGroup; group != null; group = group.ParentGroup)
            {
                // PwUuid has no == operator: compare the bytes, not the objects
                if (group.Uuid.Equals(db.RecycleBinUuid) ||
                    (group.Name == "Recycle Bin")) return true;
            }
            return false;
        }

        internal static string EntryPath(PwEntry entry)
        {
            return entry.ParentGroup.Name + "/" + getProtectedString(entry.Strings.Get("Title"));
        }

        internal static bool HasNonLatin1(string value)
        {
            foreach (char c in value)
                if (c > 0xff) return true;
            return false;
        }

        // The entry's username, password or notes as it goes to the Seclave,
        // with KeePass's references followed: {REF:...} gives the other
        // entry's field, and {USERNAME}, {S:...} and the like the entry's own.
        // Nothing else is filled in and nothing is run: {CLIPBOARD}, {DT_...},
        // {CMD:...} and one-time passwords stay as they stand. KeePass reads
        // the fields it follows as it does for auto-type, which leaves them
        // cached (see getProtectedString), so only a value with a '{' goes to
        // it.
        internal static string FieldValue(PwDatabase db, PwEntry entry, string field)
        {
            string value = getProtectedString(entry.Strings.Get(field));
            if (value.IndexOf('{') < 0) return value;
            var context = new SprContext(entry, db, SprCompileFlags.Deref);
            // Otherwise {PASSWORD} gives asterisks while KeePass hides its password column
            context.ForcePlainTextPasswords = true;
            return SprEngine.Compile(value, context);
        }

        // KeePass follows at most this many steps from a field (a field it
        // names, then a field that one names, and so on), and leaves out
        // what lies deeper without a word: a reference that comes back to
        // itself, or one nested deeper, gives a value with parts missing
        private const int MaxReferenceSteps = 11;

        // The first of the entry's username, password and notes in which
        // KeePass cannot follow every reference to its end, by name; null if
        // it can follow them all
        internal static string UnfollowableField(PwDatabase db, PwEntry entry)
        {
            var depths = new Dictionary<string, int>();
            if (!Followable(db, entry, "UserName", depths)) return "username";
            if (!Followable(db, entry, "Password", depths)) return "password";
            if (!Followable(db, entry, "Notes", depths)) return "notes";
            return null;
        }

        private static bool Followable(PwDatabase db, PwEntry entry, string field, Dictionary<string, int> depths)
        {
            int depth = ReferenceDepth(db, entry, field, depths);
            return depth >= 0 && depth <= MaxReferenceSteps;
        }

        // The most steps KeePass takes from the entry's field to fill it in,
        // or -1 if it can come back to a field on its way. depths holds the
        // fields already followed, -1 for those still being followed.
        private static int ReferenceDepth(PwDatabase db, PwEntry entry, string field, Dictionary<string, int> depths)
        {
            string node = entry.Uuid.ToHexString() + "/" + field;
            int depth;
            if (depths.TryGetValue(node, out depth)) return depth;
            depths[node] = -1;
            int deepest = 0;
            string text = field == null ? "" : getProtectedString(entry.Strings.Get(field));
            foreach (KeyValuePair<PwEntry, string> step in ReferenceSteps(db, entry, text))
            {
                int below = ReferenceDepth(db, step.Key, step.Value, depths);
                if (below < 0) return -1;
                deepest = Math.Max(deepest, below + 1);
            }
            depths[node] = deepest;
            return deepest;
        }

        // Where KeePass goes from a field's text to fill it in, one step each:
        // to the fields of the entry its placeholders name ({USERNAME},
        // {S:Pin}, the URL for a {URL:...} part), and to the field of the
        // entry each {REF:...} finds (no field for {REF:I@...}, the ID)
        private static List<KeyValuePair<PwEntry, string>> ReferenceSteps(PwDatabase db, PwEntry entry, string text)
        {
            var steps = new List<KeyValuePair<PwEntry, string>>();
            if (text.IndexOf('{') < 0) return steps;
            var names = new List<string>(PwDefs.GetStandardFields());
            foreach (string name in entry.Strings.GetKeys())
                if (!names.Contains(name)) names.Add(name);
            foreach (string name in names)
            {
                string placeholder = PwDefs.IsStandardField(name) ? "{" + name + "}" : "{S:" + name + "}";
                if (text.IndexOf(placeholder, StringComparison.OrdinalIgnoreCase) >= 0)
                    steps.Add(new KeyValuePair<PwEntry, string>(entry, name));
            }
            if (text.IndexOf("{URL:", StringComparison.OrdinalIgnoreCase) >= 0)
                steps.Add(new KeyValuePair<PwEntry, string>(entry, PwDefs.UrlField));
            if (text.IndexOf("{REF:", StringComparison.OrdinalIgnoreCase) < 0) return steps;

            // KeePass fills in the fields a reference is built from, as in
            // {REF:P@I:{S:Id}}, before it looks the reference up; so does this,
            // with the references hidden from it
            var context = new SprContext(entry, db, SprCompileFlags.Deref);
            context.ForcePlainTextPasswords = true;
            string hidden = "\u0001" + Guid.NewGuid().ToString("N") + "\u0001";
            string filled = SprEngine.Compile(StrUtil.ReplaceCaseInsensitive(text, "{REF:", hidden), context).Replace(hidden, "{REF:");
            for (int start = filled.IndexOf("{REF:"); start >= 0; start = filled.IndexOf("{REF:", start + 1))
            {
                int end = filled.IndexOf('}', start);
                if (end < 0) break;
                char scan, wanted;
                PwEntry target = SprEngine.FindRefTarget(filled.Substring(start, end - start + 1), context, out scan, out wanted);
                // KeePass leaves a reference to an entry that is gone as it stands
                if (target == null) continue;
                string field;
                switch (wanted)
                {
                    case 'T': field = PwDefs.TitleField; break;
                    case 'U': field = PwDefs.UserNameField; break;
                    case 'P': field = PwDefs.PasswordField; break;
                    case 'A': field = PwDefs.UrlField; break;
                    case 'N': field = PwDefs.NotesField; break;
                    case 'I': field = null; break;
                    // and so a reference to a field it does not know
                    default: continue;
                }
                steps.Add(new KeyValuePair<PwEntry, string>(target, field));
            }
            return steps;
        }

        // Placeholders KeePass fills in when it uses a field. The Seclave would
        // hold and type any of them as text: what FieldValue leaves, such as
        // {CLIPBOARD}, {DT_SIMPLE} or a reference to an entry that is gone.
        private static readonly string[] m_placeholders = {
            "REF:", "S:", "TITLE}", "USERNAME}", "PASSWORD}", "PASSWORD_ENC}", "NOTES}", "URL", "GROUP", "UUID}",
            "DB_", "ENV_", "DT_", "T-REPLACE-RX:", "T-CONV:", "CMD:", "C:", "PICKCHARS", "PICKFIELD}", "CLIPBOARD",
            "NEWPASSWORD", "HMACOTP}", "TIMEOTP}", "APPDIR}", "DOCDIR}", "BASE" };

        internal static bool HasPlaceholder(string value)
        {
            for (int i = value.IndexOf('{'); i >= 0; i = value.IndexOf('{', i + 1))
                foreach (string p in m_placeholders)
                    if (string.Compare(value, i + 1, p, 0, p.Length, StringComparison.OrdinalIgnoreCase) == 0) return true;
            return false;
        }

        internal static List<ExportRecord> CreateRecords(PwDatabase db, PwGroup selectedGroup, LabelOptions options)
        {
            var records = new List<ExportRecord>();
            // The handler always returns true: false would end the traversal
            selectedGroup.TraverseTree(TraversalMethod.PreOrder, null, delegate(PwEntry entry)
            {
                if (IsInRecycleBin(db, entry) || SyncKey.IsKeyEntry(entry)) return true;
                var r = new ExportRecord();
                r.Entry = entry;
                // An entry that already has a Seclave label keeps it, so that
                // moving or renaming it does not put it on the device twice
                string stored = options.KeepLabels ? SyncData.StoredLabel(entry) : null;
                r.Label = stored != null ? stored : Labels.For(entry, options);
                r.Group = Labels.Group(entry, options);
                records.Add(r);
                return true;
            });
            return records;
        }

        // Records on each written entry the label it was written under. True
        // if any entry changed.
        internal static bool StoreLabels(List<ExportRecord> records)
        {
            bool changed = false;
            foreach (ExportRecord r in records)
                if (SyncData.AssignLabel(r.Entry, LabelChars.Cut(r.Label, m_labelMaxLength))) changed = true;
            return changed;
        }

        private static void checkField(string name, string value, int maxLength, string entryPath, ExportCheck check)
        {
            int n = maxLength - value.Length;
            if (n < 0)
            {
                check.Warnings.Add(String.Format("{0} is {1} characters too long in {2}", name, -n, entryPath));
            }

            // The device stores Latin-1; anything outside it would be written as '?'
            if (HasNonLatin1(value))
            {
                check.Warnings.Add(String.Format("{0} contains characters that cannot be stored on the device (replaced by '?') in {1}", name, entryPath));
            }
        }

        internal static ExportCheck CheckRecords(PwDatabase db, List<ExportRecord> records)
        {
            return CheckRecords(db, records, null);
        }

        // The one place the export is checked. Labels are compared as the
        // device stores them: cut to 16 characters, case folded. outside:
        // for an export of one group, the records of every other entry,
        // which are probably on the device already.
        internal static ExportCheck CheckRecords(PwDatabase db, List<ExportRecord> records, List<ExportRecord> outside)
        {
            var check = new ExportCheck();
            var labels = new Dictionary<string, ExportRecord>();
            var outsideLabels = new Dictionary<string, ExportRecord>();
            if (outside != null)
            {
                foreach (ExportRecord o in outside)
                {
                    string key = LabelChars.Fold(LabelChars.Cut(o.Label, m_labelMaxLength));
                    if (!outsideLabels.ContainsKey(key)) outsideLabels.Add(key, o);
                }
            }
            foreach (ExportRecord r in records)
            {
                string entryPath = EntryPath(r.Entry);
                string label = LabelChars.Cut(r.Label, m_labelMaxLength);
                if (label.Length == 0)
                {
                    check.Errors.Add("The label is empty for " + entryPath);
                    continue;
                }
                ExportRecord first;
                if (labels.TryGetValue(LabelChars.Fold(label), out first))
                {
                    check.Collisions.Add("\"" + label + "\": " + EntryPath(first.Entry) + " and " + entryPath);
                    continue;
                }
                labels.Add(LabelChars.Fold(label), r);
                if (outsideLabels.TryGetValue(LabelChars.Fold(label), out first))
                    check.Warnings.Add("\"" + label + "\" is also the label of " + EntryPath(first.Entry) +
                        ", which is not in this export but is probably on the device; the device keeps one of the two");

                // The device keeps its web logins in this group
                if (LabelChars.Fold(LabelChars.Cut(r.Group, m_groupMaxLength)) == Wire.WwwfillGroup)
                    check.Errors.Add("The group name wwwfill is reserved on the device for its web logins: " + entryPath);

                string unfollowable = UnfollowableField(db, r.Entry);
                if (unfollowable != null)
                    check.Errors.Add("A reference in the " + unfollowable + " of " + entryPath + " cannot be followed " +
                        "(it may refer to itself or be nested too deeply)");

                // A password with '?' in place of a letter, or cut short, is a wrong password
                string password = FieldValue(db, r.Entry, "Password");
                if (HasNonLatin1(password))
                    check.Errors.Add("Password contains characters the device cannot store in " + entryPath);
                if (password.Length > m_passwordMaxLength)
                    check.Errors.Add("Password is longer than " + m_passwordMaxLength + " characters in " + entryPath +
                        "; the Seclave would hold a wrong password");

                string username = FieldValue(db, r.Entry, "UserName");
                string notes = FieldValue(db, r.Entry, "Notes");
                if (HasPlaceholder(username) || HasPlaceholder(password) || HasPlaceholder(notes))
                    check.Errors.Add("A KeePass placeholder the plugin does not fill in, such as {CLIPBOARD}, or a reference to " +
                        "an entry that is gone, in the username, password or notes of " + entryPath +
                        "; the Seclave would hold the placeholder text");

                checkField("Label", r.Label, m_labelMaxLength, entryPath, check);
                checkField("Group", r.Group, m_groupMaxLength, entryPath, check);
                checkField("Username", username, m_usernameMaxLength, entryPath, check);
                checkField("Notes", notes, m_notesMaxLength, entryPath, check);
            }
            if (records.Count > m_maxEntries)
                check.Errors.Add(String.Format("Trying to export {0} too many entries", records.Count - m_maxEntries));
            return check;
        }

        // The whole import file: the records, then empty slots up to 500
        internal static void WriteRecords(PwDatabase db, Stream stream, List<ExportRecord> records)
        {
            var writer = new BinaryWriter(stream, Encoding.GetEncoding("ISO-8859-1"));
            foreach (ExportRecord r in records) writeEntry(writer, db, r);
            for (int i = records.Count; i < m_maxEntries; i++) writeNullEntry(writer);
            writer.Flush();
        }

        private void OnSeclaveGroupExport()
        {
            ExportDatabase(m_Host.MainWindow.GetSelectedGroup());
        }

        private void OnSeclaveExport()
        {
            ExportDatabase(m_Host.Database.RootGroup);
        }

        private void OnSeclaveSettings()
        {
            LabelOptions options = LabelOptions.Load(m_Host.CustomConfig);
            string rootName = m_Host.Database != null && m_Host.Database.IsOpen ? m_Host.Database.RootGroup.Name : null;
            using (var form = new SettingsForm(options, rootName))
            {
                if (Dialogs.ShowDialog(form, m_Host.MainWindow) != DialogResult.OK) return;
                options.SetLabelling(form.Pattern, form.EmptyRootGroup);
                options.KeepLabels = form.KeepLabels;
            }
            options.Save(m_Host.CustomConfig);
        }

        // Forgets the Seclave label, and any sync state, of the selected
        // entries, so that their next export or sync gives them the label the
        // pattern gives them now
        private void OnResetLabels()
        {
            var labelled = new List<PwEntry>();
            PwEntry[] selected = m_Host.MainWindow.GetSelectedEntries();
            if (selected != null)
                foreach (PwEntry e in selected)
                    if (e.CustomData.Get(SyncData.LabelKey) != null) labelled.Add(e);
            if (labelled.Count == 0)
            {
                Dialogs.Message("None of the selected entries has a Seclave label.", m_toolTitle, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            string text = labelled.Count + " of the selected entries have a Seclave label. Forget it? Their next export or " +
                "sync gives them the label the label pattern gives them now. A copy the Seclave holds under the old label " +
                "stays there until you delete it on the Seclave.";
            if (Dialogs.Message(text, m_toolTitle, MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK) return;
            foreach (PwEntry e in labelled) SyncData.RemoveBaseline(e);
            m_Host.MainWindow.UpdateUI(false, null, false, null, false, null, true);
        }

        // The volume to write to, or null if the user gives up: nothing is
        // written unless exactly one volume qualifies
        private ImportVolume ChooseImportVolume()
        {
            while (true)
            {
                string text;
                using (var form = new VolumeSearchForm())
                {
                    if (Dialogs.ShowDialog(form, m_Host.MainWindow) == DialogResult.Cancel) return null;
                    VolumeSearch search = form.Search;
                    if (form.TimedOut)
                    {
                        text = search.Asking != null ?
                            search.Asking + ": the drive did not answer." + Environment.NewLine + "Nothing was written. Unplug it and try again." :
                            "Looking for the Seclave's drive did not finish in time. Nothing was written.";
                    }
                    else if (search.Error != null)
                    {
                        text = "Looking for the Seclave's drive failed: " + search.Error.Message;
                    }
                    else if (search.Unreadable != null)
                    {
                        text = "The list of drives could not be read, so no drive was looked at (" + search.Unreadable + ").";
                    }
                    else if (search.Found.Count == 1)
                    {
                        return search.Found[0];
                    }
                    else if (search.Found.Count > 1)
                    {
                        var paths = new List<string>();
                        foreach (ImportVolume v in search.Found) paths.Add(v.Path);
                        text = "More than one drive looks like a Seclave in import mode:" + Environment.NewLine +
                            string.Join(Environment.NewLine, paths.ToArray()) + Environment.NewLine +
                            "Nothing was written. Unplug all but the Seclave and try again.";
                    }
                    else
                    {
                        text = "No Seclave in import mode found. On the Seclave, choose import and wait for its drive, " +
                            "labelled SECLAVE, to appear; then try again.";
                        if (search.TooLarge.Count > 0)
                            text += Environment.NewLine + "Not used, too large to be a Seclave: " + string.Join(", ", search.TooLarge.ToArray());
                    }
                }
                if (Dialogs.Message(text, m_toolTitle, MessageBoxButtons.RetryCancel, MessageBoxIcon.Warning) != DialogResult.Retry)
                    return null;
            }
        }

        private void ExportDatabase(PwGroup selectedGroup)
        {
            PwDatabase db = m_Host.Database;
            // Let user know if there are any prerequisites missing for export
            if (!db.IsOpen)
            {
                Dialogs.Message("Password database needs to be unlocked for export", m_toolTitle, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (selectedGroup == null)
            {
                Dialogs.Message("Select a group to export.", m_toolTitle, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            LabelOptions options = LabelOptions.Load(m_Host.CustomConfig);
            string patternError = LabelPattern.Error(options.Pattern);
            if (patternError != null)
            {
                Dialogs.Message("The saved label pattern is not valid. " + patternError + Environment.NewLine +
                    "Correct it under Tools > Seclave > Seclave settings...", m_toolTitle, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            List<ExportRecord> records = CreateRecords(db, selectedGroup, options);
            List<ExportRecord> outside = null;
            if (selectedGroup != db.RootGroup)
            {
                var exported = new Dictionary<PwEntry, bool>();
                foreach (ExportRecord r in records) exported[r.Entry] = true;
                outside = new List<ExportRecord>();
                foreach (ExportRecord r in CreateRecords(db, db.RootGroup, options))
                    if (!exported.ContainsKey(r.Entry)) outside.Add(r);
            }
            if (!EntryChecker(db, records, outside))
            {
                return;
            }

            ImportVolume target = ChooseImportVolume();
            if (target == null) return;
            string named = target.Path;
            if (target.Label != target.Path) named += ", label " + target.Label;
            string confirm = "Sync with Seclave is the safer way; it writes no file. Continue with the export?" +
                Environment.NewLine + Environment.NewLine +
                "Write " + records.Count + " entries, with their usernames, passwords and notes unencrypted, to the Seclave at" +
                Environment.NewLine + Environment.NewLine + "    " + named + " (" + ((target.Size + 1023) / 1024) + " KB)?" +
                Environment.NewLine + Environment.NewLine + "The Seclave takes the entries in while the file is being written.";
            if (Dialogs.Message(confirm, m_toolTitle, MessageBoxButtons.OKCancel, MessageBoxIcon.Information) != DialogResult.OK) return;
            if (!db.IsOpen)
            {
                Dialogs.Message("KeePass locked the database; nothing was written.", m_toolTitle, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            // Written once, in place and in order. The device takes in what it
            // receives as import records while the file is being written, so a
            // temporary file and a rename would import the data just the same,
            // keep nothing safe, and need room for two files on a small volume.
            try
            {
                using (var fs = new FileStream(Path.Combine(target.Path, "seclave.imp"), FileMode.Create))
                {
                    WriteRecords(db, fs, records);
                }
            }
            catch (Exception ex)
            {
                Dialogs.Message("Could not write the export file: " + ex.Message + Environment.NewLine + Environment.NewLine +
                    "The Seclave may already hold part of the file. Unplug it, choose import on it again, and export again.",
                    m_toolTitle, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            bool labelled = options.KeepLabels && StoreLabels(records);
            if (labelled) m_Host.MainWindow.UpdateUI(false, null, false, null, false, null, true);

            string done = records.Count + " entries written to " + target.Path + "." + Environment.NewLine + Environment.NewLine +
                "Check that the Seclave shows Import OK, then unplug it; the import file exists only while the Seclave " +
                "is in import mode.";
            if (labelled) done += Environment.NewLine + Environment.NewLine + "Save the database to keep the entries' Seclave labels.";
            Dialogs.Message(done, "Export complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private bool EntryChecker(PwDatabase db, List<ExportRecord> records, List<ExportRecord> outside)
        {
            ExportCheck check = CheckRecords(db, records, outside);
            if (check.Collisions.Count > 0)
            {
                var message = "These entries get the same label on the device (labels keep 16 characters, and upper and lower case are the same):" +
                    Environment.NewLine + string.Join(Environment.NewLine, check.Collisions.ToArray()) + Environment.NewLine +
                    "Rename one of each pair, or change the label pattern under Tools > Seclave > Seclave settings...";
                Dialogs.Message(message, "Export validation", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            if (check.Errors.Count > 0)
            {
                Dialogs.Message(string.Join(Environment.NewLine, check.Errors.ToArray()), "Export validation", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            if (check.Warnings.Count > 0)
            {
                var message = "During check of " + records.Count + " entries, " + check.Warnings.Count + " fields would be truncated or altered, or labels shared: " + Environment.NewLine;
                message += string.Join(Environment.NewLine, check.Warnings.ToArray());
                message += Environment.NewLine + "Continue anyway?";
                if (Dialogs.Message(message, "Export validation", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.No)
                {
                    return false;
                }
            }

            return true;
        }
    }
}
