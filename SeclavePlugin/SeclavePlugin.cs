using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePassLib;
using KeePassLib.Security;

namespace SeclavePlugin
{
    public sealed class SeclavePluginExt : Plugin
    {
        private const int m_labelMaxLength = 16;
        private const int m_groupMaxLength = 8;
        private const int m_usernameMaxLength = 50;
        private const int m_passwordMaxLength = 50;
        private const int m_notesMaxLength = 83;
        private const int m_maxEntries = 500;

        private const string m_toolTitle = "Seclave Plugin";

        private int m_entriesWritten;

        private IPluginHost m_Host;
        private ToolStripSeparator m_Separator;
        private ToolStripMenuItem m_MenuItem;
        private ToolStripMenuItem m_ContextMenuItem;

        public override bool Initialize(IPluginHost host)
        {
            m_Host = host;

            // Add option to keepass menu
            ToolStripItemCollection menu = host.MainWindow.ToolsMenu.DropDownItems;
            m_Separator = new ToolStripSeparator();
            menu.Add(m_Separator);

            m_MenuItem = new ToolStripMenuItem();
            m_MenuItem.Text = "Export all groups to Seclave...";
            m_MenuItem.Click += OnSeclaveExport;
            menu.Add(m_MenuItem);

            // Add option to entry context menus
            var contextMenu = host.MainWindow.GroupContextMenu.Items;
            m_ContextMenuItem = new ToolStripMenuItem("Export this group to Seclave...");
            m_ContextMenuItem.Click += OnSeclaveGroupExport;
            contextMenu.Add(m_ContextMenuItem);

            return true;
        }

        public override void Terminate()
        {
            ToolStripItemCollection menu = m_Host.MainWindow.ToolsMenu.DropDownItems;
            menu.Remove(m_Separator);
            menu.Remove(m_MenuItem);

            var contextMenu = m_Host.MainWindow.GroupContextMenu.Items;
            contextMenu.Remove(m_ContextMenuItem);
        }

        private static bool writeTruncatedOrPadded(BinaryWriter writer, string s, int length)
        {
            // Return value is wether this entry was truncated or not
            int l = Math.Min(length, s.Length);
            string s2 = s.Substring(0, l);
            writer.Write(s2.ToCharArray());
            for (int i = l; i < length; i++)
            {
                writer.Write((byte)0);
            }
            return s.Length > length;
        }

        private static string getProtectedString(ProtectedString ps)
        {
            return ps == null ? "" : ps.ReadString();
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

        private static String GenerateLabel(PwEntry entry)
        {
            string group = entry.ParentGroup.Name;

            string title = getProtectedString(entry.Strings.Get("Title"));
            int l = 4;
            if (l > group.Length) l = group.Length;
            string label = title + "_" + group.Substring(0, l);

            StringBuilder labelBuilder = new StringBuilder();
            foreach (char c in label)
            {
                if (isValidLabelChar(c)) labelBuilder.Append(c);
                else labelBuilder.Append('_');
            }

            return labelBuilder.ToString();
        }

        private static String GenerateGroup(PwEntry entry)
        {
            string group = entry.ParentGroup.Name;
            StringBuilder groupBuilder = new StringBuilder();
            foreach (char c in group)
            {
                if (isValidLabelChar(c)) groupBuilder.Append(c);
                else groupBuilder.Append('_');
            }
            return groupBuilder.ToString();
        }

        private static void checkEntry(PwEntry entry, List<string> truncatatedStrings)
        {
            String label = GenerateLabel(entry);
            String group = GenerateGroup(entry);
            
            int n = m_labelMaxLength - label.Length;
            if (n < 0)
            {
                truncatatedStrings.Add(String.Format("Label is {0} charaters too long in ", -n) + entry.ParentGroup.Name + "/" + getProtectedString(entry.Strings.Get("Title")));
            }

            n = m_groupMaxLength - group.Length;
            if (n < 0)
            {
                truncatatedStrings.Add(String.Format("Group is {0} charaters too long in ", -n) + entry.ParentGroup.Name + "/" + getProtectedString(entry.Strings.Get("Title")));
            }

            n = m_usernameMaxLength - entry.Strings.Get("UserName").Length;
            if (n < 0)
            {
                truncatatedStrings.Add(String.Format("Username is {0} charaters too long in ", -n) + entry.ParentGroup.Name + "/" + getProtectedString(entry.Strings.Get("Title")));
            }

            n = m_passwordMaxLength - entry.Strings.Get("Password").Length;
            if (n < 0)
            {
                truncatatedStrings.Add(String.Format("Password is {0} charaters too long in ", -n) + entry.ParentGroup.Name + "/" + getProtectedString(entry.Strings.Get("Title")));
            }

            n = m_notesMaxLength - entry.Strings.Get("Notes").Length;
            if (n < 0)
            {
                truncatatedStrings.Add(String.Format("Notes is {0} charaters too long in ", -n) + entry.ParentGroup.Name + "/" + getProtectedString(entry.Strings.Get("Title")));
            }
        }

        private static void writeEntry(BinaryWriter writer, PwEntry entry)
        {
            /* Entry Cookie */
            writer.Write((byte)0x08);
            writer.Write((byte)0xf3);
            writer.Write((byte)0x24);
            writer.Write((byte)0x00);

            String label = GenerateLabel(entry);
            String group = GenerateGroup(entry);

            writeTruncatedOrPadded(writer, label, m_labelMaxLength);

            /* Status */
            writer.Write((byte)0);

            writeTruncatedOrPadded(writer, group, m_groupMaxLength);
            writeTruncatedOrPadded(writer, getProtectedString(entry.Strings.Get("UserName")), m_usernameMaxLength);
            writeTruncatedOrPadded(writer, getProtectedString(entry.Strings.Get("Password")), m_passwordMaxLength);
            writeTruncatedOrPadded(writer, getProtectedString(entry.Strings.Get("Notes")), m_notesMaxLength);

            /* Zero Padding */
            for (int i = 0; i < 12+32; i++)
            {
                writer.Write((byte)0);
            }
        }

        private bool checkHandler(ref int entriesChecked, PwEntry entry, List<string> truncatedStrings, Dictionary<string, bool> uniqueLabels, List<pair> labelCollitions)
        {
            // Check if entry parent group is Recycle bin, if so ignore it
            if ((entry.ParentGroup.Uuid == m_Host.Database.RecycleBinUuid) ||
                (entry.ParentGroup.Name == "Recycle Bin")) return false;

            String label = GenerateLabel(entry).ToLower();
            if (uniqueLabels.ContainsKey(label))
            {
                labelCollitions.Add(new pair(getProtectedString(entry.Strings.Get("Title")), entry.ParentGroup.Name));
                entriesChecked++;
                return false;
            }
            uniqueLabels.Add(label, true);
            checkEntry(entry, truncatedStrings);
            entriesChecked++;
            return true;
        }

        private bool exportHandler(ref int entriesWritten, BinaryWriter writer, PwEntry entry)
        {
            // Check if entry parent group is Recycle bin, if so ignore it
            if ((entry.ParentGroup.Uuid == m_Host.Database.RecycleBinUuid) ||
                (entry.ParentGroup.Name == "Recycle Bin")) return false;

            writeEntry(writer, entry);
            entriesWritten++;           
            return true;
        }

        private void OnSeclaveGroupExport(Object sender, EventArgs e)
        {
            ExportDatabase(m_Host.MainWindow.GetSelectedGroup());
        }

        private void OnSeclaveExport(Object sender, EventArgs e)
        {
            ExportDatabase(m_Host.Database.RootGroup);
        }

        private string GetSeclaveDevicePath()
        {
            var devices = DriveInfo.GetDrives();
            foreach (var driveInfo in devices)
            {
                if ((driveInfo.DriveFormat == "msdos") &&
                    (driveInfo.IsReady) &&
                    (driveInfo.VolumeLabel.EndsWith("SECLAVE",StringComparison.CurrentCulture)))
                {
                    var path = driveInfo.RootDirectory.ToString();
                    if (File.Exists(Path.Combine(path, "SCIMPORT.STE")))
                        return path;
                }
            }
            return null;
        }

        private void ExportDatabase(PwGroup selectedGroup)
        {
            // Let user know if there are any prerequisites missing for export
            if (!m_Host.Database.IsOpen)
            {
                MessageBox.Show("Password database needs to be unlocked for export");
                return;
            }

            // Check all entry names and limits
            if (!EntryChecker(selectedGroup))
            {
                return;
            }

            MessageBox.Show("Make sure your SECLAVE device is connected and ready for import", m_toolTitle, MessageBoxButtons.OK, MessageBoxIcon.Information);
            var path = GetSeclaveDevicePath();
            if (path == null)
            {
                MessageBox.Show("No device found!", m_toolTitle, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            FileStream fs;
            try
            {
                fs = new FileStream(Path.Combine(path, "seclave.imp"), FileMode.Create);
            }
            catch (Exception)
            {
                MessageBox.Show("Could not write export file: Access Denied");
                return;
            }

            // Set encoding
            Encoding latin1 = Encoding.GetEncoding("ISO-8859-1");

            // Let the BinaryWriter work
            var writer = EntryWriter(fs, latin1, selectedGroup);

            writer.Close();
            fs.Close();

            // Let user know that export was completed
            MessageBox.Show(m_entriesWritten + " entries was successfully exported!", "Export complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private BinaryWriter EntryWriter(FileStream fileStream, Encoding encoding, PwGroup selectedGroup)
        {
            m_entriesWritten = 0;
            
            // Create writer and traverse the tree, being root or selected group
            var writer = new BinaryWriter(fileStream, encoding);
            selectedGroup.TraverseTree(TraversalMethod.PreOrder, null, entry => exportHandler(ref m_entriesWritten, writer, entry));

            for (int i = m_entriesWritten; i < m_maxEntries; i++)
            {
                writeNullEntry(writer);
            }

            return writer;
        }

        private class pair
        {
            public pair(string label, string group)
            {
                this.label = label;
                this.group = group;
            }
            public string label;
            public string group;
        }

        private bool EntryChecker(PwGroup selectedGroup)
        {
            int m_entriesChecked = 0;
            var truncatedStrings = new List<string>();

            var uniqueLabels = new Dictionary<string, bool>();
            var labelCollitions = new List<pair>();

            selectedGroup.TraverseTree(TraversalMethod.PreOrder, null, entry => checkHandler(ref m_entriesChecked, entry, truncatedStrings, uniqueLabels, labelCollitions));
            if (labelCollitions.Any())
            {
                var message = "There is label collitions at" + Environment.NewLine;
                foreach (var p in labelCollitions)
                {
                    message += String.Format("{0} / {1}", p.group, p.label);
                }
                MessageBox.Show(message, "Export validation", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            if (m_entriesChecked > m_maxEntries)
            {
                int n = m_entriesChecked - m_maxEntries;
                MessageBox.Show(String.Format("Trying to export {0} too many entries", n), "Export validation", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }

            if (truncatedStrings.Any())
            {
                var message = "During check, " + truncatedStrings.Count + " out of " + m_entriesChecked + " entries was truncated: " + Environment.NewLine;
                message += string.Join(Environment.NewLine, truncatedStrings.ToArray());
                message += Environment.NewLine + "Continue anyway?";
                if (MessageBox.Show(message, "Export validation", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.No)
                {
                    return false;
                }
            }

            return true;
        }

        private static char Latin1ToLower(char c)
        {
            if (c >= 'a' && c <= 'z') return c;
            if (c >= '0' && c <= '9') return c;
            if (c >= 'A' && c <= 'Z') return (char)(c + ('a' - 'A'));

            if (c == 0xc6) return (char)0xe6; // KS_AE
            if (c == 0xc5) return (char)0xe5; // KS_Aring
            if (c == 0xc4) return (char)0xe4; // KS_Adiaeresis
            if (c == 0xd6) return (char)0xf6; // KS_Odiaeresis
            if (c == 0xd8) return (char)0xf8; // KS_Ooblique
            if (c == 0xdc) return (char)0xfc; // KS_Udiaeresis

            return c;
        }

        private static bool isValidLabelChar(char sc)
        {
            char c = Latin1ToLower(sc);
            return (c >= 'a' && c <= 'z') ||
                   (c >= '0' && c <= '9') ||
                   (c == '_') ||
                   (c == 0xe6) || // KS_ae
                   (c == 0xe5) || // KS_aring
                   (c == 0xe4) || // KS_adiaeresis
                   (c == 0xf6) || // KS_odiaeresis
                   (c == 0xf8) || // KS_oslash
                   (c == 0xfc) || // KS_udiaeresis
                   (c == 0xdf); // KS_sslash
        }
    }
} 