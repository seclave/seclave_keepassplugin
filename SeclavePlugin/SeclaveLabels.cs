// SPDX-License-Identifier: MIT
// Copyright 2026 Seclave AB
//
// How a KeePass entry is named on the Seclave: the label pattern, the group
// name, the characters the device allows in both, and the settings dialog.
// The export and the sync both name entries through Labels.For.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using KeePass.App.Configuration;
using KeePassLib;

namespace SeclavePlugin
{
    public static class LabelChars
    {
        public const int MaxLabel = 16;
        public const int MaxGroup = 8;

        // The device's case fold for label characters
        public static char Latin1ToLower(char c)
        {
            if (c >= 'A' && c <= 'Z') return (char)(c + ('a' - 'A'));
            if (c == 0xc6) return (char)0xe6; // AE
            if (c == 0xc5) return (char)0xe5; // A ring
            if (c == 0xc4) return (char)0xe4; // A umlaut
            if (c == 0xd6) return (char)0xf6; // O umlaut
            if (c == 0xd8) return (char)0xf8; // O slash
            if (c == 0xdc) return (char)0xfc; // U umlaut
            return c;
        }

        // The device also accepts '-' and '.', but they have always been
        // written as '_'; allowing them now would rename existing entries.
        public static bool IsValid(char sc)
        {
            char c = Latin1ToLower(sc);
            return (c >= 'a' && c <= 'z') ||
                   (c >= '0' && c <= '9') ||
                   (c == '_') ||
                   (c == 0xe6) || // ae
                   (c == 0xe5) || // a ring
                   (c == 0xe4) || // a umlaut
                   (c == 0xf6) || // o umlaut
                   (c == 0xf8) || // o slash
                   (c == 0xfc) || // u umlaut
                   (c == 0xdf);   // sharp s
        }

        public static string Sanitize(string text)
        {
            var sb = new StringBuilder(text.Length);
            foreach (char c in text) sb.Append(IsValid(c) ? c : '_');
            return sb.ToString();
        }

        // Labels compare case-insensitively on the device
        public static string Fold(string label)
        {
            var sb = new StringBuilder(label.Length);
            foreach (char c in label) sb.Append(Latin1ToLower(c));
            return sb.ToString();
        }

        public static string Cut(string text, int max)
        {
            return text.Length > max ? text.Substring(0, max) : text;
        }
    }

    // A label pattern: literal text and the tokens [Title] (the whole entry
    // title), [Group] (the group name), [GroupN] (its first N characters)
    // and [idhexN] (the first N hex digits of the entry's UUID, which never
    // changes), N from 1 to 16. Token names are case-sensitive.
    public static class LabelPattern
    {
        // Gives the labels every earlier version of the plugin gave: the
        // title, '_' and the first four characters of the parent group.
        public const string Default = "[Title]_[Group4]";

        public static readonly string[] Presets = {
            Default, "[Title]_[Group]", "[Group]_[Title]", "[Title]", "[Title]_[idhex3]", "[idhex3]_[Title]" };

        private const string TokenError = "Use [Title], [Group], [GroupN] or [idhexN] with N from 1 to 16 (case-sensitive).";

        // N of [prefixN], or 0 if the token is not one
        private static int TokenLength(string token, string prefix)
        {
            if (!token.StartsWith(prefix, StringComparison.Ordinal) || token.Length < prefix.Length + 2) return 0;
            int n = 0;
            for (int i = prefix.Length; i < token.Length - 1; i++)
            {
                if (token[i] < '0' || token[i] > '9') return 0;
                n = n * 10 + (token[i] - '0');
                if (n > LabelChars.MaxLabel) return 0;
            }
            return n;
        }

        // Splits a pattern into literal text and tokens; null if malformed
        private static List<string> Split(string pattern)
        {
            var parts = new List<string>();
            var literal = new StringBuilder();
            for (int i = 0; i < pattern.Length; i++)
            {
                char c = pattern[i];
                if (c == ']') return null;
                if (c != '[')
                {
                    literal.Append(c);
                    continue;
                }
                int end = pattern.IndexOf(']', i);
                if (end < 0) return null;
                if (literal.Length > 0) parts.Add(literal.ToString());
                literal.Length = 0;
                parts.Add(pattern.Substring(i, end - i + 1));
                i = end;
            }
            if (literal.Length > 0) parts.Add(literal.ToString());
            return parts;
        }

        private static bool IsToken(string part) { return part.StartsWith("["); }

        // Null if the pattern is usable, otherwise what is wrong with it
        public static string Error(string pattern)
        {
            if (pattern == null || pattern.Trim().Length == 0) return "Enter a label pattern.";
            List<string> parts = Split(pattern);
            if (parts == null) return TokenError;
            bool distinct = false;
            foreach (string part in parts)
            {
                if (!IsToken(part)) continue;
                if (part == "[Title]" || TokenLength(part, "[idhex") > 0) distinct = true;
                else if (part != "[Group]" && TokenLength(part, "[Group") == 0) return TokenError;
            }
            if (!distinct) return "Include [Title] or [idhexN]; otherwise entries in one group all get the same label.";
            return null;
        }

        // The label, sanitized and not yet cut to 16 characters. Tokens are
        // expanded once, so brackets in a title stay literal.
        public static string Format(string pattern, string title, string group, string entryId)
        {
            List<string> parts = Split(pattern);
            if (Error(pattern) != null) throw new ArgumentException("invalid label pattern", "pattern");
            var label = new StringBuilder();
            foreach (string part in parts)
            {
                if (!IsToken(part)) label.Append(part);
                else if (part == "[Title]") label.Append(title);
                else if (part == "[Group]") label.Append(group);
                else if (TokenLength(part, "[Group") > 0) label.Append(LabelChars.Cut(group, TokenLength(part, "[Group")));
                else label.Append(entryId.Substring(0, TokenLength(part, "[idhex")));
            }
            return LabelChars.Sanitize(label.ToString());
        }

        // An earlier build of this dialog called [idhexN] [rndhexN]
        public static string Migrate(string pattern)
        {
            if (pattern == null) return null;
            List<string> parts = Split(pattern);
            if (parts == null) return pattern;
            var sb = new StringBuilder();
            foreach (string part in parts)
            {
                int n = IsToken(part) ? TokenLength(part, "[rndhex") : 0;
                sb.Append(n > 0 ? "[idhex" + n + "]" : part);
            }
            return sb.ToString();
        }
    }

    // The label settings, kept in KeePass's own configuration (not in the
    // database), so they apply to every database.
    public sealed class LabelOptions
    {
        private const string PatternKey = "SeclavePlugin.LabelPattern";
        private const string PreviousPatternKey = "SeclavePlugin.PreviousLabelPattern";
        private const string EmptyRootGroupKey = "SeclavePlugin.EmptyRootGroup";
        private const string PreviousEmptyRootGroupKey = "SeclavePlugin.PreviousEmptyRootGroup";
        private const string KeepLabelsKey = "SeclavePlugin.KeepLabels";

        public string Pattern = LabelPattern.Default;
        // Entries directly in the database root get an empty group, both in
        // the device's group field and in [Group]
        public bool EmptyRootGroup;
        // The pattern and root setting in use before the last change, if any
        // (the root setting is unknown if it was changed by a version that
        // did not record it). The sync still recognises entries a device
        // holds under the labels they gave.
        public string PreviousPattern;
        public bool? PreviousEmptyRootGroup;
        // An export records on each entry the label it wrote it under, and
        // uses that label from then on, so that moving or renaming an entry
        // does not put it on the device a second time
        public bool KeepLabels = true;

        public static LabelOptions Load(AceCustomConfig config)
        {
            var o = new LabelOptions();
            o.Pattern = LabelPattern.Migrate(config.GetString(PatternKey, LabelPattern.Default));
            o.EmptyRootGroup = config.GetBool(EmptyRootGroupKey, false);
            o.PreviousPattern = LabelPattern.Migrate(config.GetString(PreviousPatternKey, null));
            string previousRoot = config.GetString(PreviousEmptyRootGroupKey, null);
            if (previousRoot != null) o.PreviousEmptyRootGroup = previousRoot == "true";
            o.KeepLabels = config.GetBool(KeepLabelsKey, true);
            return o;
        }

        public void Save(AceCustomConfig config)
        {
            config.SetString(PatternKey, Pattern);
            config.SetBool(EmptyRootGroupKey, EmptyRootGroup);
            config.SetString(PreviousPatternKey, PreviousPattern);
            config.SetString(PreviousEmptyRootGroupKey,
                PreviousEmptyRootGroup == null ? null : (PreviousEmptyRootGroup.Value ? "true" : "false"));
            config.SetBool(KeepLabelsKey, KeepLabels);
        }

        // Changes the pattern and the root setting, remembering the pair they
        // replace; changing either one changes labels
        public void SetLabelling(string pattern, bool emptyRootGroup)
        {
            if (pattern == Pattern && emptyRootGroup == EmptyRootGroup) return;
            PreviousPattern = Pattern;
            PreviousEmptyRootGroup = EmptyRootGroup;
            Pattern = pattern;
            EmptyRootGroup = emptyRootGroup;
        }
    }

    public static class Labels
    {
        public static string GroupName(PwEntry entry, LabelOptions options)
        {
            PwGroup group = entry.ParentGroup;
            if (group == null || (options.EmptyRootGroup && group.ParentGroup == null)) return "";
            return group.Name;
        }

        // The entry's label under a pattern, sanitized, not yet cut to 16
        public static string For(PwEntry entry, LabelOptions options, string pattern)
        {
            return LabelPattern.Format(pattern, SeclavePluginExt.getProtectedString(entry.Strings.Get(PwDefs.TitleField)),
                GroupName(entry, options), entry.Uuid.ToHexString().ToLowerInvariant());
        }

        public static string For(PwEntry entry, LabelOptions options)
        {
            return For(entry, options, options.Pattern);
        }

        // The device group, sanitized, not yet cut to 8
        public static string Group(PwEntry entry, LabelOptions options)
        {
            return LabelChars.Sanitize(GroupName(entry, options));
        }

        // Labels an entry may have been given before the pattern or the root
        // setting last changed: under the previous pattern and root setting,
        // and under the default pattern (what every plugin version before
        // label patterns used, with the database root's name as the group).
        // Cut to 16; the current label is not included.
        public static List<string> Earlier(PwEntry entry, LabelOptions options)
        {
            string current = LabelChars.Fold(LabelChars.Cut(For(entry, options), LabelChars.MaxLabel));
            var labels = new List<string>();
            var seen = new Dictionary<string, bool>();
            seen[current] = true;
            var original = new LabelOptions();
            var candidates = new List<string>();
            if (options.PreviousPattern != null && LabelPattern.Error(options.PreviousPattern) == null)
            {
                var previous = new LabelOptions();
                previous.EmptyRootGroup = options.PreviousEmptyRootGroup ?? options.EmptyRootGroup;
                candidates.Add(LabelChars.Cut(For(entry, previous, options.PreviousPattern), LabelChars.MaxLabel));
            }
            candidates.Add(LabelChars.Cut(For(entry, original), LabelChars.MaxLabel));
            foreach (string label in candidates)
            {
                if (label.Length == 0 || seen.ContainsKey(LabelChars.Fold(label))) continue;
                seen[LabelChars.Fold(label)] = true;
                labels.Add(label);
            }
            return labels;
        }
    }

    public sealed class SettingsForm : Form
    {
        private readonly ComboBox m_pattern = new ComboBox();
        private readonly CheckBox m_emptyRoot = new CheckBox();
        private readonly CheckBox m_keepLabels = new CheckBox();
        private readonly Label m_preview = new Label();
        private readonly Label m_error = new Label();
        private readonly Button m_save = new Button();
        private readonly string m_rootName;

        public string Pattern { get { return m_pattern.Text; } }
        public bool EmptyRootGroup { get { return m_emptyRoot.Checked; } }
        public bool KeepLabels { get { return m_keepLabels.Checked; } }

        // rootName: the open database's root group name, for the preview
        public SettingsForm(LabelOptions options, string rootName)
        {
            m_rootName = string.IsNullOrEmpty(rootName) ? "Database" : rootName;
            Text = "Seclave settings";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(560, 400);

            var caption = new Label();
            caption.Text = "Label pattern for entries going to the Seclave:";
            caption.SetBounds(12, 12, 536, 20);
            Controls.Add(caption);

            m_pattern.DropDownStyle = ComboBoxStyle.DropDown;
            foreach (string p in LabelPattern.Presets) m_pattern.Items.Add(p);
            m_pattern.Text = options.Pattern;
            m_pattern.SetBounds(12, 34, 536, 24);
            Controls.Add(m_pattern);

            var tokens = new Label();
            tokens.Text = "[Title] the entry title, [Group] the group name, [Group4] its first 4 characters, " +
                "[idhex3] 3 hex digits of the entry's ID, which never changes (N from 1 to 16 for both). " +
                "Labels keep 16 characters, groups 8; any character other than a letter or digit becomes '_'.";
            tokens.SetBounds(12, 64, 536, 50);
            Controls.Add(tokens);

            m_emptyRoot.Text = "Empty group for entries in the database root";
            m_emptyRoot.Checked = options.EmptyRootGroup;
            m_emptyRoot.SetBounds(12, 118, 536, 24);
            Controls.Add(m_emptyRoot);

            m_keepLabels.Text = "Keep an entry's Seclave label once assigned";
            m_keepLabels.Checked = options.KeepLabels;
            m_keepLabels.SetBounds(12, 142, 536, 24);
            Controls.Add(m_keepLabels);

            m_preview.SetBounds(12, 172, 536, 52);
            Controls.Add(m_preview);

            m_error.ForeColor = Color.Firebrick;
            m_error.SetBounds(12, 224, 536, 30);
            Controls.Add(m_error);

            var note = new Label();
            note.Text = "An entry keeps the label it was first exported or synced under, so moving or renaming it " +
                "does not put it on the Seclave twice; a new pattern or root setting applies to entries without " +
                "one. With the label not kept, an export under a new pattern or root setting adds the entries " +
                "under their new labels and leaves the old ones, so the Seclave holds both. The default, " +
                LabelPattern.Default + ", gives the labels earlier versions gave.";
            note.SetBounds(12, 256, 536, 92);
            Controls.Add(note);

            m_save.Text = "Save";
            m_save.DialogResult = DialogResult.OK;
            m_save.SetBounds(372, 360, 85, 28);
            Controls.Add(m_save);
            var cancel = new Button();
            cancel.Text = "Cancel";
            cancel.DialogResult = DialogResult.Cancel;
            cancel.SetBounds(463, 360, 85, 28);
            Controls.Add(cancel);
            AcceptButton = m_save;
            CancelButton = cancel;

            m_pattern.TextChanged += delegate { UpdatePreview(); };
            m_emptyRoot.CheckedChanged += delegate { UpdatePreview(); };
            Shown += delegate
            {
                m_pattern.Focus();
                m_pattern.SelectAll();
            };
            UpdatePreview();
        }

        private void UpdatePreview()
        {
            string error = LabelPattern.Error(Pattern);
            m_error.Text = error ?? "";
            m_save.Enabled = error == null;
            if (error != null)
            {
                m_preview.Text = "";
                return;
            }
            const string exampleId = "a1b2c3d4e5f60789";
            string rootGroup = EmptyRootGroup ? "" : m_rootName;
            m_preview.Text =
                "Mailbox in group Email: " + LabelChars.Cut(LabelPattern.Format(Pattern, "Mailbox", "Email", exampleId), LabelChars.MaxLabel) +
                Environment.NewLine +
                "Mailbox in the database root: " + LabelChars.Cut(LabelPattern.Format(Pattern, "Mailbox", rootGroup, exampleId), LabelChars.MaxLabel) +
                " (group " + (rootGroup.Length == 0 ? "empty" : LabelChars.Cut(LabelChars.Sanitize(rootGroup), LabelChars.MaxGroup)) + ")" +
                Environment.NewLine + "(The ID digits are an example.)";
        }
    }
}
