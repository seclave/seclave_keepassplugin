// SPDX-License-Identifier: MIT
// Copyright 2026 Seclave AB
//
// Two-way sync between the KeePass database and a Seclave over its USB-slave
// port.
//
// Every synced entry keeps a baseline in its CustomData: the device label it
// is linked to, and a keyed hash of what was last known to be on the device
// under that label (the key is SyncKey's). Comparing the baseline with the
// entry now and with the device now tells which side changed; when both did,
// the user decides. Nothing is applied before the user has reviewed the plan,
// nothing is deleted unless the user ticks it, and every change to a KeePass
// entry is preceded by a history backup of that entry.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePassLib;
using KeePassLib.Cryptography;
using KeePassLib.Security;
using KeePassLib.Utility;

namespace SeclavePlugin
{
    public static class SyncData
    {
        public const string LabelKey = "Seclave.Label";
        public const string BaselineKey = "Seclave.Baseline";
        // The unkeyed hash of earlier development builds; it means nothing and
        // is removed wherever an entry's sync data is written or cleared
        private const string StaleStateKey = "Seclave.State";
        // The entry the label belongs to. KeePass's Duplicate and paste copy
        // the custom data, so a copy carries the original's label and state;
        // with this the copy is a new entry, not a second claim on the label.
        public const string UuidKey = "Seclave.Uuid";

        // Entries that exist only on the device are added to KeePass under
        // this group, in a subgroup named after their device group, so that
        // the group a push would send is the one the device already has.
        public const string ImportGroup = "From Seclave";

        // A value as the device stores it: Latin-1 ('?' for anything else), cut
        // at a NUL and to the field size, CR LF as LF and any other CR left
        // out (the device types a CR as nothing).
        public static string Field(string value, int max)
        {
            if (value == null) return "";
            value = value.Replace("\r\n", "\n");
            var sb = new StringBuilder();
            foreach (char c in value)
            {
                if (c == '\0' || sb.Length == max) break;
                if (c == '\r') continue;
                sb.Append(c > 0xff ? '?' : c);
            }
            return sb.ToString();
        }

        public static string Fold(string label)
        {
            return LabelChars.Fold(label);
        }

        // The label stored on the entry by an export or a sync, or null if it
        // has none of its own. A label stored before the owner was recorded
        // counts as the entry's own.
        public static string StoredLabel(PwEntry entry)
        {
            string label = entry.CustomData.Get(LabelKey);
            if (string.IsNullOrEmpty(label)) return null;
            string owner = entry.CustomData.Get(UuidKey);
            if (owner != null && owner != entry.Uuid.ToHexString()) return null;
            return label;
        }

        // What was last known to be on the device under the entry's label,
        // or null if that is not known
        public static string Baseline(PwEntry entry)
        {
            return StoredLabel(entry) == null ? null : entry.CustomData.Get(BaselineKey);
        }

        // An entry that has a label keeps it; any other gets the one the label
        // pattern gives, as the export would write it.
        public static string LabelFor(PwEntry entry, LabelOptions options)
        {
            string stored = StoredLabel(entry);
            if (stored != null) return Field(stored, Wire.MaxLabel);
            return Field(Labels.For(entry, options), Wire.MaxLabel);
        }

        // Records the label an export wrote the entry under; the export does
        // not know what the device kept, so this sets no baseline, and a new
        // label drops any baseline the entry had. False if nothing changed.
        public static bool AssignLabel(PwEntry entry, string label)
        {
            bool same = StoredLabel(entry) == label;
            if (same && entry.CustomData.Get(UuidKey) != null) return false;
            if (!same) entry.CustomData.Remove(BaselineKey);
            entry.CustomData.Remove(StaleStateKey);
            entry.CustomData.Set(LabelKey, label);
            entry.CustomData.Set(UuidKey, entry.Uuid.ToHexString());
            // KeePass's synchronize, which is also how Save writes over a file
            // that changed on disk since it was opened, keeps the file's copy
            // of an entry unless that copy is older: sync data written without
            // a new modification time would be lost there
            entry.Touch(true, false);
            return true;
        }

        // The entry as a push sends it
        public static DeviceEntry Project(PwDatabase db, PwEntry entry, string label, LabelOptions options)
        {
            var d = new DeviceEntry();
            d.Label = label;
            d.Group = Field(Labels.Group(entry, options), Wire.MaxGroup);
            d.Username = Field(SeclavePluginExt.FieldValue(db, entry, PwDefs.UserNameField), Wire.MaxUsername);
            d.Password = Field(SeclavePluginExt.FieldValue(db, entry, PwDefs.PasswordField), Wire.MaxPassword);
            d.Optional = Field(SeclavePluginExt.FieldValue(db, entry, PwDefs.NotesField), Wire.MaxOptional);
            return d;
        }

        // Whether the entry's field, as the device would store it, is the value
        public static bool SameOnDevice(PwDatabase db, PwEntry entry, string field, string value, int max)
        {
            return Field(SeclavePluginExt.FieldValue(db, entry, field), max) == Field(value, max);
        }

        // Whether the entry's field takes its value from another entry or
        // field ({REF:...}, {USERNAME} and the like). A pull never writes over
        // such a field.
        public static bool IsReference(PwDatabase db, PwEntry entry, string field)
        {
            return SeclavePluginExt.FieldValue(db, entry, field) != SeclavePluginExt.getProtectedString(entry.Strings.Get(field));
        }

        // The baseline for what the device holds: an HMAC-SHA256 under the
        // database's sync key of the values as the device holds them, the
        // group as SameGroup compares it
        public static string Mac(byte[] key, DeviceEntry d)
        {
            string s = Fold(d.Label) + "\0" + GroupKey(d.Group) + "\0" +
                Field(d.Username, Wire.MaxUsername) + "\0" + Field(d.Password, Wire.MaxPassword) + "\0" +
                Field(d.Optional, Wire.MaxOptional);
            byte[] data = Wire.Latin1.GetBytes(s);
            try
            {
                using (var hmac = new HMACSHA256(key))
                    return BitConverter.ToString(hmac.ComputeHash(data)).Replace("-", "").ToLowerInvariant();
            }
            finally { MemUtil.ZeroByteArray(data); }
        }

        // Whether two group names are one group: compared as the device holds
        // them, mapped as the plugin writes a group, and folded. The device
        // group "my-bank" is the one the plugin writes as "my_bank".
        public static bool SameGroup(string a, string b)
        {
            return GroupKey(a) == GroupKey(b);
        }

        private static string GroupKey(string group)
        {
            return Fold(LabelChars.Sanitize(Field(group, Wire.MaxGroup)));
        }

        // Names of the fields that differ, never their values
        public static string Differences(DeviceEntry a, DeviceEntry b)
        {
            var names = new List<string>();
            if (!SameGroup(a.Group, b.Group)) names.Add("group");
            if (Field(a.Username, Wire.MaxUsername) != Field(b.Username, Wire.MaxUsername)) names.Add("username");
            if (Field(a.Password, Wire.MaxPassword) != Field(b.Password, Wire.MaxPassword)) names.Add("password");
            if (Field(a.Optional, Wire.MaxOptional) != Field(b.Optional, Wire.MaxOptional)) names.Add("notes");
            return string.Join(", ", names.ToArray());
        }

        // What a push would change in the entry's username and notes, for the
        // plan's reason; empty if nothing. (A password that would change is
        // never pushed.)
        public static string Losses(PwDatabase db, PwEntry entry)
        {
            var lost = new List<string>();
            string username = SeclavePluginExt.FieldValue(db, entry, PwDefs.UserNameField);
            string notes = SeclavePluginExt.FieldValue(db, entry, PwDefs.NotesField);
            if (Field(username, int.MaxValue).Length > Wire.MaxUsername) lost.Add("username cut to " + Wire.MaxUsername);
            if (SeclavePluginExt.HasNonLatin1(username)) lost.Add("'?' in username");
            if (Field(notes, int.MaxValue).Length > Wire.MaxOptional) lost.Add("notes cut to " + Wire.MaxOptional);
            if (SeclavePluginExt.HasNonLatin1(notes)) lost.Add("'?' in notes");
            return string.Join(", ", lost.ToArray());
        }

        // The entry's sync data in one string, to tell whether a write changed it
        private static string SyncDataOf(PwEntry entry)
        {
            return entry.CustomData.Get(LabelKey) + "\n" + entry.CustomData.Get(UuidKey) + "\n" +
                entry.CustomData.Get(BaselineKey) + "\n" + entry.CustomData.Get(StaleStateKey);
        }

        // A new modification time for a change of sync data, as AssignLabel gives one
        private static void TouchIfChanged(PwEntry entry, string before)
        {
            if (SyncDataOf(entry) != before) entry.Touch(true, false);
        }

        // onDevice is what the device now holds under the label, or null if
        // it holds nothing there any more; key is the database's sync key.
        public static void SetBaseline(PwEntry entry, string label, DeviceEntry onDevice, byte[] key)
        {
            string before = SyncDataOf(entry);
            entry.CustomData.Set(LabelKey, label);
            entry.CustomData.Set(UuidKey, entry.Uuid.ToHexString());
            entry.CustomData.Remove(StaleStateKey);
            if (onDevice == null) entry.CustomData.Remove(BaselineKey);
            else entry.CustomData.Set(BaselineKey, Mac(key, onDevice));
            TouchIfChanged(entry, before);
        }

        // "group / title", as the review dialog shows an entry
        public static string Describe(PwEntry entry)
        {
            return entry.ParentGroup.Name + " / " + SeclavePluginExt.getProtectedString(entry.Strings.Get(PwDefs.TitleField));
        }

        public static void RemoveBaseline(PwEntry entry)
        {
            string before = SyncDataOf(entry);
            entry.CustomData.Remove(LabelKey);
            entry.CustomData.Remove(BaselineKey);
            entry.CustomData.Remove(UuidKey);
            entry.CustomData.Remove(StaleStateKey);
            TouchIfChanged(entry, before);
        }
    }

    // The key of the baselines: 32 random bytes in a protected attachment on
    // an entry of its own, made in the database root and marked in its custom
    // data; that entry is never exported or synced. An instance holds a copy
    // of the key for one plan or one apply, and Dispose clears it.
    public sealed class SyncKey : IDisposable
    {
        public const string Marker = "Seclave.KeyEntry";
        public const string Attachment = "seclave-sync.key";

        private readonly PwDatabase m_db;
        private byte[] m_key;

        public SyncKey(PwDatabase db)
        {
            m_db = db;
        }

        public static bool IsKeyEntry(PwEntry entry)
        {
            return entry.CustomData.Get(Marker) != null;
        }

        // The key entry outside the recycle bin; after databases were merged
        // there can be several (count), and the oldest is the one
        public static PwEntry Find(PwDatabase db, out int count)
        {
            PwEntry oldest = null;
            int found = 0;
            db.RootGroup.TraverseTree(TraversalMethod.PreOrder, null, delegate(PwEntry e)
            {
                if (!IsKeyEntry(e) || SeclavePluginExt.IsInRecycleBin(db, e)) return true;
                found++;
                if (oldest == null || e.CreationTime < oldest.CreationTime) oldest = e;
                return true;
            });
            count = found;
            return oldest;
        }

        // The key, or null if the key entry or its attachment is missing
        public byte[] Existing
        {
            get
            {
                if (m_key == null)
                {
                    int count;
                    PwEntry entry = Find(m_db, out count);
                    ProtectedBinary stored = entry == null ? null : entry.Binaries.Get(Attachment);
                    if (stored != null && stored.Length > 0) m_key = stored.ReadData();
                }
                return m_key;
            }
        }

        // The key, made new if it is missing, on the key entry or on a new one
        public byte[] Get()
        {
            if (Existing != null) return m_key;
            int count;
            PwEntry entry = Find(m_db, out count);
            if (entry == null)
            {
                entry = new PwEntry(true, true);
                entry.Strings.Set(PwDefs.TitleField, new ProtectedString(m_db.MemoryProtection.ProtectTitle, "Seclave sync key"));
                entry.Strings.Set(PwDefs.NotesField, new ProtectedString(m_db.MemoryProtection.ProtectNotes,
                    "Used by the Seclave KeePass plugin to tell which synced entries changed. Do not delete it: " +
                    "deleting only makes the next sync re-check every synced entry."));
                entry.CustomData.Set(Marker, "1");
                m_db.RootGroup.AddEntry(entry, true);
            }
            m_key = CryptoRandom.Instance.GetRandomBytes(32);
            entry.Binaries.Set(Attachment, new ProtectedBinary(true, m_key));
            return m_key;
        }

        public void Dispose()
        {
            if (m_key != null) MemUtil.ZeroByteArray(m_key);
            m_key = null;
        }
    }

    // What was read from the device, by folded label. Web-password entries
    // (group "wwwfill") are left out: their labels belong to the device and
    // are only kept in Reserved, so that no entry is written over them.
    public sealed class Snapshot
    {
        public readonly Dictionary<string, DeviceEntry> Entries = new Dictionary<string, DeviceEntry>();
        public readonly Dictionary<string, bool> Reserved = new Dictionary<string, bool>();

        // True when every label on the device is in Entries or Reserved, so a
        // label that is missing is known to be absent and the rest are
        // device-only.
        public bool WholeStore;

        // Firmware 2.7 and later replaces an entry in place; earlier firmware
        // only by deleting it first
        public bool ReplacesInPlace;

        // Free slots on the device, or -1 if not known
        public int Free = -1;

        public void Add(DeviceEntry e)
        {
            if (e.Group == Wire.WwwfillGroup)
            {
                Reserved[SyncData.Fold(e.Label)] = true;
                return;
            }
            Entries[SyncData.Fold(e.Label)] = e;
        }

        public bool IsReserved(string label)
        {
            return Reserved.ContainsKey(SyncData.Fold(label));
        }

        public DeviceEntry Find(string label)
        {
            DeviceEntry e;
            return Entries.TryGetValue(SyncData.Fold(label), out e) ? e : null;
        }
    }

    public enum SyncAction { None, AddToDevice, UpdateDevice, DeleteOnDevice, UpdateKeePass, AddToKeePass, Link }

    public sealed class PlanItem
    {
        public PwEntry Entry;           // null for an entry only on the device
        public string Label;
        public DeviceEntry Local;       // the entry as a push would send it
        public DeviceEntry Device;      // the device's copy; null if it has none
        public SyncAction Action;
        public bool Apply;
        public bool Conflict;           // both sides changed; Action stays None until the user picks one
        public string Reason;
        public string Blocked;          // set when the item cannot be applied
        public bool Blind;              // a push's: written without reading the Seclave

        public string Outcome;
        public bool DeviceDone;
        public bool DeviceRemoved;      // the old copy was removed, the new one not stored

        public bool WritesDevice
        {
            get { return Action == SyncAction.AddToDevice || Action == SyncAction.UpdateDevice || Action == SyncAction.DeleteOnDevice; }
        }

        public string ActionText
        {
            get
            {
                switch (Action)
                {
                    case SyncAction.AddToDevice: return "Add to Seclave";
                    case SyncAction.UpdateDevice: return "Update on Seclave";
                    case SyncAction.DeleteOnDevice: return "Delete from Seclave";
                    case SyncAction.UpdateKeePass: return "Update in KeePass";
                    case SyncAction.AddToKeePass: return "Add to KeePass";
                    case SyncAction.Link: return "Link (no change)";
                }
                if (Conflict) return "Conflict: choose";
                return "Skipped";
            }
        }

        public string EntryText
        {
            get { return Entry == null ? "" : SyncData.Describe(Entry); }
        }
    }

    public static class Planner
    {
        // only: restrict the plan to these entries (a pull of selected
        // entries); null for the whole database.
        public static List<PlanItem> Build(PwDatabase db, Snapshot snapshot, ICollection<PwEntry> only, LabelOptions options)
        {
            using (var key = new SyncKey(db)) return Build(db, snapshot, only, options, key.Existing, false, false);
        }

        // A push reads nothing: it plans from KeePass alone, against what the
        // plugin last wrote to the Seclave or read there (the baseline). The
        // chosen entries that are new or changed since, or all of them.
        public static List<PlanItem> BuildPush(PwDatabase db, ICollection<PwEntry> only, LabelOptions options, bool all)
        {
            using (var key = new SyncKey(db)) return Build(db, new Snapshot(), only, options, key.Existing, true, all);
        }

        private static List<PlanItem> Build(PwDatabase db, Snapshot snapshot, ICollection<PwEntry> only, LabelOptions options,
            byte[] syncKey, bool push, bool all)
        {
            // The whole database also for some entries: one not chosen may
            // own the label a chosen one asks for
            var linked = new List<PwEntry>();
            var unlinked = new List<PwEntry>();
            var binned = new List<PwEntry>();
            db.RootGroup.TraverseTree(TraversalMethod.PreOrder, null, delegate(PwEntry e)
            {
                if (SyncKey.IsKeyEntry(e)) return true;
                if (SeclavePluginExt.IsInRecycleBin(db, e)) binned.Add(e);
                else if (SyncData.StoredLabel(e) == null) unlinked.Add(e);
                else linked.Add(e);
                return true;
            });

            var items = new List<PlanItem>();
            // folded label -> the entry that has it; linked entries claim theirs first
            var claimed = new Dictionary<string, PwEntry>();
            var live = new List<PwEntry>(linked);
            live.AddRange(unlinked);

            // After a pattern change, the device may hold a never-synced entry
            // under the label an earlier pattern gave it. Pushing it under
            // the new label would put it on the device twice, so such an
            // entry keeps its earlier label, as long as no entry asks for
            // that label under the current pattern.
            var labelOf = new Dictionary<PwEntry, string>();
            var wanted = new Dictionary<string, bool>();
            foreach (PwEntry e in live)
            {
                labelOf[e] = SyncData.LabelFor(e, options);
                wanted[SyncData.Fold(labelOf[e])] = true;
            }
            var earlier = new Dictionary<PwEntry, bool>();
            // Entries whose earlier label is on the device but now names another entry
            var earlierTaken = new Dictionary<PwEntry, string>();
            foreach (PwEntry e in unlinked)
            {
                if (snapshot.Find(labelOf[e]) != null) continue;
                foreach (string old in Labels.Earlier(e, options))
                {
                    if (snapshot.Find(old) == null) continue;
                    if (wanted.ContainsKey(SyncData.Fold(old)))
                    {
                        if (!earlierTaken.ContainsKey(e)) earlierTaken[e] = old;
                        continue;
                    }
                    labelOf[e] = old;
                    wanted[SyncData.Fold(old)] = true;
                    earlier[e] = true;
                    earlierTaken.Remove(e);
                    break;
                }
            }

            foreach (PwEntry e in live)
            {
                string key = SyncData.Fold(labelOf[e]);
                // An entry in a group of that name is never synced, so it claims no label
                bool webGroup = SyncData.Fold(SyncData.Field(Labels.Group(e, options), Wire.MaxGroup)) == Wire.WwwfillGroup;
                if (only != null && !only.Contains(e))
                {
                    // Not chosen: it only claims its label
                    if (!webGroup && !claimed.ContainsKey(key)) claimed[key] = e;
                    continue;
                }
                var item = new PlanItem();
                item.Entry = e;
                item.Label = labelOf[e];
                item.Local = SyncData.Project(db, e, item.Label, options);
                if (webGroup)
                {
                    items.Add(Blocked(item, "the group name wwwfill is reserved on the Seclave"));
                    continue;
                }
                if (claimed.ContainsKey(key))
                {
                    if (SyncData.StoredLabel(e) != null)
                        Blocked(item, "linked to the same Seclave label as " + SyncData.Describe(claimed[key]) +
                            "; use Reset Seclave label on one of them");
                    else
                        Blocked(item, "same Seclave label as " + SyncData.Describe(claimed[key]) + "; rename one of them");
                    items.Add(item);
                    continue;
                }
                claimed[key] = e;

                string blocked = Unsyncable(db, e, item.Label, snapshot);
                if (blocked != null)
                {
                    items.Add(Blocked(item, blocked));
                    continue;
                }
                if (push) ClassifyPush(item, SyncData.Baseline(e), syncKey, all);
                else Classify(item, snapshot.Find(item.Label), SyncData.Baseline(e), syncKey);
                if (item.Action == SyncAction.UpdateKeePass || item.Conflict)
                {
                    string referenced = ReferencesOverwritten(db, e, item.Device);
                    if (referenced.Length > 0)
                    {
                        item.Conflict = false;
                        item.Action = SyncAction.None;
                        Blocked(item, "the " + referenced + " differs on the Seclave, and in KeePass takes its value from " +
                            "another entry or field; change it there");
                    }
                }
                if (earlier.ContainsKey(e)) item.Reason = "under its label from an earlier pattern; " + item.Reason;
                if (earlierTaken.ContainsKey(e) && item.Action == SyncAction.AddToDevice)
                {
                    item.Apply = false;
                    item.Reason = "not on the Seclave under this label, but perhaps as " + earlierTaken[e] +
                        ", its label under an earlier pattern, which now names another entry";
                }
                // Firmware 2.6 and earlier replaces an entry only by deleting it
                // first, and an entry that was not read is never deleted
                if (item.Action == SyncAction.UpdateDevice && !item.Blind && !item.Device.HasFields && !snapshot.ReplacesInPlace)
                {
                    Blocked(item, "already on the Seclave but not read, and this firmware can only replace it by deleting it first");
                    item.Action = SyncAction.None;
                }
                if (item.WritesDevice || item.Conflict)
                {
                    string losses = SyncData.Losses(db, e);
                    if (losses.Length > 0)
                    {
                        item.Reason += " (" + losses + ")";
                        item.Apply = false;
                    }
                }
                if (item.Action != SyncAction.None || item.Conflict || item.Blocked != null) items.Add(item);
            }

            if (only != null || !snapshot.WholeStore) return items;

            foreach (PwEntry e in binned)
            {
                string label = SyncData.StoredLabel(e);
                if (label == null || claimed.ContainsKey(SyncData.Fold(label))) continue;
                DeviceEntry d = snapshot.Find(label);
                if (d == null) continue;
                claimed[SyncData.Fold(label)] = e;
                var item = new PlanItem();
                item.Entry = e;
                item.Label = label;
                item.Device = d;
                if (!d.HasFields)
                {
                    items.Add(Blocked(item, "in the KeePass recycle bin; the Seclave copy was not read, so it is not deleted"));
                    continue;
                }
                item.Action = SyncAction.DeleteOnDevice;
                item.Reason = "in the KeePass recycle bin";
                items.Add(item);
            }

            var deviceOnly = new List<string>();
            foreach (string key in snapshot.Entries.Keys)
                if (!claimed.ContainsKey(key)) deviceOnly.Add(key);
            deviceOnly.Sort(StringComparer.Ordinal);
            WarnAboutLikelyDuplicates(items, snapshot, deviceOnly);
            foreach (string key in deviceOnly)
            {
                var item = new PlanItem();
                item.Device = snapshot.Entries[key];
                item.Label = item.Device.Label;
                if (item.Device.HasFields)
                {
                    item.Action = SyncAction.AddToKeePass;
                    item.Reason = "only on the Seclave";
                }
                else
                {
                    Blocked(item, "only on the Seclave (not read)");
                }
                items.Add(item);
            }
            return items;
        }

        private static PlanItem Blocked(PlanItem item, string why)
        {
            item.Blocked = why;
            item.Reason = why;
            item.Apply = false;
            return item;
        }

        // Why the entry cannot be synced at all, or null. A password the
        // device would hold changed ('?' for a letter, or cut short) is a
        // wrong password, and so is a placeholder KeePass would fill in, or
        // a reference it cannot follow to its end.
        private static string Unsyncable(PwDatabase db, PwEntry e, string label, Snapshot snapshot)
        {
            if (snapshot.IsReserved(label)) return "this label is used by a web login on the Seclave";
            string unfollowable = SeclavePluginExt.UnfollowableField(db, e);
            if (unfollowable != null)
                return "a reference in the " + unfollowable + " cannot be followed (it may refer to itself or be nested too deeply)";
            string password = SeclavePluginExt.FieldValue(db, e, PwDefs.PasswordField);
            if (SeclavePluginExt.HasNonLatin1(password)) return "the password has characters the Seclave cannot store";
            if (SyncData.Field(password, int.MaxValue).Length > Wire.MaxPassword)
                return "the password is longer than the " + Wire.MaxPassword + " characters the Seclave stores";
            if (SeclavePluginExt.HasPlaceholder(password) ||
                SeclavePluginExt.HasPlaceholder(SeclavePluginExt.FieldValue(db, e, PwDefs.UserNameField)) ||
                SeclavePluginExt.HasPlaceholder(SeclavePluginExt.FieldValue(db, e, PwDefs.NotesField)))
                return "a KeePass placeholder the plugin does not fill in, such as {CLIPBOARD}, or a reference to an entry that " +
                    "is gone, in the username, password or notes; the Seclave would hold the placeholder text";
            return null;
        }

        // The fields a pull would write the Seclave's value into over a value
        // the entry takes from another entry or field, by name
        private static string ReferencesOverwritten(PwDatabase db, PwEntry e, DeviceEntry device)
        {
            var names = new List<string>();
            if (!SyncData.SameOnDevice(db, e, PwDefs.UserNameField, device.Username, Wire.MaxUsername) &&
                SyncData.IsReference(db, e, PwDefs.UserNameField)) names.Add("username");
            if (!SyncData.SameOnDevice(db, e, PwDefs.PasswordField, device.Password, Wire.MaxPassword) &&
                SyncData.IsReference(db, e, PwDefs.PasswordField)) names.Add("password");
            if (!SyncData.SameOnDevice(db, e, PwDefs.NotesField, device.Optional, Wire.MaxOptional) &&
                SyncData.IsReference(db, e, PwDefs.NotesField)) names.Add("notes");
            return string.Join(", ", names.ToArray());
        }

        // An entry the device holds under a label no pattern here explains
        // (a pattern from before the last change, say) would be added a
        // second time. When a device-only entry has the same username and
        // password as an entry about to be added, the add is not ticked.
        private static void WarnAboutLikelyDuplicates(List<PlanItem> items, Snapshot snapshot, List<string> deviceOnly)
        {
            foreach (PlanItem item in items)
            {
                if (item.Action != SyncAction.AddToDevice || !item.Apply || item.Local.Password.Length == 0) continue;
                foreach (string key in deviceOnly)
                {
                    DeviceEntry d = snapshot.Entries[key];
                    if (!d.HasFields) continue;
                    if (SyncData.Field(d.Username, Wire.MaxUsername) != item.Local.Username ||
                        SyncData.Field(d.Password, Wire.MaxPassword) != item.Local.Password) continue;
                    item.Apply = false;
                    item.Reason = "not on the Seclave under this label, but " + d.Label +
                        " there has the same username and password; perhaps it is this entry under an older label";
                    break;
                }
            }
        }

        // The three-way compare: the entry now, the device now, and the
        // baseline (the device's state as last known, null if never synced).
        // key is the database's sync key, null if it is missing, in which
        // case no baseline can be checked.
        private static void Classify(PlanItem item, DeviceEntry device, string baseline, byte[] key)
        {
            item.Device = device;
            if (device == null)
            {
                item.Action = SyncAction.AddToDevice;
                if (baseline == null)
                {
                    item.Apply = true;
                    item.Reason = "not on the Seclave";
                }
                else
                {
                    item.Reason = "deleted on the Seclave since the last sync";
                }
                return;
            }

            // A device group the plugin writes the same way (SameGroup) is the
            // entry's group: the entry takes the device's name for it, so a
            // push leaves the group there as it is
            if (device.Group != null && SyncData.SameGroup(item.Local.Group, device.Group)) item.Local.Group = device.Group;

            if (!device.HasFields)
            {
                if (baseline == null)
                {
                    item.Action = SyncAction.UpdateDevice;
                    item.Reason = "already on the Seclave but not read: overwrite it";
                }
                else if (key != null && SyncData.Mac(key, item.Local) != baseline)
                {
                    item.Action = SyncAction.UpdateDevice;
                    item.Reason = "changed in KeePass; the Seclave copy was not read, so a change made there would be lost";
                }
                return;
            }

            string diff = SyncData.Differences(item.Local, device);
            if (baseline == null)
            {
                if (diff.Length == 0)
                {
                    item.Action = SyncAction.Link;
                    item.Apply = true;
                    item.Reason = "already on the Seclave";
                }
                else if (diff == "group")
                {
                    // Typically an exported entry moved to another group since
                    item.Action = SyncAction.UpdateDevice;
                    item.Apply = true;
                    item.Reason = "on the Seclave in another group, never synced: move it there too" + MoveCost;
                }
                else
                {
                    item.Conflict = true;
                    item.Reason = "on the Seclave with a different " + diff + ", never synced";
                }
                return;
            }

            if (key == null)
            {
                if (diff.Length == 0)
                {
                    item.Action = SyncAction.Link;
                    item.Apply = true;
                    item.Reason = "linked again: the sync key entry is missing";
                }
                else
                {
                    item.Conflict = true;
                    item.Reason = "cannot verify which side changed; the sync key entry is missing";
                }
                return;
            }

            bool localChanged = SyncData.Mac(key, item.Local) != baseline;
            bool deviceChanged = SyncData.Mac(key, device) != baseline;
            if (!localChanged && !deviceChanged) return;
            if (localChanged && !deviceChanged)
            {
                item.Action = SyncAction.UpdateDevice;
                item.Apply = true;
                item.Reason = "changed in KeePass: " + diff + (diff == "group" ? MoveCost : "");
            }
            else if (!localChanged)
            {
                item.Action = SyncAction.UpdateKeePass;
                item.Apply = true;
                item.Reason = "changed on the Seclave: " + diff.Replace("group", "group (not applied)");
            }
            else if (diff.Length == 0)
            {
                item.Action = SyncAction.Link;
                item.Apply = true;
                item.Reason = "same change in KeePass and on the Seclave";
            }
            else
            {
                item.Conflict = true;
                item.Reason = "changed in KeePass and on the Seclave: " + diff;
            }
        }

        // An update is a replace, two presses in the Normal security mode;
        // the reason says so when only the group changes
        private const string MoveCost = " (two presses on the device in the Normal security mode)";

        private static void ClassifyPush(PlanItem item, string baseline, byte[] key, bool all)
        {
            item.Blind = true;
            item.Apply = true;
            if (baseline == null)
            {
                item.Action = SyncAction.AddToDevice;
                item.Reason = "not synced before; replaces an entry under its label on the Seclave";
            }
            else if (key == null)
            {
                item.Action = SyncAction.UpdateDevice;
                item.Reason = "may have changed: the sync key entry is missing, so the plugin cannot tell";
            }
            else if (SyncData.Mac(key, item.Local) != baseline)
            {
                item.Action = SyncAction.UpdateDevice;
                item.Reason = "changed in KeePass since the last sync; replaces the Seclave's copy";
            }
            else if (all)
            {
                item.Action = SyncAction.UpdateDevice;
                item.Reason = "unchanged since the last sync; written again";
            }
        }

        // The user's pick for a conflict
        public static void Resolve(PlanItem item, SyncAction action)
        {
            if (!item.Conflict) return;
            item.Action = action;
            item.Apply = action != SyncAction.None;
        }

        // A pull changes only KeePass. What would write to the Seclave is left
        // out, and counted; a conflict becomes an unticked update in KeePass,
        // which takes the Seclave's version.
        public static List<PlanItem> PullOnly(List<PlanItem> plan, out int leftOut)
        {
            var items = new List<PlanItem>();
            leftOut = 0;
            foreach (PlanItem item in plan)
            {
                if (item.Conflict)
                {
                    item.Conflict = false;
                    item.Action = SyncAction.UpdateKeePass;
                    item.Apply = false;
                    item.Reason += "; ticked, the Seclave's version replaces KeePass's";
                }
                if (item.WritesDevice)
                {
                    leftOut++;
                    continue;
                }
                items.Add(item);
            }
            return items;
        }
    }

    public static class Applier
    {
        // Runs the device side of the plan: deletes first (they free space),
        // then updates, then adds. A decline on the device skips that item.
        // Returns null, or why the session ended early.
        public static string RunOnDevice(DeviceSession session, List<PlanItem> items)
        {
            bool replaceInPlace = session.AtLeast(2, 7);
            var order = new List<PlanItem>();
            foreach (SyncAction a in new SyncAction[] { SyncAction.DeleteOnDevice, SyncAction.UpdateDevice, SyncAction.AddToDevice })
                foreach (PlanItem item in items)
                    if (item.Apply && item.Blocked == null && item.Action == a) order.Add(item);

            // A label whose replace question firmware 2.6 still shows, after
            // answering a push's put that the label exists
            string asking = null;
            for (int i = 0; i < order.Count; i++)
            {
                PlanItem item = order[i];
                try
                {
                    RunOne(session, item, replaceInPlace, asking);
                    asking = null;
                }
                catch (DeviceException ex)
                {
                    if (ex.Status == Wire.StAbort) item.Outcome = "declined on the Seclave";
                    else item.Outcome = "failed: " + ex.Message;
                    asking = null;
                    if (ex.Status == Wire.StLabelExists && item.Blind)
                    {
                        // The push goes on: the next command waits until the
                        // question is answered. Whatever the answer, the entry
                        // counts as not written, so the change stays to write and
                        // a later sync, which reads it, finds it either way.
                        item.Outcome = "already on the Seclave, which now asks whether to replace it; " +
                            "counted as not replaced, so the next sync checks it";
                        asking = item.Label;
                    }
                    else if (ex.Status == Wire.StLabelExists)
                    {
                        // The device now shows its own replace prompt, and
                        // would act on it without telling us. Firmware 2.6 and
                        // earlier answers a put onto an existing label this
                        // way; 2.7 answers with the outcome of its prompt, so
                        // a device that reports 2.7 and answers this way
                        // replaces as 2.6 does.
                        item.Outcome = "already on the Seclave, which now asks whether to replace it: decline that on the device";
                        return NotAttempted(order, i + 1, "the Seclave is waiting for an answer to its replace question" +
                            (replaceInPlace ? "; it reports firmware " + session.FirmwareVersion + " but answered as firmware 2.6 does" : ""));
                    }
                }
                catch (CancelledException)
                {
                    item.Outcome = "cancelled; check this entry on the Seclave";
                    return NotAttempted(order, i + 1, "cancelled; " + DeviceSession.AnswerPending);
                }
                catch (DisconnectedException ex)
                {
                    item.Outcome = "connection lost; check this entry on the Seclave";
                    return NotAttempted(order, i + 1, "connection to the Seclave lost: " + ex.Message);
                }
            }
            return null;
        }

        private static string NotAttempted(List<PlanItem> order, int from, string why)
        {
            for (int i = from; i < order.Count; i++) order[i].Outcome = "not attempted";
            return why;
        }

        private static void RunOne(DeviceSession session, PlanItem item, bool replaceInPlace, string asking)
        {
            // What the Seclave shows first, while it still asks about the last one
            string first = asking != null ? "answer whether to replace " + asking + ", then " : "";
            switch (item.Action)
            {
                case SyncAction.DeleteOnDevice:
                    item.Outcome = session.DeleteEntry(item.Label) ? "deleted from the Seclave" : "was already gone from the Seclave";
                    item.DeviceDone = true;
                    break;
                case SyncAction.AddToDevice:
                    session.PutEntry(item.Local, first + "add entry " + item.Label);
                    item.Outcome = item.Blind ? "written to the Seclave" : "added to the Seclave";
                    item.DeviceDone = true;
                    break;
                case SyncAction.UpdateDevice:
                    if (item.Blind)
                    {
                        // A push puts, and the Seclave adds or replaces it: on
                        // firmware 2.6 a replace is the put's LabelExists
                        session.PutEntry(item.Local, first + "add or replace entry " + item.Label);
                    }
                    else if (replaceInPlace)
                    {
                        // Firmware 2.7 and later asks to replace and answers with the outcome
                        try { session.PutEntry(item.Local, "replace entry " + item.Label); }
                        catch (DeviceException ex)
                        {
                            // A full store refuses a replace too; deleting first makes
                            // room, but only an entry that was read is deleted
                            if (ex.Status != Wire.StNoSpace || item.Device == null || !item.Device.HasFields) throw;
                            ReplaceByDeleting(session, item);
                        }
                    }
                    else
                    {
                        ReplaceByDeleting(session, item);
                    }
                    item.Outcome = "updated on the Seclave";
                    item.DeviceDone = true;
                    break;
            }
        }

        // Firmware 2.6 and earlier cannot report a replace: delete, then add
        private static void ReplaceByDeleting(DeviceSession session, PlanItem item)
        {
            bool existed = session.DeleteEntry(item.Label);
            item.DeviceRemoved = existed;
            session.PutEntry(item.Local, "add entry " + item.Label);
            item.DeviceRemoved = false;
        }

        // The KeePass side, on the UI thread, after RunOnDevice. Returns the
        // number of entries whose fields changed.
        public static int ApplyToKeePass(PwDatabase db, List<PlanItem> items)
        {
            using (var key = new SyncKey(db)) return ApplyToKeePass(db, items, key);
        }

        // The sync key is made the first time a baseline is written to a
        // database that has none
        private static int ApplyToKeePass(PwDatabase db, List<PlanItem> items, SyncKey key)
        {
            int changed = 0;
            bool touched = false;
            foreach (PlanItem item in items)
            {
                if (!item.Apply || item.Blocked != null) continue;
                switch (item.Action)
                {
                    case SyncAction.AddToDevice:
                    case SyncAction.UpdateDevice:
                        if (item.DeviceDone) SyncData.SetBaseline(item.Entry, item.Label, item.Local, key.Get());
                        else if (item.DeviceRemoved)
                        {
                            SyncData.SetBaseline(item.Entry, item.Label, null, null);
                            item.Outcome = "removed from the Seclave, but the new version was not stored (" + item.Outcome + "); sync again to add it";
                        }
                        else continue;
                        break;
                    case SyncAction.DeleteOnDevice:
                        if (!item.DeviceDone) continue;
                        SyncData.RemoveBaseline(item.Entry);
                        break;
                    case SyncAction.Link:
                        SyncData.SetBaseline(item.Entry, item.Label, item.Device, key.Get());
                        item.Outcome = "linked";
                        break;
                    case SyncAction.UpdateKeePass:
                        bool kept = PullInto(db, item.Entry, item.Device);
                        SyncData.SetBaseline(item.Entry, item.Label, item.Device, key.Get());
                        item.Outcome = kept ? "updated in KeePass (the old version is in the entry's history)" :
                            "updated in KeePass; the database keeps no history, so the old version is gone";
                        changed++;
                        break;
                    case SyncAction.AddToKeePass:
                        item.Entry = AddEntry(db, item.Device);
                        SyncData.SetBaseline(item.Entry, item.Label, item.Device, key.Get());
                        item.Outcome = "added to KeePass in " + SyncData.ImportGroup;
                        changed++;
                        break;
                    default:
                        continue;
                }
                touched = true;
            }
            if (touched) db.Modified = true;
            return changed;
        }

        // Writes the device's username, password and notes into the entry where
        // they differ from what the device would hold for it, except over a
        // value the entry takes from another entry or field. The group is left
        // alone. The previous version goes to the entry's history first; false
        // if the database's history settings did not keep it.
        private static bool PullInto(PwDatabase db, PwEntry entry, DeviceEntry device)
        {
            entry.CreateBackup(db);
            // The backup is the newest history item, and history is pruned
            // oldest first: if any item is left, the backup is
            bool kept = entry.History.UCount > 0;
            if (Takes(db, entry, PwDefs.UserNameField, device.Username, Wire.MaxUsername))
                entry.Strings.Set(PwDefs.UserNameField, Protect(db.MemoryProtection.ProtectUserName, device.Username));
            if (Takes(db, entry, PwDefs.PasswordField, device.Password, Wire.MaxPassword))
                entry.Strings.Set(PwDefs.PasswordField, Protect(db.MemoryProtection.ProtectPassword, device.Password));
            if (Takes(db, entry, PwDefs.NotesField, device.Optional, Wire.MaxOptional))
                entry.Strings.Set(PwDefs.NotesField, Protect(db.MemoryProtection.ProtectNotes, Notes(device.Optional)));
            entry.Touch(true, false);
            entry.MaintainBackups(db);
            return kept;
        }

        // Built from bytes: a ProtectedString built from a string keeps that
        // string as its value, unprotected in memory
        private static ProtectedString Protect(bool protect, string value)
        {
            byte[] utf8 = StrUtil.Utf8.GetBytes(value);
            try { return new ProtectedString(protect, utf8); }
            finally { MemUtil.ZeroByteArray(utf8); }
        }

        // Device notes in KeePass's line ends; the device may hold CR LF
        // from an import as well as LF
        private static string Notes(string optional)
        {
            return optional.Replace("\r\n", "\n").Replace("\n", Environment.NewLine);
        }

        // Whether the pull writes the device's value into the entry's field
        private static bool Takes(PwDatabase db, PwEntry entry, string field, string value, int max)
        {
            return !SyncData.SameOnDevice(db, entry, field, value, max) && !SyncData.IsReference(db, entry, field);
        }

        private static PwEntry AddEntry(PwDatabase db, DeviceEntry device)
        {
            PwGroup group = db.RootGroup.FindCreateGroup(SyncData.ImportGroup, true);
            if (device.Group.Length > 0) group = group.FindCreateGroup(device.Group, true);
            var e = new PwEntry(true, true);
            e.Strings.Set(PwDefs.TitleField, Protect(db.MemoryProtection.ProtectTitle, device.Label));
            e.Strings.Set(PwDefs.UserNameField, Protect(db.MemoryProtection.ProtectUserName, device.Username));
            e.Strings.Set(PwDefs.PasswordField, Protect(db.MemoryProtection.ProtectPassword, device.Password));
            e.Strings.Set(PwDefs.NotesField, Protect(db.MemoryProtection.ProtectNotes, Notes(device.Optional)));
            group.AddEntry(e, true);
            return e;
        }
    }

    // ---- dialogs ----

    public enum SnapshotSource { Backup, ReadAll }

    public enum SyncMode { Sync, Push, Pull }

    // The port box of the connect dialogs
    public static class PortBox
    {
        // The ports found, with the Seclave's chosen; failing that, the port
        // used last, which may be one the plugin cannot tell is a Seclave's
        public static void Fill(ComboBox box, List<PortChoice> ports, string lastPort)
        {
            foreach (PortChoice p in ports) box.Items.Add(p);
            PortChoice pick = null;
            foreach (PortChoice p in ports)
                if (p.Seclave && (pick == null || p.Name == lastPort)) pick = p;
            if (pick == null)
                foreach (PortChoice p in ports)
                    if (p.Name == lastPort) pick = p;
            if (pick != null) box.SelectedItem = pick;
            else if (!string.IsNullOrEmpty(lastPort)) box.Text = lastPort;
            else if (ports.Count > 0) box.SelectedIndex = 0;
        }

        // The name of the port chosen, or typed
        public static string Chosen(ComboBox box)
        {
            string text = box.Text.Trim();
            foreach (PortChoice p in box.Items)
                if (p.ToString() == text) return p.Name;
            return text;
        }
    }

    // What the command does, as a heading and rows of what it reads, writes
    // and costs on the Seclave, and the port; a push also offers to write the
    // entries unchanged since the last sync
    public sealed class ConnectForm : Form
    {
        private readonly ComboBox m_port = new ComboBox();
        private readonly CheckBox m_all = new CheckBox();
        public string Port;
        public bool WriteAll;

        // facts: a row's name, then what it says, for each row; caution: shown
        // in red under the rows, or null
        public ConnectForm(string title, string heading, string[] facts, string caution, List<PortChoice> ports, string lastPort,
            bool offerAll)
        {
            Text = title;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            const int names = 12, values = 132, width = 536;

            var head = new Label();
            head.Text = heading;
            int y = Place(head, names, 12, width, true) + 12;
            for (int i = 0; i + 1 < facts.Length; i += 2)
            {
                var name = new Label();
                name.Text = facts[i];
                int bottom = Place(name, names, y, values - names - 4, true);
                var value = new Label();
                value.Text = facts[i + 1];
                y = Math.Max(bottom, Place(value, values, y, width + names - values, false)) + 6;
            }
            if (caution != null)
            {
                var text = new Label();
                text.Text = caution;
                text.ForeColor = Color.Firebrick;
                y = Place(text, names, y + 4, width, true) + 6;
            }

            y += 10;
            var portLabel = new Label();
            portLabel.Text = "Port:";
            portLabel.Font = new Font(Font, FontStyle.Bold);
            portLabel.SetBounds(names, y + 3, values - names - 4, 20);
            Controls.Add(portLabel);
            m_port.DropDownStyle = ComboBoxStyle.DropDown;
            PortBox.Fill(m_port, ports, lastPort);
            m_port.SetBounds(values, y, 300, 24);
            Controls.Add(m_port);
            y += 34;
            if (offerAll)
            {
                m_all.Text = "Also write the entries unchanged since the last sync, to repair the Seclave";
                m_all.SetBounds(names, y, width, 24);
                Controls.Add(m_all);
                y += 32;
            }

            var ok = new Button();
            ok.Text = "Connect";
            ok.SetBounds(372, y + 8, 85, 28);
            ok.Click += OnOk;
            Controls.Add(ok);
            var cancel = new Button();
            cancel.Text = "Cancel";
            cancel.DialogResult = DialogResult.Cancel;
            cancel.SetBounds(463, y + 8, 85, 28);
            Controls.Add(cancel);
            AcceptButton = ok;
            CancelButton = cancel;
            ClientSize = new Size(560, y + 8 + 28 + 12);
            Shown += delegate
            {
                if (m_port.Text.Length > 0) ok.Focus();
                else m_port.Focus();
            };
        }

        // Puts the label at x,y, as wide as given and as tall as its text
        // wraps to; returns its bottom
        private int Place(Label label, int x, int y, int width, bool bold)
        {
            Controls.Add(label);
            if (bold) label.Font = new Font(Font, FontStyle.Bold);
            Size size = TextRenderer.MeasureText(label.Text, label.Font, new Size(width, 0), TextFormatFlags.WordBreak);
            label.SetBounds(x, y, width, size.Height + 2);
            return y + size.Height + 2;
        }

        private void OnOk(object sender, EventArgs e)
        {
            Port = PortBox.Chosen(m_port);
            if (Port.Length == 0)
            {
                MessageBox.Show(this, "Enter the Seclave's serial port.", Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            WriteAll = m_all.Checked;
            DialogResult = DialogResult.OK;
        }
    }

    // Where the backup comes from, and its key, with what typing the key
    // means next to where it is typed
    public sealed class ImportForm : Form
    {
        private readonly RadioButton m_fromSeclave = new RadioButton();
        private readonly RadioButton m_fromFile = new RadioButton();
        private readonly ComboBox m_port = new ComboBox();
        private readonly TextBox m_file = new TextBox();
        private readonly Button m_browse = new Button();
        private readonly TextBox m_key = new TextBox();
        public string Port;             // null for a file
        public string BackupFile;       // null for the Seclave
        public byte[] BackupKey;

        public const string KeyWarning = "Typing the backup key exposes it to this computer. The key never changes, and " +
            "with it anyone can open any backup of this Seclave (a SECLAVE.BKP or .bkp file), past or future, with every " +
            "password in it. Type it only on a computer you trust, and keep backup files apart from it.";

        public ImportForm(List<PortChoice> ports, string lastPort)
        {
            Text = "Import Seclave backup";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(560, 362);
            var intro = new Label();
            intro.Text = "Imports the Seclave's backup into KeePass: every entry it holds, ticked in the review, where you " +
                "can untick any. Nothing is written to the Seclave.";
            intro.SetBounds(12, 10, 536, 36);
            Controls.Add(intro);

            m_fromSeclave.Text = "From the Seclave in Usb slave mode (one press, Export backup)";
            m_fromSeclave.SetBounds(12, 52, 536, 22);
            Controls.Add(m_fromSeclave);
            var portLabel = new Label();
            portLabel.Text = "Port:";
            portLabel.SetBounds(32, 81, 44, 20);
            Controls.Add(portLabel);
            m_port.DropDownStyle = ComboBoxStyle.DropDown;
            PortBox.Fill(m_port, ports, lastPort);
            m_port.SetBounds(80, 78, 300, 24);
            Controls.Add(m_port);

            m_fromFile.Text = "From a backup file: SECLAVE.BKP, or a .bkp from the Seclave Companion";
            m_fromFile.SetBounds(12, 112, 536, 22);
            Controls.Add(m_fromFile);
            m_file.SetBounds(32, 138, 420, 24);
            Controls.Add(m_file);
            m_browse.Text = "Browse...";
            m_browse.SetBounds(460, 137, 88, 26);
            m_browse.Click += OnBrowse;
            Controls.Add(m_browse);

            var keyLabel = new Label();
            keyLabel.Text = "Backup key (Backup > Show key):";
            keyLabel.SetBounds(12, 182, 220, 20);
            Controls.Add(keyLabel);
            m_key.SetBounds(240, 179, 308, 24);
            m_key.UseSystemPasswordChar = true;
            Controls.Add(m_key);
            var warning = new Label();
            warning.Text = KeyWarning;
            warning.SetBounds(12, 212, 536, 92);
            warning.ForeColor = Color.Firebrick;
            warning.Font = new Font(Font, FontStyle.Bold);
            Controls.Add(warning);

            var ok = new Button();
            ok.Text = "Import";
            ok.SetBounds(372, 322, 85, 28);
            ok.Click += OnOk;
            Controls.Add(ok);
            var cancel = new Button();
            cancel.Text = "Cancel";
            cancel.DialogResult = DialogResult.Cancel;
            cancel.SetBounds(463, 322, 85, 28);
            Controls.Add(cancel);
            AcceptButton = ok;
            CancelButton = cancel;
            // The key is copied out by OnOk; the text box keeps no copy
            FormClosing += delegate { m_key.Text = ""; };

            m_fromSeclave.CheckedChanged += delegate { ShowSource(); };
            m_fromSeclave.Checked = true;
            ShowSource();
            Shown += delegate { m_key.Focus(); };
        }

        private void ShowSource()
        {
            m_port.Enabled = m_fromSeclave.Checked;
            m_file.Enabled = !m_fromSeclave.Checked;
            m_browse.Enabled = !m_fromSeclave.Checked;
        }

        private void OnBrowse(object sender, EventArgs e)
        {
            using (var open = new OpenFileDialog())
            {
                open.Title = "Seclave backup";
                open.Filter = "Seclave backups (*.bkp)|*.bkp;*.BKP|All files (*.*)|*.*";
                if (open.ShowDialog(this) == DialogResult.OK) m_file.Text = open.FileName;
            }
        }

        private void OnOk(object sender, EventArgs e)
        {
            Port = null;
            BackupFile = null;
            if (m_fromSeclave.Checked)
            {
                Port = PortBox.Chosen(m_port);
                if (Port.Length == 0)
                {
                    MessageBox.Show(this, "Enter the Seclave's serial port.", Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
            }
            else
            {
                BackupFile = m_file.Text.Trim();
                if (!System.IO.File.Exists(BackupFile))
                {
                    MessageBox.Show(this, "Choose the backup file.", Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
            }
            BackupKey = Backup.ParseKey(m_key.Text);
            if (BackupKey == null)
            {
                MessageBox.Show(this, "The backup key is 32 hexadecimal digits, as Backup > Show key shows it on the Seclave.",
                    Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            DialogResult = DialogResult.OK;
        }
    }

    // Runs one step against the device on a worker thread, showing what the
    // device is waiting for. Cancel abandons the command in flight, and so
    // does any other attempt to close the dialog while the worker runs.
    public sealed class ProgressForm : Form
    {
        private readonly Label m_status = new Label();
        private readonly DeviceSession m_session;
        private readonly Action m_work;
        private Thread m_thread;
        private volatile bool m_done;
        public Exception Error;

        public ProgressForm(string title, DeviceSession session, Action work)
        {
            m_session = session;
            m_work = work;
            Text = title;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            ControlBox = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(460, 110);
            m_status.SetBounds(12, 12, 436, 50);
            m_status.Text = "Working...";
            Controls.Add(m_status);
            var cancel = new Button();
            cancel.Text = "Cancel";
            cancel.SetBounds(363, 72, 85, 28);
            cancel.Click += delegate { CancelWork(); };
            Controls.Add(cancel);
            if (session != null)
                session.Waiting = delegate(string what) { SetStatus(what == null ? "Working..." : "Confirm on the Seclave if it asks: " + what); };
            FormClosing += delegate(object sender, FormClosingEventArgs e)
            {
                if (m_done) return;
                e.Cancel = true;
                CancelWork();
            };
            Shown += delegate
            {
                m_thread = new Thread(Run);
                m_thread.IsBackground = true;
                m_thread.Start();
            };
        }

        private void CancelWork()
        {
            m_status.Text = "Cancelling...";
            if (m_session != null) m_session.Cancel();
        }

        public void SetStatus(string text)
        {
            Post(delegate { m_status.Text = text; });
        }

        // From the worker: asks on the dialog's thread, and waits for the
        // answer; true for OK
        public bool Ask(string title, string text)
        {
            bool ok = false;
            Invoke((MethodInvoker)delegate
            {
                ok = Dialogs.Message(text, title, MessageBoxButtons.OKCancel, MessageBoxIcon.Question) == DialogResult.OK;
            });
            return ok;
        }

        // Runs on the UI thread, unless the dialog is already gone
        private void Post(MethodInvoker action)
        {
            try
            {
                if (IsHandleCreated && !IsDisposed) BeginInvoke(action);
            }
            catch (InvalidOperationException) { }
        }

        private void Run()
        {
            try { m_work(); }
            catch (Exception ex) { Error = ex; }
            m_done = true;
            Post(delegate { DialogResult = DialogResult.OK; });
        }

        // After the dialog has closed: waits for the worker, cancelling it if
        // it still runs. False if the work did not finish, in which case
        // nothing it was producing may be used.
        public bool Finish()
        {
            if (m_thread != null && !m_thread.Join(0))
            {
                // A finished worker is only returning; cancelling it would
                // cancel the session for the steps that follow
                if (!m_done && m_session != null) m_session.Cancel();
                m_thread.Join(5000);
            }
            return m_done;
        }
    }

    public sealed class ReviewForm : Form
    {
        private readonly ListView m_list = new ListView();
        private readonly Label m_note = new Label();
        private readonly Label m_summary = new Label();
        private readonly List<PlanItem> m_items;
        private readonly int m_free;
        private readonly PromptState m_prompts;

        public const string AllowAllCaveat = "Careful: while Allow all is set, any computer connected over USB can read " +
            "and change every entry on the Seclave without a confirmation there.";

        // free: free slots on the device, or -1 if not known; prompts: whether
        // the Seclave was found to ask for presses
        public ReviewForm(List<PlanItem> items, string source, int free, PromptState prompts)
        {
            m_items = items;
            m_free = free;
            m_prompts = prompts;
            Text = "Seclave sync: review";
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(900, 480);
            MinimizeBox = false;

            var intro = new Label();
            intro.Text = "Read from the Seclave: " + source + ". Ticked rows are applied; nothing happens before Apply. " +
                "Conflicts changed on both sides: select them and pick a version.";
            intro.SetBounds(12, 8, 876, 36);
            intro.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            Controls.Add(intro);

            m_list.View = View.Details;
            m_list.CheckBoxes = true;
            m_list.FullRowSelect = true;
            m_list.HideSelection = false;
            m_list.Columns.Add("Action", 150);
            m_list.Columns.Add("KeePass entry", 200);
            m_list.Columns.Add("Seclave label", 130);
            m_list.Columns.Add("Details", 380);
            m_list.SetBounds(12, 48, 876, 290);
            m_list.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            foreach (PlanItem item in items)
            {
                var row = new ListViewItem(new string[] { item.ActionText, item.EntryText, item.Label, item.Reason });
                row.Tag = item;
                row.Checked = item.Apply;
                if (item.Blocked != null) row.ForeColor = SystemColors.GrayText;
                m_list.Items.Add(row);
            }
            m_list.ItemCheck += OnItemCheck;
            m_list.ItemChecked += delegate { UpdateSummary(); };
            Controls.Add(m_list);

            m_note.SetBounds(12, 344, 876, 46);
            m_note.Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            m_note.ForeColor = Color.Firebrick;
            m_note.Font = new Font(Font, FontStyle.Bold);
            Controls.Add(m_note);

            m_summary.SetBounds(12, 394, 876, 36);
            m_summary.Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            Controls.Add(m_summary);

            var useKeePass = new Button();
            useKeePass.Text = "Use KeePass version";
            useKeePass.SetBounds(12, 440, 150, 28);
            useKeePass.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            useKeePass.Click += delegate { ResolveSelected(SyncAction.UpdateDevice); };
            Controls.Add(useKeePass);
            var useSeclave = new Button();
            useSeclave.Text = "Use Seclave version";
            useSeclave.SetBounds(168, 440, 150, 28);
            useSeclave.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            useSeclave.Click += delegate { ResolveSelected(SyncAction.UpdateKeePass); };
            Controls.Add(useSeclave);

            var apply = new Button();
            apply.Text = "Apply";
            apply.DialogResult = DialogResult.OK;
            apply.SetBounds(712, 440, 85, 28);
            apply.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
            Controls.Add(apply);
            var cancel = new Button();
            cancel.Text = "Cancel";
            cancel.DialogResult = DialogResult.Cancel;
            cancel.SetBounds(803, 440, 85, 28);
            cancel.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
            Controls.Add(cancel);
            AcceptButton = apply;
            CancelButton = cancel;
            Shown += delegate { apply.Focus(); };
            UpdateSummary();
        }

        private void OnItemCheck(object sender, ItemCheckEventArgs e)
        {
            var item = (PlanItem)m_list.Items[e.Index].Tag;
            if (item.Blocked != null || (item.Conflict && item.Action == SyncAction.None))
                e.NewValue = CheckState.Unchecked;
            else
                item.Apply = e.NewValue == CheckState.Checked;
        }

        private void ResolveSelected(SyncAction action)
        {
            foreach (ListViewItem row in m_list.SelectedItems)
            {
                var item = (PlanItem)row.Tag;
                if (!item.Conflict) continue;
                Planner.Resolve(item, action);
                row.SubItems[0].Text = item.ActionText;
                row.Checked = item.Apply;
            }
        }

        // The presses the Seclave asks for to apply the item in the Normal
        // mode: a replace is two
        public static int Presses(PlanItem item)
        {
            if (!item.Apply || item.Blocked != null || !item.WritesDevice) return 0;
            // A push cannot know whether the label is taken there
            return item.Action == SyncAction.UpdateDevice || item.Blind ? 2 : 1;
        }

        // Shown while the Seclave is found to ask for presses and the plan
        // changes it: how many, and how to do without; null otherwise
        public static string PromptNote(PromptState prompts, List<PlanItem> items)
        {
            int presses = 0;
            foreach (PlanItem item in items) presses += Presses(item);
            if (prompts != PromptState.Prompting || presses == 0) return null;
            return "The Seclave asks for a press of its joystick for each change: up to " + presses + " for this sync. " +
                "To keep it a mirror of KeePass without them, set Admin > Slave security > Allow all on the Seclave for " +
                "the sync, and back to Normal after it. " + AllowAllCaveat;
        }

        private void UpdateSummary()
        {
            int deviceWrites = 0, presses = 0, keepass = 0, room = 0;
            foreach (PlanItem item in m_items)
            {
                if (!item.Apply || item.Blocked != null) continue;
                if (item.WritesDevice)
                {
                    deviceWrites++;
                    presses += Presses(item);
                    if (item.Action == SyncAction.AddToDevice) room++;
                    if (item.Action == SyncAction.DeleteOnDevice) room--;
                }
                else if (item.Action == SyncAction.UpdateKeePass || item.Action == SyncAction.AddToKeePass)
                {
                    keepass++;
                }
            }
            m_summary.Text = String.Format("Changes on the Seclave: {0} (up to {1} presses on the device in the Normal security mode). " +
                "Entries changed in KeePass: {2}.", deviceWrites, presses, keepass);
            m_note.Text = PromptNote(m_prompts, m_items) ?? "";
            if (m_free >= 0 && room > m_free)
                m_summary.Text += String.Format(" The Seclave has room for {0} more entries; adds beyond that will fail.", m_free);
        }
    }

    // The menu commands
    public static class SyncCommand
    {
        private const string Title = "Seclave sync";
        private const string PortConfig = "Seclave.Sync.Port";
        public static void SyncAll(IPluginHost host) { Run(host, null, SyncMode.Sync); }
        public static void PushAll(IPluginHost host) { Run(host, null, SyncMode.Push); }
        public static void PullAll(IPluginHost host) { Run(host, null, SyncMode.Pull); }

        // The entries selected in KeePass's list, or those of the selected
        // group: the sync, both ways; the push, which reads nothing from the
        // Seclave; or the pull, which changes only KeePass. A sync or pull
        // reads only those entries from the Seclave.
        public static void SyncSelected(IPluginHost host) { RunOnSelected(host, SyncMode.Sync); }
        public static void PushSelected(IPluginHost host) { RunOnSelected(host, SyncMode.Push); }
        public static void PullSelected(IPluginHost host) { RunOnSelected(host, SyncMode.Pull); }
        public static void SyncGroup(IPluginHost host) { RunOnGroup(host, SyncMode.Sync); }
        public static void PushGroup(IPluginHost host) { RunOnGroup(host, SyncMode.Push); }
        public static void PullGroup(IPluginHost host) { RunOnGroup(host, SyncMode.Pull); }

        // By SyncMode
        private static readonly string[] s_titles = { "Sync with Seclave", "Push to Seclave", "Pull from Seclave" };
        private static readonly string[] s_verbs = { "sync", "push", "pull" };
        private static readonly string[] s_ways = { "sync with", "push to", "pull from" };

        private static void RunOnSelected(IPluginHost host, SyncMode mode)
        {
            PwDatabase db = host.Database;
            if (db == null || !db.IsOpen)
            {
                Dialogs.Message("Open the password database first.", Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            PwEntry[] selected = host.MainWindow.GetSelectedEntries();
            var only = new List<PwEntry>();
            if (selected != null)
                foreach (PwEntry e in selected)
                    if (Choosable(db, e)) only.Add(e);
            if (only.Count == 0)
            {
                Dialogs.Message("Select the entries to " + s_ways[(int)mode] + " the Seclave first; " +
                    "those in the recycle bin are not synced on their own.", Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            Run(host, only, mode);
        }

        private static void RunOnGroup(IPluginHost host, SyncMode mode)
        {
            PwDatabase db = host.Database;
            if (db == null || !db.IsOpen)
            {
                Dialogs.Message("Open the password database first.", Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            PwGroup group = host.MainWindow.GetSelectedGroup();
            List<PwEntry> only = group != null ? GroupEntries(db, group) : new List<PwEntry>();
            if (only.Count == 0)
            {
                Dialogs.Message("The group has no entries to " + s_verbs[(int)mode] + "; " +
                    "those in the recycle bin are not synced on their own.", Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            Run(host, only, mode);
        }

        // The entries of a group and of the groups in it that a command on some
        // entries takes
        public static List<PwEntry> GroupEntries(PwDatabase db, PwGroup group)
        {
            var entries = new List<PwEntry>();
            foreach (PwEntry e in group.GetEntries(true))
                if (Choosable(db, e)) entries.Add(e);
            return entries;
        }

        // Not the sync key entry, and not an entry in the recycle bin, which
        // only a sync of the whole Seclave offers to delete there
        private static bool Choosable(PwDatabase db, PwEntry e)
        {
            return !SyncKey.IsKeyEntry(e) && !SeclavePluginExt.IsInRecycleBin(db, e);
        }

        // KeePass may close or switch the database while a dialog is open
        private static bool StillOpen(IPluginHost host, PwDatabase db)
        {
            return db.IsOpen && ReferenceEquals(db, host.Database);
        }

        private static string Failure(string what, Exception ex)
        {
            if (ex is CancelledException) return what + " was cancelled; " + DeviceSession.AnswerPending + ".";
            return what + " failed: " + ex.Message;
        }

        // The open database's label settings, or null after saying why there are none
        private static LabelOptions Ready(IPluginHost host)
        {
            PwDatabase db = host.Database;
            if (db == null || !db.IsOpen)
            {
                Dialogs.Message("Open the password database first.", Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return null;
            }
            LabelOptions options = LabelOptions.Load(host.CustomConfig);
            string patternError = LabelPattern.Error(options.Pattern);
            if (patternError != null)
            {
                Dialogs.Message("The saved label pattern is not valid. " + patternError + Environment.NewLine +
                    "Correct it under Tools > Seclave > Seclave settings...", Title, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return null;
            }
            return options;
        }

        private static DeviceSession Open(string port)
        {
            try { return new DeviceSession(port); }
            catch (Exception ex)
            {
                Dialogs.Message("Cannot open " + port + ": " + ex.Message + DeviceSession.LinuxPortAdvice(port),
                    Title, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return null;
            }
        }

        private static string FirmwareText(DeviceSession session)
        {
            return session.FirmwareVersion != null ? "firmware " + session.FirmwareVersion : "firmware 2.6 or earlier";
        }

        // What a command reads, writes and costs, for its dialog: a heading, a
        // row's name then what it says for each row, and a caution or null
        private static string[] Facts(SyncMode mode, List<PwEntry> only, out string heading, out string caution)
        {
            string chosen = only == null ? null : only.Count == 1 ? "the chosen entry" : "the " + only.Count + " chosen entries";
            // Each cost on a line of its own
            string none = Environment.NewLine + "None when Slave security is Allow all";
            caution = null;
            if (mode == SyncMode.Push)
            {
                heading = only == null ? "Write KeePass's changes to the Seclave" : "Write the changes to " + chosen + " to the Seclave";
                caution = "Each entry written replaces the one under its label on the Seclave: a change made there is lost.";
                return new string[] {
                    "On the Seclave:", "Choose Usb slave",
                    "Reads:", "Nothing",
                    "Writes:", only == null ? "The entries new or changed in KeePass since the last sync" :
                        only.Count == 1 ? "The chosen entry, if it is new or changed since the last sync" :
                        "Those of " + chosen + " that are new or changed since the last sync",
                    "Presses:", "1 per entry written, 2 to replace one" + none };
            }
            string reads = only == null ? "Every field of every entry" : "Only " + chosen;
            string readPresses = only == null ? "3 or 4 per entry read" : "4 per entry read, 1 if the Seclave does not have it";
            if (mode == SyncMode.Pull)
            {
                heading = only == null ? "Take the Seclave's changes into KeePass" :
                    "Take the Seclave's changes to " + chosen + " into KeePass";
                var rows = new List<string> {
                    "On the Seclave:", "Choose Usb slave",
                    "Reads:", reads,
                    "Writes:", "Only KeePass: what you tick in the review",
                    "Presses:", readPresses + none };
                if (only == null)
                {
                    rows.Add("Faster:");
                    rows.Add("Import Seclave backup reads every entry with one press");
                }
                return rows.ToArray();
            }
            heading = only == null ? "Sync KeePass and the Seclave, both ways" : "Sync " + chosen + " with the Seclave, both ways";
            return new string[] {
                "On the Seclave:", "Choose Usb slave",
                "Reads:", reads,
                "Writes:", "What you tick in the review, on the Seclave and in KeePass",
                "Presses:", readPresses + Environment.NewLine + "1 per entry written, 2 to replace one" + none };
        }

        private static void Run(IPluginHost host, List<PwEntry> only, SyncMode mode)
        {
            PwDatabase db = host.Database;
            LabelOptions options = Ready(host);
            if (options == null) return;
            string port;
            bool all;
            string heading, caution;
            string[] facts = Facts(mode, only, out heading, out caution);
            using (var connect = new ConnectForm(s_titles[(int)mode], heading, facts, caution, DeviceSession.FindPorts(),
                host.CustomConfig.GetString(PortConfig, ""), mode == SyncMode.Push))
            {
                if (Dialogs.ShowDialog(connect, host.MainWindow) != DialogResult.OK) return;
                port = connect.Port;
                all = connect.WriteAll;
            }
            host.CustomConfig.SetString(PortConfig, port);
            DeviceSession session = Open(port);
            if (session == null) return;
            try { Sync(host, db, options, only, mode, all, session); }
            finally { session.Dispose(); }
        }

        private static void Sync(IPluginHost host, PwDatabase db, LabelOptions options, List<PwEntry> only, SyncMode mode,
            bool all, DeviceSession session)
        {
            Form owner = host.MainWindow;
            var snapshot = new Snapshot();
            string source = "";
            ProgressForm read = null;
            bool readStopped = false;
            Func<int, bool> goOn = null;
            if (only == null && mode != SyncMode.Push)
                goOn = delegate(int presses)
                {
                    readStopped = !read.Ask(Title, PressQuestion(mode, presses));
                    return !readStopped;
                };
            using (read = new ProgressForm(mode == SyncMode.Push ? "Connecting to the Seclave" : "Reading the Seclave", session, delegate
            {
                session.Probe();
                if (mode == SyncMode.Push)
                    source = "nothing, as a push never reads; each ticked entry replaces the entry under its label there, " +
                        FirmwareText(session);
                else
                    source = ReadSnapshot(session, SnapshotSource.ReadAll, null, only, options, snapshot, goOn);
            }))
            {
                DialogResult result = Dialogs.ShowDialog(read, owner);
                bool finished = read.Finish() && result == DialogResult.OK;
                if (!finished)
                {
                    Dialogs.Message("Reading the Seclave did not finish; nothing was changed.", Title, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                if (read.Error != null)
                {
                    // Stopped at the question, nothing is pending on the device
                    if (!readStopped)
                        Dialogs.Message(Failure("Reading the Seclave", read.Error), Title, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
            }

            if (!StillOpen(host, db))
            {
                Dialogs.Message("The database was closed while syncing; nothing was changed. Sync again after unlocking it.",
                    Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            List<PlanItem> plan;
            int leftOut = 0;
            if (mode == SyncMode.Push)
                plan = Planner.BuildPush(db, only ?? GroupEntries(db, db.RootGroup), options, all);
            else
            {
                plan = Planner.Build(db, snapshot, only, options);
                if (mode == SyncMode.Pull)
                {
                    plan = Planner.PullOnly(plan, out leftOut);
                    source += "; a pull changes only KeePass" +
                        (leftOut > 0 ? ", and leaves out " + leftOut + (leftOut == 1 ? " change" : " changes") + " for the Seclave" : "");
                }
            }
            if (plan.Count == 0)
            {
                string text;
                if (mode == SyncMode.Push)
                    text = all ? "There are no entries to push." : "Nothing to push: no entry has changed in KeePass since the last sync.";
                else if (mode == SyncMode.Pull)
                    text = "Nothing to pull: the Seclave holds " + (only == null ? "every entry" : "the chosen entries") +
                        " as it did at the last sync.";
                else
                    text = only == null ? "KeePass and the Seclave are in sync." : "The chosen entries are in sync with the Seclave.";
                if (leftOut > 0)
                    text += " " + leftOut + (leftOut == 1 ? " of them has changed in KeePass or is not on the Seclave" :
                        " of them have changed in KeePass or are not on the Seclave") + "; Push to Seclave... writes those.";
                Dialogs.Message(text + KeyEntriesNote(db), Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            using (var review = new ReviewForm(plan, source, snapshot.Free, session.Prompts))
            {
                if (Dialogs.ShowDialog(review, owner) != DialogResult.OK) return;
            }

            if (!StillOpen(host, db))
            {
                Dialogs.Message("The database was closed while syncing; nothing was changed. Sync again after unlocking it.",
                    Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            string stopped = null;
            using (var write = new ProgressForm("Writing to the Seclave", session, delegate
            {
                stopped = Applier.RunOnDevice(session, plan);
            }))
            {
                Dialogs.ShowDialog(write, owner);
                if (!write.Finish())
                {
                    Dialogs.Message("Writing to the Seclave did not finish, so KeePass was not changed. Check the Seclave and sync again.",
                        Title, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                if (write.Error != null) stopped = Failure("Writing", write.Error);
            }

            if (!StillOpen(host, db))
            {
                Dialogs.Message("The database was closed while syncing; the Seclave was updated. Sync again after unlocking it.",
                    Title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            int changed = Applier.ApplyToKeePass(db, plan);
            host.MainWindow.UpdateUI(false, null, changed > 0, null, true, null, db.Modified);
            ShowResult(plan, stopped, KeyEntriesNote(db));
        }

        // Import Seclave backup: every entry of a backup, read from the Seclave
        // with one press or from a file, into KeePass, ticked in the review;
        // nothing is written to the Seclave
        public static void ImportBackup(IPluginHost host)
        {
            PwDatabase db = host.Database;
            LabelOptions options = Ready(host);
            if (options == null) return;
            byte[] key = null;
            try
            {
                string port, file;
                using (var form = new ImportForm(DeviceSession.FindPorts(), host.CustomConfig.GetString(PortConfig, "")))
                {
                    if (Dialogs.ShowDialog(form, host.MainWindow) != DialogResult.OK) return;
                    port = form.Port;
                    file = form.BackupFile;
                    key = form.BackupKey;
                }
                var snapshot = new Snapshot();
                string source = "";
                if (file != null)
                {
                    string error = ReadBackupFile(file, key, snapshot);
                    if (error != null)
                    {
                        Dialogs.Message("Cannot read the backup " + file + ": " + error, Title, MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                    source = "its backup file " + System.IO.Path.GetFileName(file);
                }
                else
                {
                    host.CustomConfig.SetString(PortConfig, port);
                    DeviceSession session = Open(port);
                    if (session == null) return;
                    try
                    {
                        using (var read = new ProgressForm("Reading the Seclave's backup", session, delegate
                        {
                            session.Probe();
                            source = ReadSnapshot(session, SnapshotSource.Backup, key, null, options, snapshot, null);
                        }))
                        {
                            DialogResult result = Dialogs.ShowDialog(read, host.MainWindow);
                            if (!read.Finish() || result != DialogResult.OK)
                            {
                                Dialogs.Message("Reading the Seclave did not finish; nothing was changed.", Title, MessageBoxButtons.OK, MessageBoxIcon.Error);
                                return;
                            }
                            if (read.Error != null)
                            {
                                Dialogs.Message(Failure("Reading the Seclave's backup", read.Error), Title, MessageBoxButtons.OK, MessageBoxIcon.Error);
                                return;
                            }
                        }
                    }
                    finally { session.Dispose(); }
                }
                snapshot.WholeStore = true;

                if (!StillOpen(host, db))
                {
                    Dialogs.Message("The database was closed while importing; nothing was changed.", Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                List<PlanItem> plan = ImportPlan(db, snapshot, options);
                if (plan.Count == 0)
                {
                    Dialogs.Message("KeePass already holds every entry of the backup." + KeyEntriesNote(db), Title,
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                using (var review = new ReviewForm(plan, source + "; an import changes only KeePass", -1, PromptState.Unknown))
                {
                    if (Dialogs.ShowDialog(review, host.MainWindow) != DialogResult.OK) return;
                }
                if (!StillOpen(host, db))
                {
                    Dialogs.Message("The database was closed while importing; nothing was changed.", Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                int changed = Applier.ApplyToKeePass(db, plan);
                host.MainWindow.UpdateUI(false, null, changed > 0, null, true, null, db.Modified);
                ShowResult(plan, null, KeyEntriesNote(db));
            }
            finally
            {
                if (key != null) Array.Clear(key, 0, key.Length);
            }
        }

        // A backup file decrypted into the snapshot; null, or why it cannot be read
        public static string ReadBackupFile(string file, byte[] key, Snapshot snapshot)
        {
            try
            {
                foreach (DeviceEntry e in Backup.Decrypt(Backup.ReadArchive(System.IO.File.ReadAllBytes(file)), key)) snapshot.Add(e);
                return null;
            }
            catch (System.IO.IOException ex) { return ex.Message; }
            catch (UnauthorizedAccessException ex) { return ex.Message; }
            catch (DisconnectedException ex) { return ex.Message; }
            catch (BackupKeyException ex) { return ex.Message; }
        }

        // An import's plan: a pull of the whole backup, where an entry only on
        // the Seclave starts ticked too, since bringing every entry in is what
        // an import is for; a change made on both sides stays unticked
        public static List<PlanItem> ImportPlan(PwDatabase db, Snapshot snapshot, LabelOptions options)
        {
            int leftOut;
            List<PlanItem> plan = Planner.PullOnly(Planner.Build(db, snapshot, null, options), out leftOut);
            foreach (PlanItem item in plan)
                if (item.Action == SyncAction.AddToKeePass && item.Blocked == null) item.Apply = true;
            return plan;
        }

        // For the closing message, when merged databases brought more than
        // one sync key entry
        private static string KeyEntriesNote(PwDatabase db)
        {
            int count;
            SyncKey.Find(db, out count);
            if (count < 2) return "";
            return Environment.NewLine + Environment.NewLine + "The database has " + count + " Seclave sync key entries, as after " +
                "merging databases; the oldest is used, and the others can be deleted.";
        }

        // Asked once when reading every field, as soon as the Seclave is found
        // to ask for a press for each
        private static string PressQuestion(SyncMode mode, int presses)
        {
            string what = mode == SyncMode.Pull ? "pull" : "sync";
            return "The Seclave asks for a press of its joystick for every field it shows: reading every field of every " +
                "entry needs about " + presses + " more." + Environment.NewLine + Environment.NewLine +
                "OK goes on reading. Cancel stops the " + what + ", and nothing is changed; then either set Admin > Slave " +
                "security > Allow all on the Seclave, which reads without presses, and set it back to Normal after the " +
                what + ", or " + (mode == SyncMode.Pull ? "use Import Seclave backup, which reads every entry with one press" :
                "use Import Seclave backup, one press, to take in the Seclave's changes, and Push to Seclave to write " +
                "KeePass's") + "." + Environment.NewLine + Environment.NewLine + ReviewForm.AllowAllCaveat;
        }

        // Fills the snapshot and returns a short description of what was read.
        // goOn: when every field is read, asked once, with the presses still
        // ahead, as soon as the device is found to ask for them; false stops
        // the read with a CancelledException.
        public static string ReadSnapshot(DeviceSession session, SnapshotSource source, byte[] backupKey,
            List<PwEntry> only, LabelOptions options, Snapshot snapshot, Func<int, bool> goOn)
        {
            string firmware = FirmwareText(session);
            snapshot.ReplacesInPlace = session.AtLeast(2, 7);
            if (session.Total > 0 && session.Used >= 0) snapshot.Free = session.Total - session.Used;
            if (source == SnapshotSource.Backup)
            {
                foreach (DeviceEntry e in session.ReadBackup(backupKey)) snapshot.Add(e);
                snapshot.WholeStore = true;
                if (snapshot.Free < 0) snapshot.Free = Wire.MaxEntries - snapshot.Entries.Count - snapshot.Reserved.Count;
                return "all entries via the backup stream, " + firmware;
            }
            if (only != null)
            {
                foreach (PwEntry entry in only)
                {
                    DeviceEntry e = ReadOrDeclined(session, SyncData.LabelFor(entry, options), null);
                    // A never-synced entry may be there under an earlier pattern's label
                    if (e == null && SyncData.StoredLabel(entry) == null)
                    {
                        foreach (string old in Labels.Earlier(entry, options))
                        {
                            e = ReadOrDeclined(session, old, null);
                            if (e != null) break;
                        }
                    }
                    if (e != null) snapshot.Add(e);
                }
                return "the chosen entries, " + firmware;
            }
            List<DeviceEntry> labels = session.ListLabels();
            int next = 0;
            bool asked = false;
            if (goOn != null)
                session.BeforePress = delegate
                {
                    if (asked) return true;
                    asked = true;
                    return goOn(PressesLeft(labels, next));
                };
            try
            {
                for (next = 0; next < labels.Count; next++)
                {
                    DeviceEntry label = labels[next];
                    if (label.Group == Wire.WwwfillGroup)
                    {
                        snapshot.Add(label);
                        continue;
                    }
                    DeviceEntry e = ReadOrDeclined(session, label.Label, label.Group);
                    if (e != null) snapshot.Add(e);
                }
            }
            finally { session.BeforePress = null; }
            snapshot.WholeStore = true;
            if (snapshot.Free < 0) snapshot.Free = Wire.MaxEntries - labels.Count;
            return "every field of every entry, " + firmware;
        }

        // The presses reading every field still needs from labels[next] on,
        // one per field, the group too where the label list left it out
        private static int PressesLeft(List<DeviceEntry> labels, int next)
        {
            int presses = 0;
            for (int i = next; i < labels.Count; i++)
                if (labels[i].Group != Wire.WwwfillGroup) presses += labels[i].Group == null ? 4 : 3;
            return presses;
        }

        // An entry whose reading was declined on the device is kept as not
        // read, so the plan never ticks a change to it; the read goes on
        private static DeviceEntry ReadOrDeclined(DeviceSession session, string label, string group)
        {
            try { return session.ReadEntry(label, group); }
            catch (DeviceException ex)
            {
                if (ex.Status != Wire.StAbort) throw;
                var e = new DeviceEntry();
                e.Label = label;
                e.Group = group;
                return e;
            }
        }

        private static void ShowResult(List<PlanItem> plan, string stopped, string keyNote)
        {
            int done = 0;
            var problems = new List<string>();
            foreach (PlanItem item in plan)
            {
                if (!item.Apply || item.Blocked != null || item.Outcome == null) continue;
                bool ok = item.WritesDevice ? item.DeviceDone : true;
                if (ok) done++;
                else problems.Add(item.Label + ": " + item.Outcome);
            }
            var text = new StringBuilder();
            text.Append("Changes applied: " + done + ".");
            if (stopped != null) text.Append(Environment.NewLine + "Stopped early: " + stopped);
            if (problems.Count > 0)
            {
                text.Append(Environment.NewLine + Environment.NewLine);
                text.Append(string.Join(Environment.NewLine, problems.ToArray()));
            }
            text.Append(keyNote);
            text.Append(Environment.NewLine + Environment.NewLine + "Save the database to keep the changes and the sync state.");
            Dialogs.Message(text.ToString(), "Seclave sync complete", MessageBoxButtons.OK,
                problems.Count > 0 || stopped != null ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
        }
    }
}
