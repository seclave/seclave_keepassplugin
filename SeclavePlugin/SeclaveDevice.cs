// SPDX-License-Identifier: MIT
// Copyright 2026 Seclave AB
//
// The Seclave USB-slave interface: the wire protocol, the serial port, the
// commands the sync uses, and decryption of the backup stream. Nothing in
// this file knows about KeePass.
//
// Wire format, host to device: a 2-byte little-endian payload length, then
// the payload: an opcode byte followed by integers and fields. An integer
// below 254 is one byte; anything else is FF, a byte count (1 or 2) and the
// value little-endian. A field is an integer length and that many Latin-1
// bytes. Responses carry no length prefix: a status integer, then (for OK)
// the fields that command returns, so the reader has to know how many fields
// to expect.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Ports;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace SeclavePlugin
{
    public static class Wire
    {
        public const int OpGetGroup = 1;
        public const int OpGetUsername = 2;
        public const int OpGetPassword = 3;
        public const int OpGetOptional = 4;
        public const int OpGetWwwfill = 5;
        public const int OpGetLabelIdx = 6;
        public const int OpPutEntry = 9;
        public const int OpDelEntry = 10;
        public const int OpGetBackup = 12;
        public const int OpQueryStatus = 13;        // firmware 2.7 and later only
        // Firmware 2.7 and later have it, but 2.7 sends a label of 16 characters
        // and a group of 8 one character short, so it is used from 2.8 only
        public const int OpGetLabelGroupIdx = 14;

        public const int StOk = 0;
        public const int StEntryNotFound = 1;
        public const int StParseError = 2;          // never on the wire: the device leaves slave mode instead
        public const int StAbort = 3;               // the user declined on the device
        public const int StOutOfIndex = 4;          // end of an enumeration
        public const int StLabelExists = 5;
        public const int StNoSpace = 6;
        public const int StBadLabel = 7;
        public const int StBadDomain = 8;
        public const int StMoreLabels = 9;

        public const int MaxLabel = 16;
        public const int MaxGroup = 8;
        public const int MaxUsername = 50;
        public const int MaxPassword = 50;
        public const int MaxOptional = 83;
        public const int MaxEntries = 500;

        // A longer (or empty) frame makes the device drop out of slave mode.
        public const int MaxFramePayload = 228;

        public const string WwwfillGroup = "wwwfill";

        // The version probe (Latin-1: three o-umlauts). Firmware 2.7 and later
        // answers it with the marker; earlier firmware does not know the domain
        // and answers "not found", without a prompt in the default mode.
        public const string VersionDomain = "\u00f6\u00f6\u00f6seclave.version";
        public const string VersionMarker = "\u00f6\u00f6\u00f6seclave";

        public static readonly Encoding Latin1 = Encoding.GetEncoding("ISO-8859-1");

        public static string StatusText(int status)
        {
            switch (status)
            {
                case StOk: return "OK";
                case StEntryNotFound: return "no such entry on the Seclave";
                case StAbort: return "declined on the Seclave";
                case StLabelExists: return "the label already exists on the Seclave";
                case StNoSpace: return "the Seclave is full (500 entries)";
                case StBadLabel: return "the Seclave rejected the label or group";
                default: return "Seclave status " + status;
            }
        }

        public static void PutInt(List<byte> buf, int value)
        {
            // Two bytes is the widest integer the protocol has
            if (value < 0 || value > 0xffff) throw new ArgumentOutOfRangeException("value");
            if (value < 254)
            {
                buf.Add((byte)value);
            }
            else if (value <= 0xff)
            {
                buf.Add(0xff); buf.Add(1); buf.Add((byte)value);
            }
            else
            {
                buf.Add(0xff); buf.Add(2); buf.Add((byte)(value & 0xff)); buf.Add((byte)(value >> 8));
            }
        }

        public static void PutField(List<byte> buf, string text)
        {
            byte[] data = Latin1.GetBytes(text);
            PutInt(buf, data.Length);
            buf.AddRange(data);
        }

        public static byte[] Frame(List<byte> payload)
        {
            if (payload.Count < 1 || payload.Count > MaxFramePayload)
                throw new ArgumentException("frame payload of " + payload.Count + " bytes");
            var frame = new byte[payload.Count + 2];
            frame[0] = (byte)(payload.Count & 0xff);
            frame[1] = (byte)(payload.Count >> 8);
            payload.CopyTo(frame, 2);
            return frame;
        }

        // Returns false while buf[0..count) does not hold the whole integer yet.
        public static bool TryGetInt(byte[] buf, int count, ref int off, out int value)
        {
            value = 0;
            if (off >= count) return false;
            if (buf[off] != 0xff)
            {
                value = buf[off++];
                return true;
            }
            if (off + 1 >= count) return false;
            int n = buf[off + 1];
            if (n != 1 && n != 2) throw new DisconnectedException("garbled response from the Seclave");
            if (off + 2 + n > count) return false;
            value = buf[off + 2];
            if (n == 2) value |= buf[off + 3] << 8;
            off += 2 + n;
            return true;
        }

        // Parses a whole response, or returns null if more bytes are needed.
        // Only OK and MORE_LABELS carry fields.
        public static Response TryParse(byte[] buf, int count, int fieldCount)
        {
            int off = 0;
            int status;
            if (!TryGetInt(buf, count, ref off, out status)) return null;
            var r = new Response();
            r.Status = status;
            if (status != StOk && status != StMoreLabels)
            {
                r.Fields = new byte[0][];
                r.Length = off;
                return r;
            }
            r.Fields = new byte[fieldCount][];
            for (int i = 0; i < fieldCount; i++)
            {
                int length;
                if (!TryGetInt(buf, count, ref off, out length)) return null;
                if (off + length > count) return null;
                r.Fields[i] = new byte[length];
                Array.Copy(buf, off, r.Fields[i], 0, length);
                off += length;
            }
            r.Length = off;
            return r;
        }
    }

    public sealed class Response
    {
        public int Status;
        public byte[][] Fields;
        public int Length;      // bytes of the stream the response took

        public string Text(int i) { return Wire.Latin1.GetString(Fields[i]); }
    }

    public class DeviceException : Exception
    {
        public readonly int Status;

        public DeviceException(int status) : base(Wire.StatusText(status)) { Status = status; }
    }

    // The port is gone or the device is out of step with us; the session is over.
    public class DisconnectedException : Exception
    {
        public DisconnectedException(string message) : base(message) { }
    }

    public class CancelledException : Exception
    {
        public CancelledException() : base("cancelled") { }
    }

    public class BackupKeyException : Exception
    {
        public BackupKeyException(string message) : base(message) { }
    }

    // One entry as the device holds it. HasFields is false when only the
    // label (and perhaps the group) was read.
    public sealed class DeviceEntry
    {
        public string Label;
        public string Group;
        public string Username;
        public string Password;
        public string Optional;

        public bool HasFields { get { return Password != null; } }
    }

    // A path with every link in it followed, as the C library's realpath()
    // gives it on Linux and macOS, for which .NET has no call; null if there
    // is no such path. In sysfs that is where a device sits.
    internal static class UnixPath
    {
        [DllImport("libc", EntryPoint = "realpath")]
        private static extern IntPtr RealPath(string path, [Out] byte[] resolved);

        public static string Real(string path)
        {
            var resolved = new byte[4096];     // PATH_MAX
            if (RealPath(path, resolved) == IntPtr.Zero) return null;
            int end = Array.IndexOf(resolved, (byte)0);
            return Encoding.UTF8.GetString(resolved, 0, end < 0 ? resolved.Length : end);
        }
    }

    // Whether the Seclave asks for a press of its joystick before it does
    // what it is asked, as found from how long it takes to answer
    public enum PromptState { Unknown, Prompting, NotPrompting }

    // A serial port as the connect dialogs offer it: its name, and whether it
    // is known by its USB ids to be the Seclave's
    public sealed class PortChoice
    {
        public readonly string Name;
        public readonly bool Seclave;

        public PortChoice(string name, bool seclave)
        {
            Name = name;
            Seclave = seclave;
        }

        // The Seclave's port is named as such, unless its name says it already
        public override string ToString()
        {
            return Seclave && Name.IndexOf("seclave", StringComparison.OrdinalIgnoreCase) < 0 ? Name + " (Seclave)" : Name;
        }
    }

    public sealed class DeviceSession : IDisposable
    {
        // A read waits this long before checking for Cancel. Confirmable
        // commands block until the user acts on the device, so there is no
        // overall timeout.
        private const int PollMs = 250;

        // After a cancel the device may still show the question it was asked,
        // and answers it whenever the user acts, ahead of anything asked later
        public const string AnswerPending = "answer or decline any question still showing on the Seclave, then try again";
        private const string OutOfStep = "the Seclave answered out of step; " + AnswerPending;

        private readonly SerialPort m_port;
        private readonly byte[] m_recv = new byte[4096];
        private volatile bool m_cancel;

        // Called with a description before a command that may wait for a
        // confirmation on the device, and with null once it has answered.
        public Action<string> Waiting;

        // A person answers a prompt on the device no faster than this, while
        // the device answers what it does not ask about within milliseconds,
        // tens of them over a slow USB serial port: a command that may be
        // confirmed and takes longer than this was confirmed on the device
        public const int PromptSenseMs = 1000;

        // Found from the commands the device may confirm: Prompting once one
        // took longer than PromptSenseMs or was declined; NotPrompting once a
        // field read or a change was quicker. A quick version check or label
        // list or backup read proves nothing: the first is confirmed only in
        // the Ask all mode, the others only once per Usb slave session.
        public PromptState Prompts = PromptState.Unknown;

        // Called on the worker thread before each command the device may
        // confirm, once it is found to prompt; false ends the work with a
        // CancelledException before the device is asked
        public Func<bool> BeforePress;

        public string FirmwareVersion;      // "2.7"; null for 2.6 and earlier, or unknown
        public int Used = -1;
        public int Total = -1;

        public DeviceSession(string portName)
        {
            m_port = new SerialPort(portName);
            m_port.ReadTimeout = PollMs;
            m_port.WriteTimeout = 5000;
            m_port.Handshake = Handshake.None;
            m_port.Open();
            // A CDC device may wait for DTR before it sends. A pseudo-terminal
            // has no modem lines, which is fine.
            try
            {
                m_port.DtrEnable = true;
                m_port.RtsEnable = true;
            }
            catch (IOException) { }
            m_port.DiscardInBuffer();
        }

        public void Dispose()
        {
            try { m_port.Close(); }
            catch (IOException) { }
            // Windows reports a port whose device was unplugged this way
            catch (UnauthorizedAccessException) { }
            catch (InvalidOperationException) { }
        }

        // Callable from any thread. A command waiting for the device is
        // abandoned by closing the port; its outcome on the device is unknown.
        public void Cancel()
        {
            m_cancel = true;
        }

        public bool AtLeast(int major, int minor)
        {
            if (FirmwareVersion == null) return false;
            string[] parts = FirmwareVersion.Split('.');
            int ma, mi;
            if (parts.Length != 2 || !int.TryParse(parts[0], out ma) || !int.TryParse(parts[1], out mi)) return false;
            return ma > major || (ma == major && mi >= minor);
        }

        private Response Exchange(List<byte> payload, int fieldCount, string prompt)
        {
            byte[] frame = Wire.Frame(payload);
            int opcode = payload[0];
            try
            {
                if (m_cancel) throw new CancelledException();
                if (prompt != null && Prompts == PromptState.Prompting && BeforePress != null && !BeforePress())
                    throw new CancelledException();
                var clock = Stopwatch.StartNew();
                try { m_port.Write(frame, 0, frame.Length); }
                catch (IOException ex) { throw new DisconnectedException(ex.Message); }
                catch (InvalidOperationException ex) { throw new DisconnectedException(ex.Message); }
                catch (UnauthorizedAccessException ex) { throw new DisconnectedException(ex.Message); }
                catch (TimeoutException) { throw new DisconnectedException("the Seclave does not accept data"); }
                if (prompt != null && Waiting != null) Waiting(prompt);

                int filled = 0;
                while (true)
                {
                    Response r = Wire.TryParse(m_recv, filled, fieldCount);
                    // One command, one response: anything after it is an answer
                    // to some other question
                    if (r != null && r.Length != filled) throw new DisconnectedException(OutOfStep);
                    if (r != null)
                    {
                        if (prompt != null) Sense(opcode, r.Status, clock.ElapsedMilliseconds);
                        return r;
                    }
                    if (filled == m_recv.Length) throw new DisconnectedException("response too long");
                    if (m_cancel)
                    {
                        Dispose();
                        throw new CancelledException();
                    }
                    int n;
                    try { n = m_port.Read(m_recv, filled, m_recv.Length - filled); }
                    catch (TimeoutException) { continue; }
                    catch (IOException ex) { throw new DisconnectedException(ex.Message); }
                    catch (InvalidOperationException ex) { throw new DisconnectedException(ex.Message); }
                    // Windows reports an unplugged USB serial port this way
                    catch (UnauthorizedAccessException ex) { throw new DisconnectedException(ex.Message); }
                    // A read times out while the device is silent; returning
                    // nothing means the port was hung up (Mono, unplugged)
                    if (n == 0) throw new DisconnectedException("the Seclave went away");
                    filled += n;
                }
            }
            finally
            {
                // Responses can carry passwords
                Array.Clear(m_recv, 0, m_recv.Length);
                payload.Clear();
                Array.Clear(frame, 0, frame.Length);
                if (prompt != null && Waiting != null) Waiting(null);
            }
        }

        // What the answer to a command the device may confirm shows
        private void Sense(int opcode, int status, long ms)
        {
            if (ms > PromptSenseMs || status == Wire.StAbort) Prompts = PromptState.Prompting;
            else if (Prompts == PromptState.Unknown && opcode != Wire.OpGetWwwfill && opcode != Wire.OpGetLabelIdx &&
                opcode != Wire.OpGetLabelGroupIdx && opcode != Wire.OpGetBackup)
                Prompts = PromptState.NotPrompting;
        }

        private static List<byte> Command(int opcode)
        {
            var payload = new List<byte>();
            payload.Add((byte)opcode);
            return payload;
        }

        // Finds out which firmware this is, without ever sending an opcode the
        // device may not know: an unknown opcode ends the session.
        public void Probe()
        {
            var probe = Command(Wire.OpGetWwwfill);
            Wire.PutField(probe, Wire.VersionDomain);
            Wire.PutInt(probe, 0);
            // Promptless except in the Ask all mode
            Response r = Exchange(probe, 2, "version check");
            // Firmware 2.6 and earlier answers "not found"; a decline proves
            // nothing about the firmware: both are taken as old firmware. Any
            // other answer is not one to this question.
            if (r.Status == Wire.StMoreLabels) throw new DisconnectedException(OutOfStep);
            if (r.Status != Wire.StOk) return;
            if (r.Text(0) != Wire.VersionMarker || r.Fields[1].Length != 0) throw new DisconnectedException(OutOfStep);

            r = Exchange(Command(Wire.OpQueryStatus), 3, null);
            if (r.Status != Wire.StOk) return;
            FirmwareVersion = r.Text(0);
            int.TryParse(r.Text(1), out Used);
            int.TryParse(r.Text(2), out Total);
        }

        // Every label, and from firmware 2.8 its group. One "Show all labels"
        // confirmation covers the whole walk. Firmware 2.7 has the
        // label-and-group enumeration too, but returns a label that fills all
        // 16 characters, or a group that fills all 8, one character short
        // there, so on 2.7 only the labels are listed, as on 2.6.
        public List<DeviceEntry> ListLabels()
        {
            bool withGroups = AtLeast(2, 8);
            var labels = new List<DeviceEntry>();
            for (int index = 0; ; index++)
            {
                // The store holds at most 500 entries, so the device ends the
                // walk at index 500 at the latest
                if (index > Wire.MaxEntries) throw new DisconnectedException("the Seclave listed more than " + Wire.MaxEntries + " labels");
                var cmd = Command(withGroups ? Wire.OpGetLabelGroupIdx : Wire.OpGetLabelIdx);
                Wire.PutInt(cmd, index);
                Response r = Exchange(cmd, withGroups ? 2 : 1, index == 0 ? "show all labels" : null);
                if (r.Status == Wire.StOutOfIndex) return labels;
                if (r.Status != Wire.StOk) throw new DeviceException(r.Status);
                var e = new DeviceEntry();
                e.Label = Text(r, 0, Wire.MaxLabel);
                if (withGroups) e.Group = Text(r, 1, Wire.MaxGroup);
                labels.Add(e);
            }
        }

        // A field longer than the device stores is not one of its answers
        private static string Text(Response r, int field, int max)
        {
            if (r.Fields[field].Length > max) throw new DisconnectedException(OutOfStep);
            return r.Text(field);
        }

        private string GetField(int opcode, string label, int max, string prompt)
        {
            var cmd = Command(opcode);
            Wire.PutField(cmd, label);
            Response r = Exchange(cmd, 1, prompt);
            if (r.Status == Wire.StEntryNotFound) return null;
            if (r.Status != Wire.StOk) throw new DeviceException(r.Status);
            return Text(r, 0, max);
        }

        // All fields of one entry, one confirmation each in the default mode;
        // pass the group if the label enumeration already gave it. Null if
        // the label is not on the device.
        public DeviceEntry ReadEntry(string label, string group)
        {
            var e = new DeviceEntry();
            e.Label = label;
            e.Group = group != null ? group : GetField(Wire.OpGetGroup, label, Wire.MaxGroup, "show group of " + label);
            if (e.Group == null) return null;
            e.Username = GetField(Wire.OpGetUsername, label, Wire.MaxUsername, "show username of " + label);
            e.Password = GetField(Wire.OpGetPassword, label, Wire.MaxPassword, "show password of " + label);
            e.Optional = GetField(Wire.OpGetOptional, label, Wire.MaxOptional, "show optional of " + label);
            if (e.Username == null || e.Password == null || e.Optional == null) return null;
            return e;
        }

        public void PutEntry(DeviceEntry e, string prompt)
        {
            var cmd = Command(Wire.OpPutEntry);
            Wire.PutField(cmd, e.Label);
            Wire.PutField(cmd, e.Group);
            Wire.PutField(cmd, e.Username);
            Wire.PutField(cmd, e.Password);
            Wire.PutField(cmd, e.Optional);
            Response r = Exchange(cmd, 0, prompt);
            if (r.Status != Wire.StOk) throw new DeviceException(r.Status);
        }

        // False if there was no such label.
        public bool DeleteEntry(string label)
        {
            var cmd = Command(Wire.OpDelEntry);
            Wire.PutField(cmd, label);
            Response r = Exchange(cmd, 0, "remove entry " + label);
            if (r.Status == Wire.StEntryNotFound) return false;
            if (r.Status != Wire.StOk) throw new DeviceException(r.Status);
            return true;
        }

        // The whole store from the backup stream, decrypted with the backup key
        // (Backup > Show key on the device). One confirmation for all of it.
        public List<DeviceEntry> ReadBackup(byte[] backupKey)
        {
            var items = new List<byte[]>();
            for (int index = 0; ; index++)
            {
                // 500 records and the header at index 500, so the device ends
                // the stream at index 501
                if (index > Wire.MaxEntries + 1) throw new DisconnectedException("the backup stream is longer than " + (Wire.MaxEntries + 1) + " items");
                var cmd = Command(Wire.OpGetBackup);
                Wire.PutInt(cmd, index);
                Response r = Exchange(cmd, 1, index == 0 ? "export backup" : null);
                if (r.Status == Wire.StOutOfIndex) break;
                if (r.Status != Wire.StOk) throw new DeviceException(r.Status);
                if (r.Fields[0].Length != Backup.ItemSize)
                    throw new DisconnectedException("backup item of " + r.Fields[0].Length + " bytes");
                items.Add(r.Fields[0]);
            }
            return Backup.Decrypt(items, backupKey);
        }

        // The Seclave's ports, known by its USB ids: no other port is offered.
        // macOS has no such lookup here, so there its USB modem ports are
        // offered, unmarked. One not found can still be typed in.
        public static List<PortChoice> FindPorts()
        {
            var ports = new List<PortChoice>();
            if (Environment.OSVersion.Platform == PlatformID.Unix || Environment.OSVersion.Platform == PlatformID.MacOSX)
            {
                // The udev rule shipped for Linux creates this name
                if (File.Exists("/dev/seclave")) ports.Add(new PortChoice("/dev/seclave", true));
                var acm = new List<string>();
                try { acm.AddRange(Directory.GetFiles("/dev", "ttyACM*")); }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
                acm.Sort();
                foreach (string p in acm)
                    if (IsSeclaveTty(Path.GetFileName(p))) ports.Add(new PortChoice(p, true));
                try
                {
                    string[] mac = Directory.GetFiles("/dev", "cu.usbmodem*");
                    Array.Sort(mac);
                    foreach (string p in mac) ports.Add(new PortChoice(p, false));
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
            else
            {
                // The ports present now. Windows keeps the COM name it gave a
                // Seclave after it is unplugged, so a name is the Seclave's
                // only while that port is present.
                Dictionary<string, bool> seclave = WindowsSeclavePorts();
                string[] names = SerialPort.GetPortNames();
                Array.Sort(names);
                var seen = new Dictionary<string, bool>();
                foreach (string p in names)
                {
                    string key = p.ToUpperInvariant();
                    if (seen.ContainsKey(key) || !seclave.ContainsKey(key)) continue;
                    seen[key] = true;
                    ports.Add(new PortChoice(p, true));
                }
            }
            return ports;
        }

        // Said after a port that would not open. On Linux only root and the
        // dialout group may open the Seclave's port until its udev rule is
        // installed, which names the port /dev/seclave.
        public static string LinuxPortAdvice(string port)
        {
            if (!port.StartsWith("/dev/ttyACM") || File.Exists("/dev/seclave")) return "";
            return Environment.NewLine + Environment.NewLine +
                "On Linux, KeePass may open the Seclave's port once its udev rule is installed: download " +
                "install-udev-rule.sh from https://github.com/seclave/seclave_keepassplugin/releases, " +
                "run it once with sudo sh install-udev-rule.sh, and choose Usb slave on the Seclave again.";
        }

        private const string UsbIds = "VID_20A0&PID_41E3";

        private static bool IsSeclaveTty(string ttyName)
        {
            // Walk up from the tty's device, its USB interface once the link is
            // followed, to the USB device directory that holds the ids
            try
            {
                string path = UnixPath.Real("/sys/class/tty/" + ttyName + "/device");
                for (int i = 0; i < 6 && path != null; i++)
                {
                    string vid = Path.Combine(path, "idVendor");
                    string pid = Path.Combine(path, "idProduct");
                    if (File.Exists(vid) && File.Exists(pid))
                        return File.ReadAllText(vid).Trim() == "20a0" && File.ReadAllText(pid).Trim() == "41e3";
                    path = Path.GetDirectoryName(path);
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            // Without realpath() the port is only not listed first
            catch (DllNotFoundException) { }
            catch (EntryPointNotFoundException) { }
            return false;
        }

        // Every COM name Windows has given a Seclave, in upper case, found by
        // the Seclave's USB ids in the registry
        private static Dictionary<string, bool> WindowsSeclavePorts()
        {
            var names = new Dictionary<string, bool>();
            try
            {
                using (RegistryKey usb = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USB"))
                {
                    if (usb == null) return names;
                    foreach (string device in usb.GetSubKeyNames())
                    {
                        if (!device.ToUpperInvariant().StartsWith(UsbIds)) continue;
                        using (RegistryKey parent = usb.OpenSubKey(device))
                        {
                            if (parent == null) continue;
                            foreach (string instance in parent.GetSubKeyNames())
                            {
                                using (RegistryKey p = parent.OpenSubKey(instance + @"\Device Parameters"))
                                {
                                    object name = p == null ? null : p.GetValue("PortName");
                                    if (name != null) names[name.ToString().ToUpperInvariant()] = true;
                                }
                            }
                        }
                    }
                }
            }
            catch (System.Security.SecurityException) { }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
            return names;
        }
    }

    // The Seclave 2 backup stream: 500 record items and then a header item,
    // 224 bytes each. Each item is AES-128-CTR encrypted and CBC-MACed with
    // keys derived from the backup key; every item is authenticated before
    // any of it is used.
    public static class Backup
    {
        public const int ItemSize = 224;
        private const int EncSize = 208;        // the encrypted, MACed prefix of an item
        private const int MacOffset = 208;      // 10-byte MAC
        private const int IndexOffset = 218;    // little-endian record index
        private const int CookieOffset = 220;
        private const int HeaderNonce = 186;
        private const int HeaderMac = 202;

        private static readonly byte[] RecordCookie = { 0x08, 0xf3, 0x22, 0x00 };
        private static readonly byte[] HeaderCookie = { 0x08, 0xf3, 0x23, 0x00 };

        // Each working key is the AES decryption of one of these under the backup key
        private static readonly byte[] EncKeyConstant = Hex("4a18d9f57880ef1bbd9bd162a995efc8");
        private static readonly byte[] MacKeyConstant = Hex("6dfb51477ead4d3233b590630e3750a8");

        private const string WrongKey = "The backup key does not match this Seclave. Check it against Backup > Show key on the device.";

        public static byte[] Hex(string digits)
        {
            var b = new byte[digits.Length / 2];
            for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(digits.Substring(2 * i, 2), 16);
            return b;
        }

        // The 32 hex digits of a backup key, with or without the dashes and
        // spaces the device groups them with. Null if it is not 32 hex digits.
        public static byte[] ParseKey(string text)
        {
            var digits = new StringBuilder();
            foreach (char c in text)
            {
                if (c == '-' || c == ' ') continue;
                if (Uri.IsHexDigit(c)) digits.Append(c);
                else return null;
            }
            return digits.Length == 32 ? Hex(digits.ToString()) : null;
        }

        // ECB ignores the IV; one is passed because not every implementation
        // accepts none
        private static readonly byte[] UnusedIv = new byte[16];

        // Aes.Create() rather than the managed Rijndael class, which Windows
        // refuses under its FIPS policy
        private static Aes NewAes()
        {
            Aes aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            return aes;
        }

        private static byte[] Block(ICryptoTransform aes, byte[] input, int offset)
        {
            var output = new byte[16];
            aes.TransformBlock(input, offset, 16, output, 0);
            return output;
        }

        // The item's counter block: its index big-endian at bytes 12..13, XOR the nonce
        private static byte[] Iv(byte[] nonce, int index)
        {
            var iv = new byte[16];
            iv[12] = (byte)(index >> 8);
            iv[13] = (byte)index;
            for (int i = 0; i < 16; i++) iv[i] ^= nonce[i];
            return iv;
        }

        // The counter increments big-endian across all 16 bytes
        private static byte[] Ctr(ICryptoTransform enc, byte[] counter, byte[] data, int offset, int length)
        {
            var output = new byte[length];
            var ctr = (byte[])counter.Clone();
            for (int off = 0; off < length; off += 16)
            {
                byte[] stream = Block(enc, ctr, 0);
                for (int i = 0; i < 16 && off + i < length; i++)
                    output[off + i] = (byte)(data[offset + off + i] ^ stream[i]);
                for (int i = 15; i >= 0; i--)
                    if (++ctr[i] != 0) break;
            }
            return output;
        }

        // CBC-MAC from a zero block over the IV and then the data
        private static bool MacMatches(ICryptoTransform mac, byte[] iv, byte[] data, int offset, int length, byte[] item, int macOffset)
        {
            byte[] m = Block(mac, iv, 0);
            var x = new byte[16];
            for (int off = 0; off < length; off += 16)
            {
                for (int i = 0; i < 16; i++) x[i] = (byte)(m[i] ^ data[offset + off + i]);
                m = Block(mac, x, 0);
            }
            // Every byte is compared, so the time taken says nothing about where they differ
            int diff = 0;
            for (int i = 0; i < 10; i++) diff |= m[i] ^ item[macOffset + i];
            return diff == 0;
        }

        private static bool HasCookie(byte[] item, byte[] cookie)
        {
            for (int i = 0; i < 4; i++)
                if (item[CookieOffset + i] != cookie[i]) return false;
            return true;
        }

        private static string Text(byte[] plain, int start, int end)
        {
            int n = 0;
            while (start + n < end && plain[start + n] != 0) n++;
            return Wire.Latin1.GetString(plain, start, n);
        }

        // A backup archive, as the Seclave's Backup > Export writes it
        // (SECLAVE.BKP) and the Seclave Companion saves it: the backup
        // stream's items, each at the start of a slot of 256 bytes
        public const int ArchiveSlot = 256;

        public static List<byte[]> ReadArchive(byte[] data)
        {
            int count = Wire.MaxEntries + 1;
            if (data.Length != count * ArchiveSlot)
                throw new DisconnectedException("not a Seclave backup: the file is " + data.Length + " bytes, a backup " +
                    count * ArchiveSlot);
            var items = new List<byte[]>();
            for (int i = 0; i < count; i++)
            {
                var item = new byte[ItemSize];
                Array.Copy(data, i * ArchiveSlot, item, 0, ItemSize);
                items.Add(item);
            }
            return items;
        }

        public static List<DeviceEntry> Decrypt(List<byte[]> items, byte[] backupKey)
        {
            if (items.Count != Wire.MaxEntries + 1)
                throw new DisconnectedException("backup stream of " + items.Count + " items");
            byte[] header = items[Wire.MaxEntries];
            if (!HasCookie(header, HeaderCookie) || BitConverter.ToUInt16(header, IndexOffset) != Wire.MaxEntries)
                throw new DisconnectedException("no backup header at the end of the stream");

            byte[] encKey = null, macKey = null, iv = null, headerPlain = null;
            try
            {
                using (Aes aes = NewAes())
                {
                    using (ICryptoTransform root = aes.CreateDecryptor(backupKey, UnusedIv))
                    {
                        encKey = Block(root, EncKeyConstant, 0);
                        macKey = Block(root, MacKeyConstant, 0);
                    }
                    using (ICryptoTransform enc = aes.CreateEncryptor(encKey, UnusedIv))
                    using (ICryptoTransform mac = aes.CreateEncryptor(macKey, UnusedIv))
                    {
                        var nonce = new byte[16];
                        Array.Copy(header, HeaderNonce, nonce, 0, 16);
                        iv = Iv(nonce, Wire.MaxEntries);
                        if (!MacMatches(mac, iv, header, 0, 16, header, HeaderMac)) throw new BackupKeyException(WrongKey);
                        headerPlain = Ctr(enc, iv, header, 0, 16);
                        int declared = BitConverter.ToUInt16(headerPlain, 4);

                        var bySlot = new SortedDictionary<int, DeviceEntry>();
                        var seen = new Dictionary<int, bool>();
                        for (int i = 0; i < Wire.MaxEntries; i++)
                        {
                            byte[] item = items[i];
                            if (!HasCookie(item, RecordCookie)) throw new DisconnectedException("backup item " + i + " is not a record");
                            int slot = BitConverter.ToUInt16(item, IndexOffset);
                            if (slot >= Wire.MaxEntries || seen.ContainsKey(slot))
                                throw new DisconnectedException("backup record slots repeat or point outside the store");
                            seen[slot] = true;
                            // The index is plaintext but chooses the IV, so a moved item fails its MAC.
                            // The header has proved the key, so a failure here is a damaged stream.
                            iv = Iv(nonce, slot);
                            if (!MacMatches(mac, iv, item, 0, EncSize, item, MacOffset))
                                throw new DisconnectedException("backup record " + slot + " is damaged or not from this export; retry the sync");
                            byte[] plain = Ctr(enc, iv, item, 0, EncSize);
                            try
                            {
                                int status = plain[16];
                                if (status == 0) continue;
                                if (status != 1) throw new DisconnectedException("backup record " + slot + " has an impossible status");
                                var e = new DeviceEntry();
                                e.Label = Text(plain, 0, 16);
                                e.Group = Text(plain, 17, 25);
                                e.Username = Text(plain, 25, 75);
                                e.Password = Text(plain, 75, 125);
                                e.Optional = Text(plain, 125, 208);
                                bySlot[slot] = e;
                            }
                            finally
                            {
                                Array.Clear(plain, 0, plain.Length);
                            }
                        }
                        if (bySlot.Count != declared)
                            throw new DisconnectedException("the backup header promises " + declared + " entries, the records hold " + bySlot.Count);
                        return new List<DeviceEntry>(bySlot.Values);
                    }
                }
            }
            finally
            {
                foreach (byte[] b in new byte[][] { encKey, macKey, iv, headerPlain })
                    if (b != null) Array.Clear(b, 0, b.Length);
            }
        }
    }
}
