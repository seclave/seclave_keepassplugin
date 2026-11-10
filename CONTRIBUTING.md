# Contributing

The plugin uses only KeePass's own plugin API and the .NET Framework. It ships
as a `.plgx`, which is source: KeePass compiles it on the user's machine when
it loads it. Patches that add a dependency will be turned down on that ground
alone.

The source is four files, each with one job, read top to bottom:

- `SeclavePlugin.cs` - the plugin entry point, its menu items, and the export
  to the Seclave's import volume;
- `SeclaveLabels.cs` - how an entry is named on the Seclave: the label
  pattern, the group name, the label characters, and the settings dialog.
  The export and the sync both name entries through it;
- `SeclaveDevice.cs` - the Seclave's USB slave interface: the wire protocol,
  the serial port, and decryption of the backup stream. It uses no KeePass
  types;
- `SeclaveSync.cs` - the sync: the per-entry sync state, the plan, applying
  it, and its dialogs.

Next to them, `SyncButton16.png` and `SyncButton32.png` are the picture on
the plugin's toolbar button, the key of the Seclave mark, at 16 and 32
pixels. The Seclave mark is a trademark of Seclave AB; Seclave makes these
pictures, so a patch should leave them as they are.

A new file needs a `Compile` line in `SeclavePlugin.csproj` (KeePass compiles
what that file lists), or for an image an `EmbeddedResource` line, and a good
reason. KeePass on Windows compiles plugins
against .NET Framework 3.5 with a C# 3 compiler, so keep to C# 3: no string
interpolation, `?.`, optional or named arguments, `async`, or .NET 4 APIs
such as `string.Join` over an `IEnumerable` or `Tuple`. Mono does not catch
this; compiling with the 2.0 reference assemblies does (packages `keepass2`
and `mono-mcs`):

```
A=/usr/lib/mono/2.0-api
mkdir -p output
mcs -langversion:3 -nostdlib -t:library -out:output/check.dll \
    -r:$A/mscorlib.dll -r:$A/System.dll -r:$A/System.Core.dll \
    -r:$A/System.Windows.Forms.dll -r:$A/System.Drawing.dll \
    -r:/usr/lib/keepass2/KeePass.exe SeclavePlugin/*.cs SeclavePlugin/Properties/*.cs
```

## Tests

Seclave tests every change and every release with its own development
tools (device stubs, a firmware simulator, and tests driving a real
KeePass), which are not part of this repository. If you send a patch, say
how you tested it; a real Seclave in Usb slave mode is the best test.

## Building

`./create_plgx.sh` packages the source into `output/SeclavePlugin.plgx` with
`keepass2 --plgx-create` (no compiler is involved). `keepass2` packs every
file under `SeclavePlugin/`, so the script first checks that the directory
holds only the project file and the sources and images it lists, and stops
otherwise.
`./compile_on_podman.sh` does the same inside a container, so only Podman
needs to be installed.

## The Linux udev rule

`linux/install-udev-rule.sh` installs the udev rule that Linux needs for the
Seclave's serial port (see the README). Its two rule lines are the ones the
Seclave Companion's Linux packages install, and the two change together. It
is plain POSIX `sh`, so that it runs as `/bin/sh` on every distribution.

## Releasing

Releases are made by Seclave from tagged commits, by the release workflow
(`.github/workflows/release.yml`), which attaches the `.plgx` and
`linux/install-udev-rule.sh`.

## License

Contributions are accepted under the MIT license that covers this repository;
every source file carries an `SPDX-License-Identifier: MIT` header.
