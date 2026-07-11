# Install keepass plugin
Download the latest release from https://github.com/seclave/seclave_keepassplugin/releases 
and install .plgx according to https://keepass.info/help/v2/plugins.html

# Building the release .plgx

The supported build is the Docker path (only needs docker):

`./compile_on_docker.sh`

This packages the plugin source into `output/SeclavePlugin.plgx` using
`keepass2 --plgx-create` (no compiler needed — KeePass compiles the plgx on
the user's machine when loading it).

# Ubuntu development environment (optional, for IDE/compile checking)

Install the following packages:
`apt-get install msbuild mono-complete`

The project references KeePass.exe via `obj/KeePass.exe`; supply it from an
installed KeePass2 before building:

```
apt-get install keepass2
mkdir -p SeclavePlugin/obj && cp /usr/lib/keepass2/KeePass.exe SeclavePlugin/obj/
cd SeclavePlugin && msbuild -p:Configuration=Release
```

Note: this mono build is only for development; the shipped artifact is the
source-packaged .plgx from the Docker path above.

# License

MIT — see the [LICENSE](LICENSE) file.

Seclave is a trademark of Seclave AB. This license grants no trademark rights.
