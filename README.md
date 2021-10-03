# Install keepass plugin
Download the latest release from https://github.com/seclave/seclave_keepassplugin/releases 
and install .plgx according to https://keepass.info/help/v2/plugins.html

# Ubuntu development environment

Install the following packages:
`apt-get install msbuild mono-complete mono-roslyn`

## To build it using mono and msbuild under Ubuntu
`cd SeclavePlugin && msbuild -p:Configuration=Release`
