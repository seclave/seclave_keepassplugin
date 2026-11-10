#!/bin/sh
# Packages SeclavePlugin/ into output/SeclavePlugin.plgx. keepass2 packs
# every file under the directory, so anything there besides the project file
# and the sources and images it lists stops the build instead of being shipped.
set -eu

expected=$( (sed -En 's/.*<(Compile|EmbeddedResource) Include="([^"]*)".*/SeclavePlugin\/\2/p' SeclavePlugin/SeclavePlugin.csproj | tr '\\' '/'
             echo SeclavePlugin/SeclavePlugin.csproj) | sort)
packed=$(find SeclavePlugin ! -type d | sort)
if [ "$packed" != "$expected" ]; then
    echo "SeclavePlugin/ must hold exactly the project file and its Compile and EmbeddedResource items." >&2
    echo "Found:" >&2
    echo "$packed" >&2
    echo "Expected:" >&2
    echo "$expected" >&2
    exit 1
fi
echo "Packing:"
echo "$packed"

keepass2 --plgx-create SeclavePlugin
mkdir output 2>/dev/null || true
mv SeclavePlugin.plgx output
