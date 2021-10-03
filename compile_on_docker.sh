#!/bin/sh

TMPDIR=`mktemp -d`

docker build -t keepass-compile docker

tar cvzf $TMPDIR/code.tgz create_plgx.sh \
SeclavePlugin/SeclavePlugin.csproj \
SeclavePlugin/SeclavePlugin.cs \
SeclavePlugin/Properties/AssemblyInfo.cs

rm -rf output 2>/dev/null || true
mkdir output

docker run -it -e $USER --rm -v $TMPDIR/code.tgz:/compile/code.tgz -v $PWD/output:/compile/output keepass-compile sh -c "tar xvzf code.tgz; ./create_plgx.sh"

rm -f $TMPDIR/code.tgz
rmdir $TMPDIR
