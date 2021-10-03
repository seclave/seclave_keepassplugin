#!/bin/sh

keepass2 --plgx-create SeclavePlugin
mkdir output 2>/dev/null || true
mv SeclavePlugin.plgx output
