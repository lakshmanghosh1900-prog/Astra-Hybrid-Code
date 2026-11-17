#!/bin/sh
set -eu

scan_dir=/tmp/gitleaks-scan
if [ -d /git-metadata ]; then
    rm -rf "$scan_dir"
    mkdir -p "$scan_dir"
    cp -a /workspace/. "$scan_dir/"
    rm -rf "$scan_dir/.git"
    mkdir -p "$scan_dir/.git"
    cp -a /git-metadata/. "$scan_dir/.git/"
    set -- "$@" --source "$scan_dir"
fi
exec gitleaks "$@"
