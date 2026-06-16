#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"

export CORPLINK_SOURCE_REPO="$repo_root"
export CORPLINK_SOURCE_REV="$(git -C "$repo_root" rev-parse HEAD)"

cd "$repo_root/ci"
rm -f corplink-rs-*.pkg.tar.zst corplink-rs-*.pkg.tar.zst.sig

makepkg -Csf --noconfirm
