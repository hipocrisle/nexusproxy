#!/bin/bash
# Сборка windows-бинарника в контейнере: на хост ничего не ставится.
set -e
cd "$(dirname "$0")"
docker run --rm -v "$PWD/core:/w" -w /w rust:latest bash -c '
  apt-get update -qq && apt-get install -y -qq gcc-mingw-w64-x86-64 >/dev/null
  rustup target add x86_64-pc-windows-gnu >/dev/null
  cargo build --release --target x86_64-pc-windows-gnu
'
ls -la core/target/x86_64-pc-windows-gnu/release/nexusproxy-core.exe
