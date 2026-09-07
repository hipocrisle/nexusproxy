#!/bin/bash
# Быстрая проверка сборки под Windows БЕЗ полной сборки окна.
# Нужна потому, что часть кода компилируется только под Windows, и
# опечатка там всплывает лишь в CI — а это двадцать минут.
set -e
cd "$(dirname "$0")"
npm --prefix app run build >/dev/null
docker run --rm \
  -v "$PWD:/w" -w /w/app/src-tauri \
  -v "$PWD/.cargo-cache:/usr/local/cargo/registry" \
  rust:latest bash -c '
    set -e
    export PATH=/usr/local/cargo/bin:$PATH
    apt-get update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq clang lld llvm >/dev/null 2>&1
    rustup target add x86_64-pc-windows-msvc >/dev/null
    command -v cargo-xwin >/dev/null || cargo install --locked cargo-xwin >/dev/null
    cargo xwin check --target x86_64-pc-windows-msvc
  '
