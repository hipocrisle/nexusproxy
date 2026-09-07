#!/bin/bash
# Сборка окна программы под Windows.
# Интерфейс собирается снаружи (в контейнере слишком старый node),
# внутри остаётся только Rust. На хост ничего не ставится.
set -e
cd "$(dirname "$0")/app"

echo "── интерфейс ──"
npm run build

echo "── Rust под Windows ──"
mkdir -p ../.cargo-cache
docker run --rm \
  -v "$PWD/..:/w" -w /w/app \
  -v "$PWD/../.cargo-cache:/usr/local/cargo/registry" \
  -e CARGO_TERM_COLOR=never \
  rust:latest bash -c '
    set -e
    export PATH=/usr/local/cargo/bin:$PATH
    apt-get update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq clang lld llvm >/dev/null 2>&1  # llvm нужен ради llvm-rc — компилятора ресурсов Windows
    rustup target add x86_64-pc-windows-msvc
    command -v cargo-xwin  >/dev/null || cargo install --locked cargo-xwin
    command -v cargo-tauri >/dev/null || cargo install --locked tauri-cli --version "^2"
    # интерфейс уже собран — пересобирать нечем и незачем
    cargo tauri build \
      --target x86_64-pc-windows-msvc \
      --runner cargo-xwin \
      --no-bundle \
      --config "{\"build\":{\"beforeBuildCommand\":\"\"}}"
  '
echo "── результат ──"
ls -la src-tauri/target/x86_64-pc-windows-msvc/release/*.exe 2>/dev/null || echo "exe не найден"
